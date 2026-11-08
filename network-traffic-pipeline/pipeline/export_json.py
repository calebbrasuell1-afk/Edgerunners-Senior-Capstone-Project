"""Export aggregated SQLite tables to compact JSON for the browser app.

Writes into the export dir:
  nodes.json      -- hosts (top-N by volume, malicious always kept)
  edges.json      -- host-pair edges between kept nodes, incl. their service ports
                     (see _load_edge_ports)
  timeline.json   -- time-SLICED arcs for the TimeArcs view (see _sliced_timeline):
                     one per host pair per proto per bucket_seconds, not one per pair
  meta.json       -- summary stats + attack-type breakdown
  detector.json   -- the AI detector's regions
  gt_events.json  -- ground-truth attack INTERVALS (see export_gt_events)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def _load_pair_close_types(conn: sqlite3.Connection) -> dict[tuple[str, str], dict[str, int]]:
    """Pair (unordered, sorted) -> {close_type: count}.

    Sums the two full-coverage rollups, which cover disjoint stretches of the
    capture and so cannot double-count: ``pair_close_types`` (built from the
    archived parquet shards, which only decoded the first 90 minutes) and
    ``pair_close_types_parsed`` (derived from TCP flags at parse time by
    parse_flows.classify_close, covering everything ingested since). Falls back to
    ``detector_pairs`` -- only detector-flagged pairs -- when both are empty."""
    out: dict[tuple[str, str], dict[str, int]] = {}
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("pair_close_types", "pair_close_types_parsed"):
        if table not in tables:
            continue
        for ip_a, ip_b, ct, n in conn.execute(
                f"SELECT ip_a, ip_b, close_type, n FROM {table}"):
            bucket = out.setdefault((ip_a, ip_b), {})
            bucket[ct] = bucket.get(ct, 0) + n
    if out:
        return out
    for initiator, responder, ct, n in conn.execute(
            """SELECT initiator, responder, close_type, COUNT(*)
               FROM detector_pairs WHERE initiator IS NOT NULL AND responder IS NOT NULL
               GROUP BY initiator, responder, close_type"""):
        key = (initiator, responder) if initiator < responder else (responder, initiator)
        bucket = out.setdefault(key, {})
        name = ct or "unknown"
        bucket[name] = bucket.get(name, 0) + n
    return out


# Which port on a flow row is the SERVICE port, and which side it belongs to. Mirrors
# aggregate.SERVICE_REQUEST_SQL exactly: the requester's service port is the row's
# dst_port, the responder's is its src_port. TCP rows captured mid-stream (no SYN and no
# SYN-ACK) are unattributable -- either port could be the ephemeral one -- so they are
# dropped rather than guessed at; ICMP has no ports at all.
_PORT_ROLE_SQL = (
    "(f.proto='tcp' AND f.syn>0 AND f.synack=0) OR (f.proto='udp' AND f.dst_port<=f.src_port)"
)
_PORT_KEEP_SQL = (
    "(f.proto='tcp' AND (f.syn>0 OR f.synack>0)) OR f.proto='udp'"
)


def _load_edge_ports(conn: sqlite3.Connection, edges: list[dict],
                     top_n: int = 6) -> None:
    """Attach a per-edge port breakdown to each kept edge, in place.

    ``edges.distinct_dst_ports`` only ever said HOW MANY service ports a direction
    requested, never which -- so an edge detail panel could report "12 dst ports" without
    naming one of them. This adds the names and their weights::

        edge["ports"] = {"to":   [[port, flows], ...],  "to_distinct":   n,
                         "from": [[port, flows], ...],  "from_distinct": n}

    ``to`` are the service ports this direction CONNECTED TO (the requester's dst_port);
    ``from`` are the ones it ANSWERED FROM (the responder's src_port). A direction is
    usually one or the other, so most edges carry a single list; keeping both means an
    edge that really did both (a host that is client and server on the same pair) is not
    silently collapsed into one story. Each list is the ``top_n`` busiest by flow count,
    with ``*_distinct`` the full distinct-port count behind it so the view can say
    "+N more" honestly. Keys are omitted when empty.

    Counted per direction, so summing an edge's ``to`` flows and its reverse edge's
    ``from`` flows double-counts the same connections -- that is the same both-rows-per-
    connection shape the rest of the export uses.
    """
    by_key = {(e["source"], e["target"], e["proto"]): e for e in edges}
    conn.execute("DROP TABLE IF EXISTS temp.ep_keys")
    conn.execute("CREATE TEMP TABLE ep_keys (src_ip TEXT, dst_ip TEXT, proto TEXT)")
    conn.executemany("INSERT INTO temp.ep_keys VALUES (?,?,?)", list(by_key))
    conn.execute("CREATE INDEX temp.idx_ep_keys ON ep_keys (src_ip, dst_ip, proto)")

    # (edge, role) -> {port: flows}. Only kept edges are joined in, and only the ports
    # that survive the role gate, so this stays a few hundred thousand small rows.
    tally: dict[tuple, dict[int, int]] = {}
    for src, dst, proto, role, port, n in conn.execute(
        f"""SELECT f.src_ip, f.dst_ip, f.proto,
                   CASE WHEN {_PORT_ROLE_SQL} THEN 'to' ELSE 'from' END AS role,
                   CASE WHEN {_PORT_ROLE_SQL} THEN f.dst_port ELSE f.src_port END AS port,
                   COUNT(*)
            FROM flows f JOIN ep_keys k
              ON f.src_ip = k.src_ip AND f.dst_ip = k.dst_ip AND f.proto = k.proto
            WHERE {_PORT_KEEP_SQL}
            GROUP BY f.src_ip, f.dst_ip, f.proto, role, port"""
    ):
        tally.setdefault((src, dst, proto, role), {})[port] = n

    for (src, dst, proto, role), counts in tally.items():
        edge = by_key.get((src, dst, proto))
        if edge is None:            # not a kept pair; the join should exclude it already
            continue
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
        ports = edge.setdefault("ports", {})
        ports[role] = [[p, n] for p, n in top]
        ports[f"{role}_distinct"] = len(counts)

    conn.execute("DROP TABLE IF EXISTS temp.ep_keys")


def export_gt_events(conn: sqlite3.Connection, export_dir: str | Path,
                     t_min: float | None, t_max: float | None) -> int:
    """Ground-truth attack INTERVALS, for the TimeArcs ground-truth panel.

    Every other route ground truth takes to the browser is denormalized onto a flow,
    edge or node as a boolean plus a type string (see label.py propagate) — which says
    that a connection was labelled, but not when the labelled attack began or ended.
    ``gt_events`` is the only place ``start_utc``/``stop_utc`` survive, and the panel is
    built on exactly those two columns, so this exports the table itself.

    Clipped to the capture window, since an event outside it has no x to be drawn at:
    the ground truth covers ~10 days against a ~90 minute capture, so the clip is the
    difference between 8,223 rows and 408 (~45 KB).

    Note ``stop == start`` is common and legitimate (a third of the in-window events are
    minute-granular point events); the renderer gives those a minimum bulge rather than a
    zero-width arc. Ports are kept raw, exactly as ``label.py`` stored them — "0"/"0.0"
    means unspecified — because they are shown in a tooltip, never matched on here.
    """
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    events: list[dict] = []
    if "gt_events" in tables:
        # An open-ended window keeps everything rather than nothing: a db exported before
        # flows/edges carried timestamps has no window to clip to, and dropping the whole
        # table is a worse answer than a larger file.
        lo = t_min if t_min is not None else float("-inf")
        hi = t_max if t_max is not None else float("inf")
        for etype, src, sports, dst, dports, start, stop in conn.execute(
                """SELECT event_type, src, src_ports, dst, dst_ports, start_utc, stop_utc
                   FROM gt_events WHERE start_utc IS NOT NULL AND stop_utc IS NOT NULL
                   ORDER BY start_utc"""):
            if stop < lo or start > hi:
                continue
            events.append({
                "type": etype, "src": src, "dst": dst,
                "start": start, "stop": stop,
                "src_ports": sports, "dst_ports": dports,
            })
    with open(export_dir / "gt_events.json", "w", encoding="utf-8") as fh:
        json.dump(events, fh)
    return len(events)


def _sliced_timeline(conn: sqlite3.Connection, edges: list[dict],
                     bucket_seconds: int, t0: float) -> list[dict]:
    """Timeline arcs: one per (host pair, proto, TIME SLICE) — not one per pair.

    The ``edges`` rollup is ``GROUP BY src_ip, dst_ip, proto`` over ``flows`` (see
    aggregate.py), keeping only MIN(first_ts). Building the timeline straight off it —
    which is what this module used to do — gave TimeArcs exactly one arc per host pair,
    pinned at the second their very first packet crossed, no matter how long they went on
    talking. That is the wrong shape for a chart whose entire subject is *when*:

      * 155.108.237.71 -> 172.28.4.7 is 200,025 flows spread evenly over 288.9s. One arc.
      * 172.28.192.5 <-> 70.98.1.1 is 8,167 flows spanning the whole 5,406s capture. One arc.
      * 95% of ground-truth-malicious pairs outlive their own arc by more than a second;
        82% by more than a minute. The distortion lands almost entirely on attack traffic,
        because attacks are the thing that persists.

    So we re-group the same kept pairs by ``bucket_seconds`` and emit an arc per slice. A
    pair that really was momentary still yields exactly one arc, at its own ``first_ts``
    (MIN within the slice, not the slice boundary) — so the 96.8% of pairs that never
    outlive a single bucket are byte-for-byte what they were before. Measured cost at the
    60s default: 220,198 arcs -> 242,839, +10%, concentrated on the ~5,500 long-lived
    pairs that were the ones lying.

    Per-slice ``bytes``/``flows`` are that slice's own, so a byte-weighted arc finally
    means the traffic at that moment rather than the pair's lifetime total.

    ``malicious``/``attack_types`` are also resolved per slice, from the flow labels
    inside it, using the same bidirectional rule label.py applies to edges (a pair is
    malicious in a slice if *either* direction has a labelled flow there — the reply half
    of an answered attack carries label=0 on its own flows). Without this a pair that was
    attacked for five minutes of a ninety-minute conversation would light up all ninety
    minutes as malicious, which is the same class of lie in a different field. The union
    over a pair's slices reproduces the old pair-level flag exactly, so no connection
    enters or leaves the malicious set — see the note on the ``attack`` lookup below.

    ``detector``/``detector_types`` stay pair-level, inherited from the parent edge —
    detector findings are regions over host pairs, not per-flow labels.
    """
    b = int(bucket_seconds) or 60
    by_key = {(e["source"], e["target"], e["proto"]): e for e in edges}

    conn.execute("DROP TABLE IF EXISTS temp.tl_keys")
    conn.execute("CREATE TEMP TABLE tl_keys (src_ip TEXT, dst_ip TEXT, proto TEXT)")
    conn.executemany("INSERT INTO temp.tl_keys VALUES (?,?,?)", list(by_key))
    conn.execute("CREATE INDEX temp.idx_tl_keys ON tl_keys (src_ip, dst_ip, proto)")

    # Per-slice attack types, both directions unioned into each. Small enough to hold in
    # a dict (~1.5k rows): only labelled flows contribute.
    #
    # Keyed on (host pair, slice) and deliberately NOT on proto, which mirrors label.py's
    # `pair_types` exactly — it matches an edge on src/dst alone, so the TCP and ICMP edges
    # between two hosts inherit a UDP attack's flag. Adding proto here looks more precise and
    # is a defensible reading, but it silently *unflags* pairs the rest of the app still calls
    # malicious (measured: 8 edges across 2 host pairs, whose labelled flows are all UDP). The
    # job of this function is to put arcs at the right TIME; whether a per-proto flag is the
    # better rule is a separate question, and answering it here would make the timeline
    # disagree with edges.json about which connections are attacks.
    attack: dict[tuple, str] = {}
    for a, z, slot, types in conn.execute(
        f"""WITH pair_types AS (
                SELECT src_ip AS a, dst_ip AS z,
                       CAST(first_ts / {b} AS INTEGER) AS slot, attack_type
                FROM flows WHERE label = 1
                UNION ALL
                SELECT dst_ip AS a, src_ip AS z,
                       CAST(first_ts / {b} AS INTEGER) AS slot, attack_type
                FROM flows WHERE label = 1)
            SELECT a, z, slot, GROUP_CONCAT(DISTINCT attack_type)
            FROM pair_types GROUP BY a, z, slot"""
    ):
        attack[(a, z, slot)] = types

    timeline: list[dict] = []
    sliced = set()
    for src, dst, proto, slot, first_ts, last_ts, byts, pkts, n in conn.execute(
        f"""SELECT f.src_ip, f.dst_ip, f.proto,
                   CAST(f.first_ts / {b} AS INTEGER) AS slot,
                   MIN(f.first_ts), MAX(f.last_ts),
                   SUM(f.bytes), SUM(f.pkts), COUNT(*)
            FROM flows f JOIN tl_keys k
              ON f.src_ip = k.src_ip AND f.dst_ip = k.dst_ip AND f.proto = k.proto
            GROUP BY f.src_ip, f.dst_ip, f.proto, slot"""
    ):
        edge = by_key.get((src, dst, proto))
        if edge is None:          # not a kept pair; the join should exclude it already
            continue
        sliced.add((src, dst, proto))
        types = attack.get((src, dst, slot))
        timeline.append({
            "source": src, "target": dst, "proto": proto,
            "bucket": int((first_ts - t0) // b) if t0 else 0,
            "first_ts": first_ts, "last_ts": last_ts,
            "bytes": byts, "pkts": pkts, "flows": n,
            "malicious": types is not None, "attack_types": types,
            "detector": edge["detector"], "detector_types": edge["detector_types"],
        })

    # Any kept pair the flows join didn't reach keeps its pair-level arc, so slicing can
    # only ever add detail — never silently drop a connection the graph still draws.
    for e in edges:
        if (e["source"], e["target"], e["proto"]) in sliced:
            continue
        timeline.append({
            "source": e["source"], "target": e["target"], "proto": e["proto"],
            "bucket": int((e["first_ts"] - t0) // b) if t0 else 0,
            "first_ts": e["first_ts"], "last_ts": e["last_ts"],
            "bytes": e["bytes"], "pkts": e["pkts"], "flows": e["flow_count"],
            "malicious": e["malicious"], "attack_types": e["attack_types"],
            "detector": e["detector"], "detector_types": e["detector_types"],
        })

    conn.execute("DROP TABLE IF EXISTS temp.tl_keys")
    timeline.sort(key=lambda x: x["first_ts"])
    return timeline


def export_all(conn: sqlite3.Connection, export_dir: str | Path,
               top_n_nodes: int = 5000, top_n_edges: int = 30000,
               bucket_seconds: int = 60) -> dict:
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)

    pair_close_types = _load_pair_close_types(conn)

    # Per-node close-type distribution: sum each unordered pair's counts into both
    # endpoints. Reuses the same rollup edges use, so a host's totals reconcile with
    # the sum of its incident TCP edges (each pair counted once).
    node_close_types: dict[str, dict[str, int]] = {}
    for (ip_a, ip_b), counts in pair_close_types.items():
        for ip in (ip_a, ip_b):
            bucket = node_close_types.setdefault(ip, {})
            for ct, n in counts.items():
                bucket[ct] = bucket.get(ct, 0) + n

    # Edge-driven selection: keep the most meaningful connections (all malicious
    # edges + the heaviest by volume), then pull in exactly the hosts they touch.
    # This yields a connected graph rather than a sparse set of top-volume hosts.
    edges = []
    seen = set()
    eq = """SELECT src_ip,dst_ip,proto,pkts,bytes,flow_count,distinct_dst_ports,
                   first_ts,last_ts,malicious,attack_types,detector_flag,detector_types,
                   syn,synack,rst,rst_rate
            FROM edges """

    def add_edge(r):
        if (r[0], r[1], r[2]) not in seen:
            seen.add((r[0], r[1], r[2]))
            edge = {
                "source": r[0], "target": r[1], "proto": r[2],
                "pkts": r[3], "bytes": r[4], "flow_count": r[5],
                "distinct_dst_ports": r[6], "first_ts": r[7], "last_ts": r[8],
                "malicious": bool(r[9]), "attack_types": r[10],
                "detector": bool(r[11]), "detector_types": r[12],
                "syn": r[13], "synack": r[14], "rst": r[15],
                "rst_rate": round(r[16], 4),
            }
            if r[2] == "tcp":
                key = (r[0], r[1]) if r[0] < r[1] else (r[1], r[0])
                ct = pair_close_types.get(key)
                if ct:
                    edge["close_types"] = ct
            edges.append(edge)

    # Always keep ground-truth and detector-flagged edges, then the heaviest.
    for r in conn.execute(eq + "WHERE malicious=1 OR detector_flag=1"):
        add_edge(r)
    for r in conn.execute(eq + "ORDER BY bytes DESC LIMIT ?", (top_n_edges,)):
        add_edge(r)

    # Finding neighborhood: every edge touching a detector-flagged host (the
    # NodeTrix matrix members and the peers they reach out to). Scans and SYN
    # floods are low-byte, so the top-by-bytes cut above misses them; keep the
    # whole neighborhood explicitly so the hybrid view shows the full fan-out
    # instead of a few heavy edges. One full scan, filtered in Python (the set
    # of flagged hosts can exceed SQLite's bound-variable limit).
    det_hosts = {r[0] for r in conn.execute(
        "SELECT ip FROM hosts WHERE detector_flag=1")}
    for r in conn.execute(eq):
        if r[0] in det_hosts or r[1] in det_hosts:
            add_edge(r)

    # Hosts kept = endpoints of the selected edges, every flagged host, and the
    # top_n_nodes heaviest hosts by total volume. The last group lets the graph
    # show standalone hosts (not just edge endpoints); set top_n_nodes huge to
    # keep every host. We filter the full host list in Python rather than an
    # `IN (...)` clause so `keep` can exceed SQLite's bound-variable limit.
    keep = set()
    for e in edges:
        keep.add(e["source"]); keep.add(e["target"])
    for r in conn.execute(
            "SELECT ip FROM hosts WHERE malicious_flag=1 OR detector_flag=1"):
        keep.add(r[0])
    for r in conn.execute(
            "SELECT ip FROM hosts ORDER BY (bytes_in+bytes_out) DESC LIMIT ?",
            (top_n_nodes,)):
        keep.add(r[0])
    nodes = [{
        "id": r[0], "internal": bool(r[1]),
        "pkts_in": r[2], "pkts_out": r[3], "bytes_in": r[4], "bytes_out": r[5],
        "peers": r[6], "ports_contacted": r[7], "fanout": r[8],
        "syn_no_synack": r[9], "malicious": bool(r[10]),
        "attack_types": r[11], "detector": bool(r[12]), "detector_types": r[13],
        "detector_confidence": r[14], "detector_role": r[15],
        "syn_in": r[16], "completion_ratio": round(r[17], 4),
        "rst_rate": round(r[18], 4), "peak_conn_rate": r[19],
        "anomaly_score": round(r[20], 3), "anomaly_top": r[21],
        "anomaly_breadth": r[22],
        "retrans": r[23], "icmp_errors": r[24], "rtt_ms": round(r[25], 2),
    } for r in conn.execute(
        """SELECT ip,is_internal,pkts_in,pkts_out,bytes_in,bytes_out,
                   distinct_peers,distinct_ports_contacted,fanout,syn_no_synack,
                   malicious_flag,attack_types,detector_flag,detector_types,
                   detector_confidence,detector_role,
                   syn_in,completion_ratio,rst_rate,peak_conn_rate,
                   anomaly_score,anomaly_top,anomaly_breadth,
                   retrans,icmp_errors,rtt_ms FROM hosts""")
        if r[0] in keep]
    for node in nodes:
        ct = node_close_types.get(node["id"])
        if ct:
            node["close_types"] = ct

    # Which service ports each kept edge actually used (names behind the
    # `distinct_dst_ports` count the detail panels used to show on its own).
    _load_edge_ports(conn, edges)

    # Timeline arcs: the kept pairs re-cut into time slices, ordered by start time.
    t0 = min((e["first_ts"] for e in edges), default=0)
    timeline = _sliced_timeline(conn, edges, bucket_seconds, t0)

    # Detector regions: one record per AI-detected attack (for the findings panel).
    # Only the IPs we actually captured are listed under `ips_in_capture`.
    kept_ips = {n["id"] for n in nodes}
    detector_regions = []
    for row in conn.execute(
        """SELECT region_id,attack_type,known_name,category,confidence,responder,
                  port,t_min,t_max,n_ips,n_pairs,reason,ips_json FROM detector_regions
           ORDER BY confidence DESC, n_pairs DESC"""):
        rid = row[0]
        ips = {r[0] for r in conn.execute(
            "SELECT DISTINCT initiator FROM detector_pairs WHERE region_id=? "
            "UNION SELECT DISTINCT responder FROM detector_pairs WHERE region_id=?",
            (rid, rid))}
        # A finding's roster is the union of its flagged-pair endpoints, its full
        # member list (`ips_json`), and its responder -- unioned unconditionally,
        # not just as a no-pairs fallback. This mirrors the host-flagging in
        # detector.label_detector so every detector-flagged host appears inside its
        # finding's boundary blob (otherwise roster-only members of pair-having
        # regions are flagged but sit outside every blob).
        ips |= set(json.loads(row[12])) if row[12] else set()
        if row[5]:
            ips.add(row[5])
        detector_regions.append({
            "id": rid, "attack_type": row[1], "known_name": row[2],
            "category": row[3], "confidence": row[4], "responder": row[5],
            "port": row[6], "t_min": row[7], "t_max": row[8],
            "n_ips": row[9], "n_pairs": row[10], "reason": row[11],
            "ips_in_capture": sorted(i for i in ips if i in kept_ips),
        })

    # Meta / summary.
    flows_total, pkts_total, bytes_total = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(pkts),0), COALESCE(SUM(bytes),0) FROM flows"
    ).fetchone()
    tmin, tmax = conn.execute(
        "SELECT MIN(first_ts), MAX(last_ts) FROM flows"
    ).fetchone()
    if tmin is None:
        tmin, tmax = conn.execute(
            "SELECT MIN(first_ts), MAX(last_ts) FROM edges"
        ).fetchone()
    labeled = conn.execute("SELECT COUNT(*) FROM flows WHERE label=1").fetchone()[0]
    attack_breakdown = conn.execute(
        """SELECT attack_type, COUNT(*) FROM flows
           WHERE label=1 GROUP BY attack_type ORDER BY COUNT(*) DESC"""
    ).fetchall()
    det_hosts = conn.execute(
        "SELECT COUNT(*) FROM hosts WHERE detector_flag=1").fetchone()[0]
    det_breakdown = conn.execute(
        """SELECT attack_type, COUNT(*) FROM detector_regions GROUP BY attack_type
           ORDER BY COUNT(*) DESC""").fetchall()
    meta = {
        "flows_total": flows_total, "packets_total": pkts_total,
        "bytes_total": bytes_total, "labeled_flows": labeled,
        "nodes_exported": len(nodes), "edges_exported": len(edges),
        "time_min": tmin, "time_max": tmax,
        "bucket_seconds": bucket_seconds,
        "attack_breakdown": [{"type": a, "flows": c} for a, c in attack_breakdown],
        "detector_hosts": det_hosts, "detector_regions": len(detector_regions),
        "detector_breakdown": [{"type": a, "regions": c} for a, c in det_breakdown],
    }

    for name, obj in (("nodes", nodes), ("edges", edges),
                      ("timeline", timeline), ("meta", meta),
                      ("detector", detector_regions)):
        with open(export_dir / f"{name}.json", "w", encoding="utf-8") as fh:
            json.dump(obj, fh)

    gt_events = export_gt_events(conn, export_dir, tmin, tmax)

    return {"nodes": len(nodes), "edges": len(edges),
            "timeline": len(timeline), "labeled_flows": labeled,
            "detector_regions": len(detector_regions), "detector_hosts": det_hosts,
            "gt_events": gt_events}

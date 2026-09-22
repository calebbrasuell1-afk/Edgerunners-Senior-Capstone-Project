"""Write parsed flows into SQLite and derive host-pair edges + per-host stats.

``write_flows`` streams flow dicts (one per capture file) into the ``flows``
table. After all files are written, ``build_edges`` and ``build_hosts`` derive
the rollups used by the graph views, entirely in SQL.
"""
from __future__ import annotations

import ipaddress
import json
import math
import sqlite3
from statistics import median

from parse_flows import (BUCKET_SECONDS, BYTES, FIN, FIRST_TS, FIRST_SYN_TS,
                         FIRST_SYNACK_TS, ICMP_CODE, ICMP_TYPE, LAST_TS, PKTS,
                         RETRANS, RST, SYN, SYNACK)

# "Did THIS flow row request a service port?" — the gate for every distinct-port
# count. Each connection is stored twice (one row per direction), so counting
# dst_port over all rows also counts the *client's* ephemeral port from the reply
# direction: 98.6% of SYN-ACK-bearing rows have dst_port >= 32768. Ungated, the
# count inflated by up to ~5000x and ranked pure responders (flood victims, busy
# servers) above real scanners -- a SYN-flood victim that never initiated a single
# connection topped the "ports contacted" leaderboard at 21,536.
#   tcp  -- the initiator is the side that sent a SYN and got no SYN-ACK back
#           (flag sums are per-direction, so the responder's row never matches).
#   udp  -- no handshake to key on; the service is the lower-numbered port, which
#           keeps 53/123/5353/137 and drops the ephemeral reply rows.
#   icmp -- no ports at all (parse_flows stores 0), so it never counts.
# Mid-stream TCP captured without a handshake (syn=0 and synack=0) is
# unattributable and counts for neither side.
SERVICE_REQUEST_SQL = (
    "((proto='tcp' AND syn>0 AND synack=0) OR (proto='udp' AND dst_port<=src_port))"
)
# Distinct service ports this row's source actually reached out to.
PORTS_REQUESTED_SQL = f"COUNT(DISTINCT CASE WHEN {SERVICE_REQUEST_SQL} THEN dst_port END)"


def write_flows(conn: sqlite3.Connection, flows: dict, min_packets: int = 0) -> int:
    """Insert a flow dict into the ``flows`` table. Returns rows written."""
    rows = []
    for (src, dst, sport, dport, proto), r in flows.items():
        if min_packets and r[PKTS] < min_packets:
            continue
        rows.append((src, dst, sport, dport, proto,
                     r[FIRST_TS], r[LAST_TS], r[PKTS], r[BYTES],
                     r[SYN], r[SYNACK], r[FIN], r[RST],
                     r[FIRST_SYN_TS], r[FIRST_SYNACK_TS], r[RETRANS],
                     r[ICMP_TYPE], r[ICMP_CODE]))
    conn.executemany(
        """INSERT INTO flows
           (src_ip,dst_ip,src_port,dst_port,proto,first_ts,last_ts,pkts,bytes,
            syn,synack,fin,rst,first_syn_ts,first_synack_ts,retrans,icmp_type,icmp_code)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    return len(rows)


def write_close_types(conn: sqlite3.Connection, conns: dict) -> int:
    """Upsert parse-time close-type counts into ``pair_close_types_parsed``,
    summing on conflict so connections accumulate across capture files."""
    if not conns:
        return 0
    rows = [(ip_a, ip_b, ct, n) for (ip_a, ip_b, ct), n in conns.items()]
    conn.executemany(
        """INSERT INTO pair_close_types_parsed (ip_a,ip_b,close_type,n)
           VALUES (?,?,?,?)
           ON CONFLICT(ip_a,ip_b,close_type) DO UPDATE SET n=n+excluded.n""",
        rows,
    )
    conn.commit()
    return len(rows)


def write_buckets(conn: sqlite3.Connection, buckets: dict) -> int:
    """Upsert a per-(host, time-bucket) counter dict into ``host_buckets``,
    summing on conflict so buckets accumulate across capture files."""
    if not buckets:
        return 0
    rows = [(ip, b, *vals) for (ip, b), vals in buckets.items()]
    conn.executemany(
        """INSERT INTO host_buckets
           (ip,bucket,pkts_in,pkts_out,bytes_in,bytes_out,syn_in,synack_out,rst,retrans)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(ip,bucket) DO UPDATE SET
             pkts_in=pkts_in+excluded.pkts_in, pkts_out=pkts_out+excluded.pkts_out,
             bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out,
             syn_in=syn_in+excluded.syn_in, synack_out=synack_out+excluded.synack_out,
             rst=rst+excluded.rst, retrans=retrans+excluded.retrans""",
        rows,
    )
    conn.commit()
    return len(rows)


def build_edges(conn: sqlite3.Connection) -> int:
    """Roll directional flows up to host-pair edges (src_ip, dst_ip, proto).

    Also carries the TCP-flag sums (syn/synack/rst) and an RST rate so the views
    can read handshake-health signals straight off an edge. Every flow has at
    least one packet, so SUM(pkts) is never zero.

    ``distinct_dst_ports`` counts only service ports this direction requested
    (see ``SERVICE_REQUEST_SQL``), so the reply half of an answered connection
    reports 0 rather than one ephemeral port per client connection.
    """
    conn.execute("DELETE FROM edges")
    conn.execute(
        f"""
        INSERT INTO edges
            (src_ip,dst_ip,proto,pkts,bytes,flow_count,distinct_dst_ports,first_ts,last_ts,
             syn,synack,rst,rst_rate)
        SELECT src_ip, dst_ip, proto,
               SUM(pkts), SUM(bytes), COUNT(*),
               {PORTS_REQUESTED_SQL}, MIN(first_ts), MAX(last_ts),
               SUM(syn), SUM(synack), SUM(rst), SUM(rst) * 1.0 / SUM(pkts)
        FROM flows
        GROUP BY src_ip, dst_ip, proto
        """
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]


def build_hosts(conn: sqlite3.Connection, internal_cidr: str) -> int:
    """Derive per-IP node statistics from the flows table."""
    net = ipaddress.ip_network(internal_cidr)

    def is_internal(ip: str) -> int:
        try:
            return int(ipaddress.ip_address(ip) in net)
        except ValueError:
            return 0

    # Outbound stats: host as source. synack_out = SYN-ACKs this host sent back
    # (it answered an inbound SYN); rst_out = RSTs it emitted. dports counts only
    # service ports this host actually requested -- see SERVICE_REQUEST_SQL.
    out = {}
    for ip, pkts, byts, fanout, dports, syn_no, synack_out, rst_out, retrans_out in conn.execute(
        f"""SELECT src_ip, SUM(pkts), SUM(bytes),
                  COUNT(DISTINCT dst_ip), {PORTS_REQUESTED_SQL},
                  SUM(CASE WHEN syn>0 AND synack=0 THEN 1 ELSE 0 END),
                  SUM(synack), SUM(rst), SUM(retrans)
           FROM flows GROUP BY src_ip"""
    ):
        out[ip] = (pkts, byts, fanout, dports, syn_no, synack_out, rst_out, retrans_out)

    # Inbound stats: host as destination. syn_in = SYNs received (connection
    # attempts aimed at this host); rst_in = RSTs received.
    inb = {}
    for ip, pkts, byts, syn_in, rst_in in conn.execute(
        """SELECT dst_ip, SUM(pkts), SUM(bytes), SUM(syn), SUM(rst)
           FROM flows GROUP BY dst_ip"""
    ):
        inb[ip] = (pkts, byts, syn_in, rst_in)

    # Peak inbound new-connection rate: most flows *started* against this host in
    # any one-second window (the DDoS-flood burstiness signal).
    peak = {}
    for ip, pk in conn.execute(
        """SELECT dst_ip, MAX(c) FROM (
               SELECT dst_ip, CAST(first_ts AS INTEGER) AS sec, COUNT(*) AS c
               FROM flows GROUP BY dst_ip, sec
           ) GROUP BY dst_ip"""
    ):
        peak[ip] = pk

    # ICMP error replies received (dest-unreachable=3, time-exceeded=11): a sign
    # this host's traffic is failing to reach peers. -1 default means "no ICMP".
    icmp_err = {}
    for ip, c in conn.execute(
        """SELECT dst_ip, SUM(pkts) FROM flows
           WHERE proto='icmp' AND icmp_type IN (3,11) GROUP BY dst_ip"""
    ):
        icmp_err[ip] = c

    # Distinct peers (either direction).
    peers: dict[str, set] = {}
    for a, b in conn.execute("SELECT DISTINCT src_ip, dst_ip FROM flows"):
        peers.setdefault(a, set()).add(b)
        peers.setdefault(b, set()).add(a)

    all_ips = set(out) | set(inb)
    rows = []
    for ip in all_ips:
        po, bo, fanout, dports, syn_no, synack_out, rst_out, retrans_out = out.get(
            ip, (0, 0, 0, 0, 0, 0, 0, 0))
        pi, bi, syn_in, rst_in = inb.get(ip, (0, 0, 0, 0))
        # Responder handshake completion: of the SYNs aimed at this host, how many
        # it answered with a SYN-ACK. 1.0 when it received no SYNs (not a target).
        completion = min(1.0, synack_out / syn_in) if syn_in else 1.0
        total_pkts = pi + po
        rst_rate = (rst_in + rst_out) / total_pkts if total_pkts else 0.0
        rows.append((ip, is_internal(ip), pi, po, bi, bo,
                     len(peers.get(ip, ())), dports, fanout, syn_no,
                     syn_in, completion, rst_rate, peak.get(ip, 0),
                     retrans_out, icmp_err.get(ip, 0)))

    conn.execute("DELETE FROM hosts")
    conn.executemany(
        """INSERT INTO hosts
           (ip,is_internal,pkts_in,pkts_out,bytes_in,bytes_out,
            distinct_peers,distinct_ports_contacted,fanout,syn_no_synack,
            syn_in,completion_ratio,rst_rate,peak_conn_rate,retrans,icmp_errors)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    return len(rows)


# Behavioral signals scored for the anomaly triage. Each entry is
# (name, host-feature, log1p?) — count signals are log-transformed so a few huge
# attackers don't swamp the robust scale; ratios are used as-is.
_SIGNALS = [
    ("syn_in", "syn_in", True),                    # inbound connection attempts (target volume)
    ("completion_deficit", "completion_deficit", False),  # 1 - SYN-ACK/SYN (victim degradation)
    ("fanout", "fanout", True),                    # distinct dst IPs (scanner)
    ("half_open_out", "syn_no_synack", True),      # outbound half-open (scanner)
    ("rst_count", "rst_count", True),              # RST packets (errors/refusals) — count, log1p
    ("peak_conn_rate", "peak_conn_rate", True),    # burst of new connections (flood)
]

# completion_deficit is a ratio that's unstable for tiny hosts (a host with 1 SYN
# and no SYN-ACK reads as deficit=1.0); gate it by an inbound-SYN floor. RST is
# scored as a *count* (log1p), not a rate, because rst_rate is bimodal (most
# hosts ~0, a cluster at 1.0) which collapses the robust scale and explodes the z.
_MIN_SYN_IN = 20    # min inbound SYNs before completion_deficit counts


def _robust_scale(values: list[float]) -> tuple[float, float]:
    """Center + scale for a modified z-score (median / 1.4826·MAD).

    Falls back gracefully for zero-inflated signals (most hosts at 0, so the
    plain MAD is 0): use the spread of the above-center values, then the
    center→max range. A returned scale of 0 means "constant" → no outliers.
    """
    med = median(values)
    scale = 1.4826 * median([abs(v - med) for v in values])
    if scale > 0:
        return med, scale
    upper = [v - med for v in values if v > med]
    if upper:
        scale = 1.4826 * median(upper)
        if scale > 0:
            return med, scale
        mx = max(values)
        if mx > med:
            return med, mx - med
    return med, 0.0


def compute_anomaly(conn: sqlite3.Connection, breadth_z: float = 3.5) -> int:
    """Score each host as a *robust outlier* and write the result to ``hosts``.

    For each behavioral signal we compute a one-sided modified z-score within the
    host's peer group (internal vs external). ``anomaly_score`` is the max over
    signals (weight-free: a host is flagged if extreme on *any* behavior), and we
    persist the per-signal components + the top driver so the UI/AI can explain
    *why* a host fired. This is a triage/outlier score, not a maliciousness score.
    """
    hosts = []
    for (ip, internal, syn_in, completion, fanout, syn_no, rst_rate, peak,
         pkts_in, pkts_out) in conn.execute(
        """SELECT ip,is_internal,syn_in,completion_ratio,fanout,syn_no_synack,
                  rst_rate,peak_conn_rate,pkts_in,pkts_out FROM hosts"""
    ):
        total_pkts = pkts_in + pkts_out
        hosts.append((ip, internal, {
            "syn_in": syn_in,
            "completion_deficit": (1.0 - completion) if syn_in >= _MIN_SYN_IN else 0.0,
            "fanout": fanout, "syn_no_synack": syn_no,
            "rst_count": rst_rate * total_pkts,   # reconstruct RST packet count
            "peak_conn_rate": peak,
        }))

    # Robust center/scale per (peer group, signal).
    groups: dict[int, list] = {0: [], 1: []}
    for h in hosts:
        groups[1 if h[1] else 0].append(h)
    scales: dict[tuple[int, str], tuple[float, float]] = {}
    for g, members in groups.items():
        if not members:
            continue
        for name, key, logt in _SIGNALS:
            vals = [math.log1p(m[2][key]) if logt else m[2][key] for m in members]
            scales[(g, name)] = _robust_scale(vals)

    updates = []
    for ip, internal, feats in hosts:
        g = 1 if internal else 0
        comps = {}
        for name, key, logt in _SIGNALS:
            center, scale = scales.get((g, name), (0.0, 0.0))
            if scale <= 0:
                continue
            x = math.log1p(feats[key]) if logt else feats[key]
            z = (x - center) / scale
            if z > 0:
                comps[name] = round(z, 2)
        if comps:
            top = max(comps, key=comps.get)
            score = comps[top]
            breadth = sum(1 for z in comps.values() if z > breadth_z)
            blob = json.dumps(comps)
        else:
            top, score, breadth, blob = None, 0.0, 0, None
        updates.append((round(score, 3), top, breadth, blob, ip))

    conn.executemany(
        """UPDATE hosts SET anomaly_score=?, anomaly_top=?, anomaly_breadth=?,
           anomaly_components=? WHERE ip=?""",
        updates,
    )
    conn.commit()
    return len(updates)


def build_bucket_signals(conn: sqlite3.Connection) -> int:
    """Backfill the flow-derived per-(ip, time-bucket) signal columns on
    ``host_buckets``: fanout, ports_contacted, peers, syn_no_synack,
    peak_conn_rate, icmp_errors and rtt_ms.

    Each query is the whole-table form of the per-host queries in
    ``server/signals.py:_flow_signals_for`` — same ``first_ts`` bucketing on the
    BUCKET_SECONDS grid — so the bulk radar endpoint and the drill-down chart
    agree bucket-for-bucket. Distinct counts (fanout/ports/peers) are per-bucket
    distinct, NOT cumulative: summing bins does not reproduce the whole-capture
    ``hosts`` values. Idempotent: every run resets the columns and recomputes
    from ``flows``, so it is safe to re-run standalone on an existing DB.
    """
    import time as _time

    b = BUCKET_SECONDS
    # Reset so a re-run never leaves stale values behind. rtt_ms goes back to
    # NULL (absent = no handshake in that bucket); the counts to 0.
    conn.execute(
        """UPDATE host_buckets SET fanout=0, ports_contacted=0, peers=0,
           syn_no_synack=0, peak_conn_rate=0, icmp_errors=0, rtt_ms=NULL""")
    # Normally created by compute_rtt during a full pipeline run; guard so the
    # standalone backfill doesn't pay the self-join without it.
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_flows_4tuple
                    ON flows(src_ip,dst_ip,src_port,dst_port)""")

    # (label, SELECT ip, bucket, value(s)..., UPSERT setting just those columns).
    # Rows should already exist (the flow's first packet lands in the same bucket
    # at parse time), but the counter columns default to 0 so a fresh insert is
    # valid either way.
    queries = [
        ("fanout/ports/half-open",
         f"""SELECT src_ip, CAST(first_ts/{b} AS INTEGER)*{b} AS t,
                    COUNT(DISTINCT dst_ip), {PORTS_REQUESTED_SQL},
                    SUM(CASE WHEN syn>0 AND synack=0 THEN 1 ELSE 0 END)
             FROM flows GROUP BY src_ip, t""",
         """INSERT INTO host_buckets (ip,bucket,fanout,ports_contacted,syn_no_synack)
            VALUES (?,?,?,?,?) ON CONFLICT(ip,bucket) DO UPDATE SET
              fanout=excluded.fanout, ports_contacted=excluded.ports_contacted,
              syn_no_synack=excluded.syn_no_synack"""),
        ("peers",
         f"""SELECT ip, t, COUNT(DISTINCT peer) FROM (
               SELECT src_ip AS ip, CAST(first_ts/{b} AS INTEGER)*{b} AS t,
                      dst_ip AS peer FROM flows
               UNION
               SELECT dst_ip AS ip, CAST(first_ts/{b} AS INTEGER)*{b} AS t,
                      src_ip AS peer FROM flows
             ) GROUP BY ip, t""",
         """INSERT INTO host_buckets (ip,bucket,peers) VALUES (?,?,?)
            ON CONFLICT(ip,bucket) DO UPDATE SET peers=excluded.peers"""),
        ("peak_conn_rate",
         f"""SELECT dst_ip, t, MAX(c) FROM (
               SELECT dst_ip, CAST(first_ts/{b} AS INTEGER)*{b} AS t,
                      CAST(first_ts AS INTEGER) AS sec, COUNT(*) AS c
               FROM flows GROUP BY dst_ip, t, sec
             ) GROUP BY dst_ip, t""",
         """INSERT INTO host_buckets (ip,bucket,peak_conn_rate) VALUES (?,?,?)
            ON CONFLICT(ip,bucket) DO UPDATE SET peak_conn_rate=excluded.peak_conn_rate"""),
        ("icmp_errors",
         f"""SELECT dst_ip, CAST(first_ts/{b} AS INTEGER)*{b} AS t, SUM(pkts)
             FROM flows WHERE proto='icmp' AND icmp_type IN (3,11)
             GROUP BY dst_ip, t""",
         """INSERT INTO host_buckets (ip,bucket,icmp_errors) VALUES (?,?,?)
            ON CONFLICT(ip,bucket) DO UPDATE SET icmp_errors=excluded.icmp_errors"""),
        ("rtt_ms",
         f"""SELECT r.src_ip, CAST(r.first_synack_ts/{b} AS INTEGER)*{b} AS t,
                    ROUND(AVG((r.first_synack_ts - f.first_syn_ts) * 1000.0), 2)
             FROM flows r JOIN flows f
               ON f.src_ip=r.dst_ip AND f.dst_ip=r.src_ip
              AND f.src_port=r.dst_port AND f.dst_port=r.src_port
             WHERE r.first_synack_ts>0 AND f.first_syn_ts>0
               AND r.first_synack_ts>=f.first_syn_ts
               AND (r.first_synack_ts - f.first_syn_ts)<60
             GROUP BY r.src_ip, t""",
         """INSERT INTO host_buckets (ip,bucket,rtt_ms) VALUES (?,?,?)
            ON CONFLICT(ip,bucket) DO UPDATE SET rtt_ms=excluded.rtt_ms"""),
    ]

    total = 0
    for label, select_sql, upsert_sql in queries:
        t0 = _time.time()
        n, batch = 0, []
        # Stream the GROUP BY results (millions of groups) in bounded batches
        # instead of materializing them; reading flows while upserting
        # host_buckets on the same connection is fine (different tables).
        for row in conn.execute(select_sql):
            batch.append(row)
            if len(batch) >= 50_000:
                conn.executemany(upsert_sql, batch)
                n += len(batch)
                batch.clear()
        if batch:
            conn.executemany(upsert_sql, batch)
            n += len(batch)
        total += n
        print(f"  bucket signals: {label} {n:,} rows in {_time.time() - t0:.1f}s")
    conn.commit()
    # The rollup rewrites most of host_buckets; fold the WAL back into the DB.
    conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    return total


def compute_rtt(conn: sqlite3.Connection) -> int:
    """Mean responder handshake RTT per host (ms), from the Phase-2 per-flow
    first-SYN / first-SYN-ACK timestamps.

    Matches each forward SYN flow with its reverse SYN-ACK flow on the swapped
    4-tuple and attributes the RTT to the responder (the host that sent the
    SYN-ACK). Implausible gaps (>60s — clock skew / port reuse) are dropped.
    No-op until a re-parse has populated the timestamps.
    """
    conn.execute("UPDATE hosts SET rtt_ms=0")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_flows_4tuple
                    ON flows(src_ip,dst_ip,src_port,dst_port)""")
    rows = conn.execute(
        """
        SELECT r.src_ip AS responder,
               AVG((r.first_synack_ts - f.first_syn_ts) * 1000.0) AS rtt_ms
        FROM flows r
        JOIN flows f
          ON f.src_ip = r.dst_ip AND f.dst_ip = r.src_ip
         AND f.src_port = r.dst_port AND f.dst_port = r.src_port
        WHERE r.first_synack_ts > 0 AND f.first_syn_ts > 0
          AND r.first_synack_ts >= f.first_syn_ts
          AND (r.first_synack_ts - f.first_syn_ts) < 60
        GROUP BY r.src_ip
        """
    ).fetchall()
    conn.executemany("UPDATE hosts SET rtt_ms=? WHERE ip=?",
                     [(rtt, ip) for ip, rtt in rows])
    conn.commit()
    return len(rows)


def backfill_port_counts(conn: sqlite3.Connection) -> tuple[int, int]:
    """Recompute the distinct-port columns on ``hosts`` and ``edges`` IN PLACE.

    ``build_hosts``/``build_edges`` rebuild their tables from scratch, which would
    drop the label/detector columns written later in the pipeline (run.py steps 4
    and 4b). This updates only the two port columns, so an existing database can
    adopt the ``SERVICE_REQUEST_SQL`` gate without a re-label. Idempotent.
    """
    # One grouped pass per table into a temp table, then a keyed update -- far
    # cheaper than a correlated subquery over ``flows`` per row.
    conn.execute("DROP TABLE IF EXISTS temp.port_fix_hosts")
    conn.execute(f"""CREATE TEMP TABLE port_fix_hosts AS
                     SELECT src_ip AS ip, {PORTS_REQUESTED_SQL} AS n
                     FROM flows GROUP BY src_ip""")
    conn.execute("CREATE INDEX temp.idx_pfh ON port_fix_hosts(ip)")
    n_hosts = conn.execute(
        """UPDATE hosts SET distinct_ports_contacted =
             COALESCE((SELECT n FROM temp.port_fix_hosts WHERE ip = hosts.ip), 0)"""
    ).rowcount

    conn.execute("DROP TABLE IF EXISTS temp.port_fix_edges")
    conn.execute(f"""CREATE TEMP TABLE port_fix_edges AS
                     SELECT src_ip, dst_ip, proto, {PORTS_REQUESTED_SQL} AS n
                     FROM flows GROUP BY src_ip, dst_ip, proto""")
    conn.execute("CREATE INDEX temp.idx_pfe ON port_fix_edges(src_ip,dst_ip,proto)")
    n_edges = conn.execute(
        """UPDATE edges SET distinct_dst_ports = COALESCE((
             SELECT n FROM temp.port_fix_edges p
             WHERE p.src_ip = edges.src_ip AND p.dst_ip = edges.dst_ip
               AND p.proto = edges.proto), 0)"""
    ).rowcount
    conn.execute("DROP TABLE temp.port_fix_hosts")
    conn.execute("DROP TABLE temp.port_fix_edges")
    conn.commit()
    return n_hosts, n_edges


if __name__ == "__main__":
    # Standalone backfill: `python pipeline/aggregate.py` recomputes the
    # flow-derived columns on an existing database (no pcap re-parse; the flows
    # table is the source). init_schema runs migrate(), which adds the columns to
    # a pre-existing host_buckets first.
    import time

    import db
    from config import load_config, resolve

    cfg = load_config(None)
    conn = db.connect(resolve(cfg["paths"]["db_path"]))
    db.init_schema(conn)
    t0 = time.time()
    n = build_bucket_signals(conn)
    print(f"bucket signals: {n:,} rows updated in {time.time() - t0:.1f}s")
    t0 = time.time()
    nh, ne = backfill_port_counts(conn)
    conn.close()
    print(f"port counts: {nh:,} hosts + {ne:,} edges updated in {time.time() - t0:.1f}s")

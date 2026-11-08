"""Integrate AI attack-detector results as a second overlay alongside ground truth.

The detector JSON (``NETWORK_DETECTOR_RESULTS/detector-results.json``) holds, per
dataset, a list of *regions* (detected attack clusters). Each region carries an
``attackType`` / ``knownAttackName`` / ``attackCategory`` / ``confidence``, a time
window, an optional ``responder`` (target) and ``_port``, free-text
``reason``/``evidence``, fine-grained ``flaggedPairs`` (initiator -> responder with
a close-type), and a per-IP role map (victim / attacker / infrastructure).

We store regions + flagged pairs verbatim, then overlay detector flags onto the
``edges`` and ``hosts`` rollups so the graph can show detector findings next to
the ground-truth labels.
"""
from __future__ import annotations

import json
import sqlite3

# Role precedence when an IP appears in several regions (most severe wins).
_ROLE_RANK = {"victim": 3, "attacker": 2, "infrastructure": 1}


def _sig(t_min, t_max, ips) -> str:
    return f"{t_min}|{t_max}|{','.join(ips)}"


def load_detector(conn: sqlite3.Connection, json_path: str) -> int:
    """Read the detector JSON into ``detector_regions`` + ``detector_pairs``.
    Returns the number of regions loaded. Uses the first (only) dataset."""
    with open(json_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    datasets = doc.get("datasets", {})
    if not datasets:
        return 0
    ds = next(iter(datasets.values()))

    # Lookups from signature -> roles / explanation text.
    role_by_sig = {k: v for k, v in ds.get("roleMaps", [])}
    explain_by_sig = {k: v for k, v in ds.get("explainCache", [])}

    conn.execute("DELETE FROM detector_regions")
    conn.execute("DELETE FROM detector_pairs")

    regions = ds.get("regions", [])
    pair_rows = []
    for rid, r in enumerate(regions):
        ips = r.get("ips", []) or []
        t_min = (r.get("tMinUs") or 0) / 1e6  # microseconds -> epoch seconds
        t_max = (r.get("tMaxUs") or 0) / 1e6
        sig = _sig(r.get("tMinUs"), r.get("tMaxUs"), ips)
        roles = role_by_sig.get(sig)
        explain = explain_by_sig.get(sig)
        pairs = r.get("flaggedPairs") or []
        conn.execute(
            """INSERT INTO detector_regions
               (region_id,attack_type,known_name,category,confidence,responder,port,
                t_min,t_max,n_ips,n_pairs,reason,evidence,roles_json,explain,ips_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, r.get("attackType"), r.get("knownAttackName"), r.get("attackCategory"),
             r.get("confidence"), r.get("responder"), r.get("_port"),
             t_min, t_max, len(ips), len(pairs), r.get("reason"), r.get("evidence"),
             json.dumps(roles) if roles is not None else None,
             explain if isinstance(explain, str) else None,
             json.dumps(ips)),
        )
        for p in pairs:
            pair_rows.append((rid, p.get("i"), p.get("r"), p.get("c"),
                              p.get("ct"), p.get("dp")))
    if pair_rows:
        conn.executemany(
            """INSERT INTO detector_pairs
               (region_id,initiator,responder,count,close_type,dst_port)
               VALUES (?,?,?,?,?,?)""", pair_rows)
    conn.commit()
    return len(regions)


def label_detector(conn: sqlite3.Connection) -> dict:
    """Overlay detector regions onto edges and hosts (only IPs we actually
    captured get flagged). Returns coverage stats."""
    # Reset detector columns.
    conn.execute("UPDATE edges SET detector_flag=0, detector_types=NULL")
    conn.execute("UPDATE hosts SET detector_flag=0, detector_types=NULL, "
                 "detector_confidence=0, detector_role=NULL")

    host_types: dict[str, set] = {}
    host_conf: dict[str, float] = {}
    host_role: dict[str, str] = {}
    edge_types: dict[tuple, set] = {}

    regions = conn.execute(
        "SELECT region_id,attack_type,confidence,responder,roles_json,ips_json "
        "FROM detector_regions"
    ).fetchall()
    for rid, atype, conf, responder, roles_json, ips_json in regions:
        roles = dict(json.loads(roles_json)) if roles_json else {}
        region_ips = json.loads(ips_json) if ips_json else []

        # Host-level: flag every IP the detector named for this region -- the
        # flagged-pair endpoints, the region's full member roster (`ips_json`),
        # and the roles map, unioned together. The roster is included
        # unconditionally (not just as a no-pairs fallback) so every named member
        # is flagged, so the detector-host count matches the detector's full IP
        # set rather than only hosts that happen to carry an explicit pair.
        ips = {r[0] for r in conn.execute(
            "SELECT DISTINCT initiator FROM detector_pairs WHERE region_id=? "
            "UNION SELECT DISTINCT responder FROM detector_pairs WHERE region_id=?",
            (rid, rid))}
        ips |= set(region_ips) | set(roles.keys())
        if responder:
            ips.add(responder)
        for ip in ips:
            host_types.setdefault(ip, set()).add(atype)
            if conf and conf > host_conf.get(ip, 0):
                host_conf[ip] = conf
            role = roles.get(ip)
            if role and _ROLE_RANK.get(role, 0) > _ROLE_RANK.get(host_role.get(ip, ""), 0):
                host_role[ip] = role

        # Edge-level: from explicit flagged pairs (directional initiator->responder).
        for ini, resp in conn.execute(
            "SELECT initiator, responder FROM detector_pairs WHERE region_id=?", (rid,)):
            if ini and resp:
                edge_types.setdefault((ini, resp), set()).add(atype)
        # Regions with a single responder but no pairs: flag IPs -> responder.
        if responder and not conn.execute(
            "SELECT 1 FROM detector_pairs WHERE region_id=? LIMIT 1", (rid,)).fetchone():
            for ip in (region_ips or roles):
                if ip != responder:
                    edge_types.setdefault((ip, responder), set()).add(atype)

    # Write host overlay (only rows that exist in hosts are affected).
    conn.executemany(
        """UPDATE hosts SET detector_flag=1, detector_types=?, detector_confidence=?,
                            detector_role=? WHERE ip=?""",
        [("; ".join(sorted(host_types[ip])), host_conf.get(ip, 0),
          host_role.get(ip), ip) for ip in host_types])
    # Write edge overlay (match the directional edge regardless of proto).
    conn.executemany(
        """UPDATE edges SET detector_flag=1, detector_types=?
           WHERE src_ip=? AND dst_ip=?""",
        [("; ".join(sorted(types)), s, d) for (s, d), types in edge_types.items()])
    conn.commit()

    flagged_hosts = conn.execute(
        "SELECT COUNT(*) FROM hosts WHERE detector_flag=1").fetchone()[0]
    flagged_edges = conn.execute(
        "SELECT COUNT(*) FROM edges WHERE detector_flag=1").fetchone()[0]
    return {"regions": len(regions), "flagged_hosts": flagged_hosts,
            "flagged_edges": flagged_edges}

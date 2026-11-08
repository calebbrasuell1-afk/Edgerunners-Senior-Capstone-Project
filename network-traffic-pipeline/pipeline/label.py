"""Join captured flows against the ground-truth attack catalogue.

A flow is labelled malicious when its host pair matches a ground-truth event
(in either direction), its time window overlaps the event window (+/- a
tolerance), and the service port matches (or the event leaves ports
unspecified). Labels then propagate to the ``edges`` and ``hosts`` rollups.
"""
from __future__ import annotations

import datetime as dt
import sqlite3

import pandas as pd


def parse_ports(s) -> tuple[set, list] | None:
    """Parse a ground-truth port cell. Returns ``None`` for "unspecified"
    (matches any port), else ``(singles, ranges)``."""
    s = "" if s is None else str(s).strip()
    if s in ("", "0", "0.0", "nan", "NaN"):
        return None
    singles: set[int] = set()
    ranges: list[tuple[int, int]] = []
    for tok in s.replace(",", " ").split():
        if ":" in tok:
            lo, hi = tok.split(":", 1)
            ranges.append((int(float(lo)), int(float(hi))))
        else:
            try:
                singles.add(int(float(tok)))
            except ValueError:
                continue
    return (singles, ranges)


def _port_match(port: int, parsed) -> bool:
    if parsed is None:
        return True
    singles, ranges = parsed
    if port in singles:
        return True
    return any(lo <= port <= hi for lo, hi in ranges)


def _to_epoch(s: str) -> float:
    return dt.datetime.strptime(str(s).strip(), "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=dt.timezone.utc
    ).timestamp()


def load_ground_truth(conn: sqlite3.Connection, csv_path: str) -> list[dict]:
    """Read the CSV into the ``gt_events`` table and return parsed events."""
    df = pd.read_csv(csv_path)
    conn.execute("DELETE FROM gt_events")
    events = []
    rows = []
    for _, row in df.iterrows():
        try:
            start = _to_epoch(row["Start Time (UTC)"])
            stop = _to_epoch(row["Stop Time (UTC)"])
        except Exception:
            continue
        ev = {
            "c2s_id": row.get("C2S ID"),
            "event_type": str(row.get("Event Type", "")).strip(),
            "src": str(row.get("Source", "")).strip(),
            "dst": str(row.get("Destination", "")).strip(),
            "src_ports": parse_ports(row.get("Source Port(s)")),
            "dst_ports": parse_ports(row.get("Destination Port(s)")),
            "start": start,
            "stop": stop,
        }
        events.append(ev)
        rows.append((row.get("C2S ID"), ev["event_type"], ev["src"],
                     str(row.get("Source Port(s)")), ev["dst"],
                     str(row.get("Destination Port(s)")), start, stop))
    conn.executemany(
        """INSERT INTO gt_events
           (c2s_id,event_type,src,src_ports,dst,dst_ports,start_utc,stop_utc)
           VALUES (?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    return events


def label_flows(conn: sqlite3.Connection, events: list[dict], tol: float = 60.0) -> dict:
    """Match flows to events and write labels. Returns coverage stats."""
    # Pull all flows into memory, indexed by ordered (src,dst).
    cur = conn.execute(
        "SELECT rowid, src_ip, dst_ip, src_port, dst_port, first_ts, last_ts FROM flows"
    )
    index: dict[tuple[str, str], list] = {}
    total = 0
    for rid, s, d, sp, dp, ft, lt in cur:
        total += 1
        index.setdefault((s, d), []).append((rid, sp, dp, ft, lt))

    labels: dict[int, set] = {}   # rowid -> set of attack types

    def consider(bucket, port_of, parsed_ports, ev_start, ev_stop, atype):
        for rid, sp, dp, ft, lt in bucket:
            # time overlap with tolerance
            if lt < ev_start - tol or ft > ev_stop + tol:
                continue
            port = sp if port_of == "src" else dp
            if _port_match(port, parsed_ports):
                labels.setdefault(rid, set()).add(atype)

    for ev in events:
        fwd = index.get((ev["src"], ev["dst"]))
        if fwd:
            # forward flow: service port appears as dst_port
            consider(fwd, "dst", ev["dst_ports"], ev["start"], ev["stop"], ev["event_type"])
        rev = index.get((ev["dst"], ev["src"]))
        if rev:
            # reverse flow: service port appears as src_port
            consider(rev, "src", ev["dst_ports"], ev["start"], ev["stop"], ev["event_type"])

    # Write labels back.
    conn.execute("UPDATE flows SET label=0, attack_type=NULL")
    conn.executemany(
        "UPDATE flows SET label=1, attack_type=? WHERE rowid=?",
        [("; ".join(sorted(types)), rid) for rid, types in labels.items()],
    )
    conn.commit()
    return {"total_flows": total, "labeled_flows": len(labels),
            "coverage_pct": round(100.0 * len(labels) / total, 3) if total else 0.0}


def propagate(conn: sqlite3.Connection) -> None:
    """Push flow labels up to edges (either direction) and hosts."""
    # Edges: mark malicious where the host pair has any labeled flow in either direction.
    conn.execute("UPDATE edges SET malicious=0, attack_types=NULL")
    conn.execute(
        """
        WITH pair_types AS (
            SELECT src_ip AS a, dst_ip AS b, attack_type FROM flows WHERE label=1
            UNION ALL
            SELECT dst_ip AS a, src_ip AS b, attack_type FROM flows WHERE label=1
        )
        UPDATE edges
        SET malicious = 1,
            attack_types = (
                SELECT GROUP_CONCAT(DISTINCT attack_type)
                FROM pair_types pt
                WHERE pt.a = edges.src_ip AND pt.b = edges.dst_ip
            )
        WHERE EXISTS (
            SELECT 1 FROM pair_types pt
            WHERE pt.a = edges.src_ip AND pt.b = edges.dst_ip
        )
        """
    )
    # Hosts: mark any IP appearing on either side of a labeled flow.
    conn.execute("UPDATE hosts SET malicious_flag=0, attack_types=NULL")
    conn.execute(
        """
        WITH host_types AS (
            SELECT src_ip AS ip, attack_type FROM flows WHERE label=1
            UNION ALL
            SELECT dst_ip AS ip, attack_type FROM flows WHERE label=1
        )
        UPDATE hosts
        SET malicious_flag = 1,
            attack_types = (
                SELECT GROUP_CONCAT(DISTINCT attack_type)
                FROM host_types ht WHERE ht.ip = hosts.ip
            )
        WHERE EXISTS (SELECT 1 FROM host_types ht WHERE ht.ip = hosts.ip)
        """
    )
    conn.commit()

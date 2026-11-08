"""Roll up per-flow TCP close types from the archived parquet flow-list shards
into ``pair_close_types`` (see db.py), so the Force Graph can show each edge's
close-type distribution. This is the only place close_type has full coverage
(the SQLite ``flows`` table never captured it) -- ``detector_pairs`` only has
it for detector-flagged pairs and is used as a fallback when the shards aren't
available (see export_json.load_pair_close_types).

The shards store close_type as an integer code; the mapping below was derived
by decoding each code's packet-flag sequence (SYN/SYN-ACK/RST/FIN-ACK) and
cross-referencing with the detector JSON's named close types for pairs that
appear in both sources.
"""
from __future__ import annotations

import glob
import sqlite3
from pathlib import Path

CODE_TO_NAME = {
    0: "ongoing",
    1: "graceful",
    2: "abortive",
    4: "rst_during_handshake",
    5: "invalid_ack",
    7: "incomplete_no_synack",
    8: "incomplete_no_ack",
}


def _name(code: int) -> str:
    return CODE_TO_NAME.get(code, f"other_{code}")


def build_pair_close_types(conn: sqlite3.Connection, flow_list_dir: str | Path) -> int:
    """Read every ``flows_*.parquet`` shard in ``flow_list_dir`` and rewrite
    ``pair_close_types`` with (unordered pair, close_type) -> flow count.
    Returns the number of rows written (0 if no shards were found)."""
    import pandas as pd

    shards = sorted(glob.glob(str(Path(flow_list_dir) / "flows_*.parquet")))
    conn.execute("DELETE FROM pair_close_types")
    if not shards:
        conn.commit()
        return 0

    totals: dict[tuple[str, str, str], int] = {}
    for shard in shards:
        df = pd.read_parquet(shard, columns=["ip1", "ip2", "close_type"])
        a = df["ip1"].where(df["ip1"] < df["ip2"], df["ip2"])
        b = df["ip2"].where(df["ip1"] < df["ip2"], df["ip1"])
        names = df["close_type"].map(_name)
        grouped = pd.DataFrame({"a": a, "b": b, "ct": names}).value_counts()
        for (ip_a, ip_b, ct), n in grouped.items():
            key = (ip_a, ip_b, ct)
            totals[key] = totals.get(key, 0) + int(n)

    rows = [(a, b, ct, n) for (a, b, ct), n in totals.items()]
    conn.executemany(
        "INSERT INTO pair_close_types (ip_a, ip_b, close_type, n) VALUES (?,?,?,?)",
        rows,
    )
    conn.commit()
    return len(rows)


def main(argv=None):
    import argparse

    from config import load_config, resolve
    import db

    ap = argparse.ArgumentParser(
        description="Backfill pair_close_types from archived parquet shards and re-export JSON.")
    ap.add_argument("--config", default=None)
    ap.add_argument("--no-export", action="store_true")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    db_path = resolve(cfg["paths"]["db_path"])
    flow_shards_dir = cfg["paths"].get("flow_shards_dir")

    conn = db.connect(db_path)
    db.init_schema(conn)

    if not flow_shards_dir:
        print("(paths.flow_shards_dir not set in config; nothing to do)")
        conn.close()
        return 1

    n = build_pair_close_types(conn, resolve(flow_shards_dir))
    print(f"pair_close_types: {n:,} rows")

    if not args.no_export and n:
        import export_json
        export_dir = resolve(cfg["paths"]["export_dir"])
        top_n_nodes = cfg["export"]["top_n_nodes"]
        top_n_edges = cfg["export"]["top_n_edges"]
        bucket = cfg["export"].get("timeline_bucket_seconds", 60)
        res = export_json.export_all(conn, export_dir, top_n_nodes, top_n_edges, bucket)
        print(f"Exported -> {export_dir}: {res['nodes']} nodes, {res['edges']} edges")

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

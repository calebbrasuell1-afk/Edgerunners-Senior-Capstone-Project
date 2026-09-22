#!/usr/bin/env python3
"""Export data/network.db to viz/public/data/*.json for the browser app.

Thin CLI wrapper around pipeline/export_json.py. Run from the project root:

    python3 export_db.py
    python3 export_db.py --db data/network.db --out viz/public/data
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "pipeline"))

import export_json  # noqa: E402
from config import load_config, resolve  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Export network.db to the JSON files the visualization reads.")
    ap.add_argument("--config", default=None, help="pipeline/config.yaml path")
    ap.add_argument("--db", default=None,
                    help="SQLite database (default: paths.db_path from config)")
    ap.add_argument("--out", default=None,
                    help="Output directory (default: paths.export_dir from config)")
    ap.add_argument("--top-n-nodes", type=int, default=None,
                    help="Max standalone hosts to include (default: from config)")
    ap.add_argument("--top-n-edges", type=int, default=None,
                    help="Heaviest edges to include (default: from config)")
    ap.add_argument("--bucket-seconds", type=int, default=None,
                    help="TimeArcs bucket size (default: from config)")
    ap.add_argument("--gt-only", action="store_true",
                    help="Rewrite only gt_events.json, reusing the capture window from the "
                         "existing meta.json. Seconds instead of a full re-export.")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    db_path = resolve(args.db or cfg["paths"]["db_path"])
    export_dir = resolve(args.out or cfg["paths"]["export_dir"])
    top_n_nodes = args.top_n_nodes or cfg["export"]["top_n_nodes"]
    top_n_edges = args.top_n_edges or cfg["export"]["top_n_edges"]
    bucket = args.bucket_seconds or cfg["export"].get("timeline_bucket_seconds", 60)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 1

    print(f"Reading  {db_path}")
    print(f"Writing  {export_dir}")
    conn = sqlite3.connect(db_path)
    try:
        if args.gt_only:
            # The window normally comes from a MIN/MAX over the flows table, which is the
            # expensive part of a full export on a multi-gigabyte db. The previous export
            # already computed it, so read it back instead of recomputing it.
            meta_path = export_dir / "meta.json"
            tmin = tmax = None
            if meta_path.exists():
                import json
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                tmin, tmax = meta.get("time_min"), meta.get("time_max")
            else:
                print("  (no meta.json — exporting the whole ground-truth table)")
            res = {"gt_events": export_json.export_gt_events(
                conn, export_dir, tmin, tmax)}
        else:
            res = export_json.export_all(
                conn, export_dir, top_n_nodes, top_n_edges, bucket)
    finally:
        conn.close()

    print(f"Exported -> {export_dir}")
    for key, val in res.items():
        if isinstance(val, int):
            print(f"  {key}: {val:,}")
        else:
            print(f"  {key}: {val}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

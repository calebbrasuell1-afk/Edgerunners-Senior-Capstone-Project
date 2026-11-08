"""Orchestrate the full pipeline:

    download -> (per file: stream-parse -> aggregate-into-db -> delete raw)
             -> build edges/hosts -> label with ground truth -> export JSON

Safety: only files living inside ``raw_dir`` are deleted. Captures discovered in
``local_source_dir`` (e.g. your original dataset in the project root) are never
removed, regardless of --keep-raw.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import aggregate
import close_types
import coverage
import db
import detector
import export_json
import label
import parse_flows
from config import load_config, resolve


def _parse_worker(path_str: str):
    """Top-level (picklable) worker for multiprocessing."""
    return path_str, parse_flows.parse_file(path_str)


def collect_local(raw_dir: Path, local_dir: Path) -> list[Path]:
    """Find captures to process. Prefer .pcap.xz; fall back to .pcap per stem.
    raw_dir is searched first (deletable), then local_dir (protected)."""
    by_stem: dict[str, Path] = {}
    for d in (raw_dir, local_dir):
        if not d or not d.exists():
            continue
        for pat in ("*.pcap.xz", "*.pcap"):
            for p in sorted(d.glob(pat)):
                stem = p.name[:-3] if p.name.endswith(".xz") else p.name
                # First directory wins; within a dir prefer .pcap.xz (seen first).
                by_stem.setdefault(stem, p)
    return list(by_stem.values())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the PCAP aggregation pipeline.")
    ap.add_argument("--config", default=None)
    ap.add_argument("--skip-download", action="store_true",
                    help="use captures already on disk (raw_dir / local_source_dir)")
    ap.add_argument("--max-files", type=int, default=None,
                    help="download at most N matching files (0 = no limit)")
    ap.add_argument("--skip", type=int, default=None,
                    help="skip the first N matching files before downloading")
    ap.add_argument("--append", action="store_true",
                    help="add to the existing database instead of rebuilding from "
                         "scratch (keeps previously ingested captures)")
    ap.add_argument("--keep-raw", action="store_true",
                    help="do not delete captures from raw_dir after parsing")
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--top-n-nodes", type=int, default=None)
    ap.add_argument("--top-n-edges", type=int, default=None)
    ap.add_argument("--tol", type=float, default=None, help="label time tolerance (s)")
    ap.add_argument("--no-export", action="store_true")
    ap.add_argument("--close-types-only", action="store_true",
                    help="Re-derive ONLY the parse-time close-type rollup: download and "
                         "parse each capture, write pair_close_types_parsed, and skip "
                         "flows/buckets and every rollup, label, detector and export "
                         "stage. For re-deriving close types after a classifier change "
                         "without redoing hours of aggregation that is already correct. "
                         "Progress is tracked in close_types_done so it can resume.")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    raw_dir = resolve(cfg["paths"]["raw_dir"])
    local_dir = resolve(cfg["paths"].get("local_source_dir", "."))
    db_path = resolve(cfg["paths"]["db_path"])
    export_dir = resolve(cfg["paths"]["export_dir"])
    gt_path = resolve(cfg["paths"]["ground_truth"])
    detector_path = resolve(cfg["paths"].get("detector_results", "")) \
        if cfg["paths"].get("detector_results") else None
    internal_cidr = cfg["parse"]["internal_cidr"]
    workers = args.workers or cfg["parse"].get("workers", 1)
    min_packets = cfg["parse"].get("min_packets", 0)
    tol = args.tol if args.tol is not None else cfg["label"].get("tolerance_seconds", 60)
    top_n_nodes = args.top_n_nodes or cfg["export"]["top_n_nodes"]
    top_n_edges = args.top_n_edges or cfg["export"]["top_n_edges"]
    bucket = cfg["export"].get("timeline_bucket_seconds", 60)

    dl = cfg["download"]
    max_files = args.max_files if args.max_files is not None else dl.get("max_files", 0)
    skip = args.skip if args.skip is not None else dl.get("skip", 0)
    # Basic Auth: env var PCAP_DL_PASSWORD overrides the config password so the
    # secret need not live in config.yaml. Auth is sent only if a username is set.
    dl_user = os.environ.get("PCAP_DL_USERNAME") or dl.get("username") or ""
    dl_pass = os.environ.get("PCAP_DL_PASSWORD") or dl.get("password") or ""
    dl_auth = (dl_user, dl_pass) if dl_user else None
    # Same override for the source URL itself -- it's a personal/authenticated
    # share link, so it lives in .env rather than the committed config.yaml.
    dl_source_url = os.environ.get("PCAP_DL_SOURCE_URL") or dl.get("source_url") or ""

    t_start = time.time()
    conn = db.connect(db_path)
    db.init_schema(conn)
    # Default: rebuild from scratch. With --append, keep existing flows so new
    # captures accumulate (edges/hosts are always rederived from the full flows
    # table below, so they don't need preserving).
    if not args.append:
        db.reset_tables(conn, ["flows", "edges", "hosts", "host_buckets", "ingested",
                               "pair_close_types_parsed"])
    # Captures already parsed into the DB -- skip these so re-running an
    # overlapping range can't double-count flows. In --close-types-only mode the
    # captures ARE already in `ingested` (that's the point: their flows are fine,
    # only the close types need redoing), so the guard moves to its own table.
    if args.close_types_only:
        already = {r[0] for r in conn.execute("SELECT name FROM close_types_done")}
        print(f"close-types-only: {len(already)} capture(s) already redone")
    else:
        already = {r[0] for r in conn.execute("SELECT name FROM ingested")}

    raw_dir_resolved = raw_dir.resolve()

    def maybe_delete(path: Path):
        # Only delete inside raw_dir; never the user's original source files.
        if args.keep_raw:
            return
        try:
            if path.resolve().parent == raw_dir_resolved:
                path.unlink()
                print(f"  deleted raw: {path.name}")
        except OSError as e:
            print(f"  (could not delete {path.name}: {e})", file=sys.stderr)

    def record_ingested(name: str, n_flows: int):
        conn.execute("INSERT OR REPLACE INTO ingested (name, n_flows, ts) VALUES (?,?,?)",
                     (name, n_flows, time.time()))
        conn.commit()

    # 1+2. Acquire + parse + aggregate (+ delete raw as we go).
    total_flows = 0
    if not args.skip_download:
        if not dl_source_url:
            print("No download.source_url configured. Set PCAP_DL_SOURCE_URL in "
                  ".env, or run with --skip-download to use files already on disk.")
            return 1
        # Streaming path: download ONE file, parse it, delete it, then fetch the
        # next. Peak disk stays at a single capture instead of the whole set.
        import download
        links = download.discover_links(dl_source_url, dl["link_regex"],
                                        dl.get("verify_tls", True), dl_auth)
        total = len(links)
        if skip > 0:
            links = links[skip:]
        if max_files and max_files > 0:
            links = links[:max_files]
        print(f"discovered {total} file(s); downloading+processing {len(links)} "
              f"(skip={skip}, max_files={max_files or 'all'}) with 1 worker:")
        if not links:
            print("No matching files to download. Check link_regex / source_url.")
            return 1
        for i, url in enumerate(links, 1):
            name = url.rstrip("/").split("/")[-1]
            if name in already:
                print(f"  [{i}/{len(links)}] skip (already ingested): {name}")
                continue
            path = download.download_file(url, raw_dir, dl.get("verify_tls", True), dl_auth)
            flows, buckets, conns = parse_flows.parse_file(str(path))
            if args.close_types_only:
                # Close types only: the flows/buckets from this capture are already
                # in the DB and correct, so writing them again would double-count.
                n_c = sum(conns.values())
                aggregate.write_close_types(conn, conns)
                conn.execute("INSERT OR REPLACE INTO close_types_done (name,n,ts) "
                             "VALUES (?,?,?)", (name, n_c, time.time()))
                conn.commit()
                print(f"  [{i}/{len(links)}] close types {path.name}: {n_c:,} attempts")
            else:
                n = aggregate.write_flows(conn, flows, min_packets)
                aggregate.write_buckets(conn, buckets)
                aggregate.write_close_types(conn, conns)
                total_flows += n
                record_ingested(name, n)
                print(f"  [{i}/{len(links)}] parsed {path.name}: {n:,} flows")
            maybe_delete(path)
    else:
        # Local path: files are already on disk, so parse them in parallel.
        captures = [p for p in collect_local(raw_dir, local_dir) if p.name not in already]
        if not captures:
            print("No new captures found. Provide a source_url or place files in raw_dir/local_source_dir.")
            return 1
        print(f"Processing {len(captures)} capture(s) with {workers} worker(s):")
        for c in captures:
            print(f"  - {c}")
        paths = [str(p) for p in captures]
        if workers and workers > 1 and len(paths) > 1:
            import multiprocessing as mp
            with mp.Pool(min(workers, len(paths))) as pool:
                for path_str, (flows, buckets, conns) in pool.imap_unordered(_parse_worker, paths):
                    n = aggregate.write_flows(conn, flows, min_packets)
                    aggregate.write_buckets(conn, buckets)
                    aggregate.write_close_types(conn, conns)
                    total_flows += n
                    record_ingested(Path(path_str).name, n)
                    print(f"  parsed {Path(path_str).name}: {n:,} flows")
                    maybe_delete(Path(path_str))
        else:
            for path_str in paths:
                flows, buckets, conns = parse_flows.parse_file(path_str)
                n = aggregate.write_flows(conn, flows, min_packets)
                aggregate.write_buckets(conn, buckets)
                aggregate.write_close_types(conn, conns)
                total_flows += n
                record_ingested(Path(path_str).name, n)
                print(f"  parsed {Path(path_str).name}: {n:,} flows")
                maybe_delete(Path(path_str))

    if args.close_types_only:
        rows, attempts = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(n),0) FROM pair_close_types_parsed").fetchone()
        print(f"Close types (parsed): {rows:,} pair rows / {attempts:,} attempts")
        for ct, n in conn.execute("SELECT close_type, SUM(n) FROM pair_close_types_parsed "
                                  "GROUP BY 1 ORDER BY 2 DESC"):
            print(f"    {ct:<24}{n:>12,}")
        print("Rollups, labelling and detector were skipped (already correct). "
              "Re-export so the viz picks the new close types up.")
        print(coverage.run(conn, cfg, export_dir, db_path)[0])
        conn.close()
        print(f"Done in {time.time() - t_start:.1f}s")
        return 0

    print(f"Total flows this run: {total_flows:,}")

    # 3. Rollups.
    n_edges = aggregate.build_edges(conn)
    n_hosts = aggregate.build_hosts(conn, internal_cidr)
    aggregate.compute_anomaly(conn)
    aggregate.compute_rtt(conn)
    n_bsig = aggregate.build_bucket_signals(conn)
    print(f"Edges: {n_edges:,}  Hosts: {n_hosts:,}  Bucket-signal rows: {n_bsig:,}")

    # 4. Ground-truth labeling.
    if gt_path.exists():
        events = label.load_ground_truth(conn, str(gt_path))
        cov = label.label_flows(conn, events, tol)
        label.propagate(conn)
        print(f"Ground truth: {len(events):,} events  "
              f"labeled {cov['labeled_flows']:,}/{cov['total_flows']:,} flows "
              f"({cov['coverage_pct']}%)")
    else:
        print(f"(ground-truth file not found at {gt_path}; skipping labeling)")

    # 4b. AI-detector overlay (parallel to ground truth).
    if detector_path and detector_path.exists():
        n_reg = detector.load_detector(conn, str(detector_path))
        dcov = detector.label_detector(conn)
        print(f"Detector: {n_reg} regions  "
              f"flagged {dcov['flagged_hosts']} hosts / {dcov['flagged_edges']} edges "
              f"in capture window")
    elif detector_path:
        print(f"(detector file not found at {detector_path}; skipping detector overlay)")

    # 4c. Edge close-type distribution (Force Graph strips). Two sources, summed
    # at export: the archived parquet shards (first 90 min only) and the parse-time
    # rollup derived from TCP flags (everything ingested since). Export falls back
    # to detector_pairs only if both are empty.
    flow_shards_dir = cfg["paths"].get("flow_shards_dir")
    if flow_shards_dir and resolve(flow_shards_dir).exists():
        n_pct = close_types.build_pair_close_types(conn, resolve(flow_shards_dir))
        print(f"Close types (shards): {n_pct:,} pair rows")
    elif flow_shards_dir:
        print(f"(flow shards not found at {flow_shards_dir}; close types come from "
              f"the parse-time rollup alone)")
    n_parsed, n_conns = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(n), 0) FROM pair_close_types_parsed").fetchone()
    print(f"Close types (parsed): {n_parsed:,} pair rows / {n_conns:,} connections")

    # 5. Export.
    if not args.no_export:
        res = export_json.export_all(conn, export_dir, top_n_nodes, top_n_edges, bucket)
        print(f"Exported -> {export_dir}: "
              f"{res['nodes']} nodes, {res['edges']} edges, {res['timeline']} arcs")

    # 6. Coverage audit. LAST, so it sees the export it is auditing, and unconditional --
    # the failure it exists to catch (a derived source silently covering less of the capture
    # than the capture now holds) is created by exactly the runs that add data, and is
    # invisible from inside the app afterwards. See pipeline/coverage.py.
    report, n_behind = coverage.run(conn, cfg, export_dir, db_path)
    print(report)

    conn.close()
    print(f"Done in {time.time() - t_start:.1f}s")
    if n_behind:
        # Not a failure exit: the run DID produce a valid DB and export, and most of the app
        # is fine. But it must not scroll past unremarked, which is how the 90/180-minute
        # split survived a full ingest unnoticed.
        print(f"WARNING: {n_behind} source(s) do not cover the whole capture (above). "
              f"Run `python pipeline/coverage.py --strict` in CI to gate on this.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

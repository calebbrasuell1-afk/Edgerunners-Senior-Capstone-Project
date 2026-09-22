"""Time-coverage audit: does every derived, time-bounded source still cover the capture?

WHY THIS EXISTS
---------------
The app reads several sources that are DERIVED from the capture and carry their own time
range, and one source that IS the capture (``host_buckets``, the 10s grid every per-bucket
series is built on). Ingesting new data grows the capture. It does not grow the derived
sources, and nothing used to compare them -- so a source could silently cover half the
capture while every chart drawn from it kept rendering, just emptily, over the half it had.

That is not hypothetical. The capture went from 90 to 180 minutes; the archived parquet
shards -- then the only close-type source carrying a per-flow timestamp -- stayed at 90. The
TimeArcs close-type violin drew nothing past minute 90 and said "no host in this chart
carries this signal", which points at the hosts. The hosts were fine. Nobody could have
noticed from inside the app, because a half-covered source and a genuinely quiet half of a
capture look identical.

No close-type view reads the shards any more. All three -- the TimeArcs violin, the per-host
drill-down and the per-edge panel -- are derived from the `flows` table, which is written by
the same runs that define the capture and so cannot fall behind (see server/signals.py
_close_series_from_flows). The shards are still reported below, because they still build the
pair-level `pair_close_types` rollup, but a gap there no longer empties a chart: that rollup
is summed with the parse-time `pair_close_types_parsed`, which covers everything ingested
since. Hence `series=False` on that row -- see the Source docstring.

So coverage is made an explicit, measured property here, checked on every pipeline run and
printed next to the other stage summaries. A source that falls behind the capture now says
so at ingest time, by name, with the interval it is missing.

ADDING A SOURCE
---------------
Append to :func:`sources`. Anything with a time range belongs here; the cost of a row is a
few lines and the cost of omitting one is the failure above. `required=False` marks a source
whose ABSENCE is a legitimate deployment choice (the shards are optional). It does not
excuse a source from the coverage check: absent is a configuration, behind is a bug, and a
source that is present but incomplete fails --strict whether it is required or not.
"""
from __future__ import annotations

import glob
import gzip
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from parse_flows import BUCKET_SECONDS

# A source is "behind" only when it misses more than this much of the capture. One bucket of
# slack, because the derived grids round their own way: the close-type series bins on the
# shard manifest's microsecond window while host_buckets floors to 10s, so the two disagree
# by a few seconds at the ends even when they cover the same capture.
TOLERANCE_S = float(BUCKET_SECONDS)

# The server clamps a bulk signal-series request to this many bins, and windowStats.js
# reconstructs per-window totals from that series -- which is only valid while one bin is one
# native bucket (a downsampled bin holds its MAX, which is not summable). Past this many
# buckets the server starts folding buckets together and that reconstruction goes quietly
# wrong, so the bucket count is checked against it too.
SIGNAL_BINS_MAX = 4096


@dataclass
class Source:
    """One time-bounded source, and what it covers."""
    key: str
    label: str
    t0: float | None                  # None = the source is absent entirely
    t1: float | None
    detail: str = ""
    required: bool = True
    note: str = ""                    # a non-coverage problem worth printing
    # Is a TIME SERIES drawn from this? Only those can fail the audit. A source whose window
    # feeds nothing time-indexed -- or whose gap another source fills -- is still reported,
    # because knowing where it reaches is useful, but a short window is not a bug there. Set
    # this False only when a gap provably cannot empty a chart; the default is the safe one.
    series: bool = True

    @property
    def present(self) -> bool:
        return self.t0 is not None and self.t1 is not None


def capture_span(conn: sqlite3.Connection) -> tuple[float, float] | None:
    """The authoritative capture window, from ``host_buckets``.

    That table rather than ``flows`` because it is the grid the per-bucket signal series are
    built on, so it is what every time-series consumer is implicitly measured against. Its
    last bucket is a START, so a bucket's width is added to reach the real end.
    """
    row = conn.execute("SELECT MIN(bucket), MAX(bucket) FROM host_buckets").fetchone()
    if not row or row[0] is None:
        return None
    return float(row[0]), float(row[1]) + BUCKET_SECONDS


_SHARD_LABEL = "close-type pair rollup (shards)"


def _shard_window(flow_shards_dir: str | Path | None) -> tuple[Source, ...]:
    """The archived parquet shards, reported but no longer able to empty a chart.

    Their window comes from the shard-set manifest two levels up from the flow_list dir.

    Scope note, because this row used to be the whole reason the module exists: every
    close-type TIME series -- the TimeArcs violin, the per-host drill-down, the per-edge
    panel -- now derives from `flows` and covers whatever the capture covers. What the
    shards still do is build `pair_close_types`, a pair-level rollup with no time axis, and
    export_json sums that with the parse-time `pair_close_types_parsed` which covers
    everything ingested since. So the two halves are complete between them and a short
    shard window costs nothing. Reported at `series=False`: worth seeing, not worth failing.
    """
    if not flow_shards_dir:
        return (Source("close_series", _SHARD_LABEL, None, None,
                       detail="paths.flow_shards_dir not configured", required=False,
                       series=False),)
    d = Path(flow_shards_dir)
    shards = sorted(glob.glob(str(d / "flows_*.parquet")))
    if not shards:
        return (Source("close_series", _SHARD_LABEL, None, None,
                       detail=f"no flows_*.parquet under {d}", required=False, series=False),)
    manifest = d.parent.parent / "manifest.json"
    t0 = t1 = None
    note = ""
    if manifest.exists():
        try:
            tr = (json.loads(manifest.read_text(encoding="utf-8")) or {}).get("time_range") or {}
            if tr.get("start") is not None and tr.get("end") is not None:
                t0, t1 = tr["start"] / 1e6, tr["end"] / 1e6
        except (OSError, ValueError) as e:
            note = f"manifest unreadable ({e.__class__.__name__})"
    else:
        note = "no manifest.json; window unknown"
    return (Source("close_series", _SHARD_LABEL, t0, t1,
                   detail=f"{len(shards)} shard(s); pair-level totals only", required=False,
                   series=False, note=note),)


# The baked payload's own header, without parsing 39 MB of body: close_series_all builds its
# dict with these keys first and json.dumps preserves insertion order, so they are inside the
# first few hundred bytes. A miss just means the bake is skipped in the report, never a crash.
_HEAD_RE = re.compile(r'"t0":\s*([0-9.eE+-]+).*?"binSeconds":\s*([0-9.eE+-]+).*?"nBins":\s*(\d+)')


def _baked_caches(db_path: Path) -> list[Source]:
    """The pre-built close-type payloads under ``data/cache``.

    Still audited even though the filename now carries a fingerprint of the data
    (signals._close_fingerprint), which makes a superseded bake unreachable rather than
    merely wrong. The check earns its place on the leftovers: bakes written before that
    change are keyed on metric and bin count alone, and a v1 file sitting in the cache
    directory is exactly the "chart quietly drawn from last month's data" this module is
    for. They show up here as BEHIND until they are deleted.
    """
    out: list[Source] = []
    for path in sorted((db_path.parent / "cache").glob("close_all_*.json.gz")):
        t0 = t1 = None
        note = ""
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                head = fh.read(1024)
            m = _HEAD_RE.search(head)
            if m:
                t0 = float(m.group(1))
                width, n = float(m.group(2)), int(m.group(3))
                t1 = t0 + width * n
                # Resolution drift, which no span check can see. The bin count is pinned by a
                # constant (server _CLOSE_ALL_BINS / client CLOSE_BINS, both 542) while the
                # window it divides comes from the data -- so a capture that doubles silently
                # halves this feed's time resolution and it stops sharing a grid with the
                # signal series it is drawn beside.
                if abs(width - BUCKET_SECONDS) > BUCKET_SECONDS * 0.1:
                    note = (f"bins are {width:.1f}s, not the {BUCKET_SECONDS}s host_buckets "
                            f"grid - the pinned {n}-bin count no longer fits this capture")
            else:
                note = "header not recognized"
        except (OSError, ValueError, EOFError) as e:
            note = f"unreadable ({e.__class__.__name__})"
        out.append(Source(f"bake:{path.name}", f"baked cache {path.name}", t0, t1,
                          detail=f"{path.stat().st_size / 1e6:.1f} MB", required=False,
                          note=note))
    return out


def sources(conn: sqlite3.Connection, cfg: dict, export_dir: Path,
            db_path: Path) -> list[Source]:
    """Every time-bounded source, in reporting order."""
    out: list[Source] = []

    row = conn.execute("SELECT MIN(first_ts), MAX(last_ts) FROM flows").fetchone()
    out.append(Source("flows", "flows table", row[0], row[1],
                      detail=f"{conn.execute('SELECT COUNT(*) FROM flows').fetchone()[0]:,} rows"))

    n_buckets = conn.execute("SELECT COUNT(DISTINCT bucket) FROM host_buckets").fetchone()[0]
    note = ""
    if n_buckets > SIGNAL_BINS_MAX:
        # Not a coverage gap -- a resolution one, and invisible from any span check. Past the
        # clamp the server folds buckets together and windowStats' per-window reconstruction
        # (which sums bins) starts reading maxima instead of sums.
        note = (f"{n_buckets:,} buckets exceeds the {SIGNAL_BINS_MAX:,}-bin signal-series "
                f"clamp — bins stop being one bucket each and windowed sums go wrong")
    span = capture_span(conn)
    out.append(Source("host_buckets", "host_buckets grid (capture)",
                      span[0] if span else None, span[1] if span else None,
                      detail=f"{n_buckets:,} x {BUCKET_SECONDS}s buckets", note=note))

    meta_path = Path(export_dir) / "meta.json"
    if meta_path.exists():
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
            out.append(Source("export", "exported meta.json", m.get("time_min"),
                              m.get("time_max"), detail=str(meta_path)))
        except (OSError, ValueError) as e:
            out.append(Source("export", "exported meta.json", None, None,
                              detail=f"unreadable ({e.__class__.__name__})"))
    else:
        out.append(Source("export", "exported meta.json", None, None,
                          detail=f"not written yet ({meta_path})"))

    paths = cfg.get("paths") or {}
    shards_dir = paths.get("flow_shards_dir")
    if shards_dir:
        from config import resolve
        shards_dir = resolve(shards_dir)
    out.extend(_shard_window(shards_dir))
    out.extend(_baked_caches(db_path))
    return out


def audit(srcs: list[Source], span: tuple[float, float]) -> list[dict]:
    """Compare each source to the capture span. Returns one verdict dict per source."""
    c0, c1 = span
    total = max(c1 - c0, 1e-9)
    rows = []
    for s in srcs:
        if not s.present:
            rows.append({"src": s, "state": "absent", "pct": 0.0, "gaps": []})
            continue
        lo, hi = max(c0, s.t0), min(c1, s.t1)
        covered = max(0.0, hi - lo)
        gaps = []
        if s.t0 - c0 > TOLERANCE_S:
            gaps.append((c0, min(s.t0, c1)))
        if c1 - s.t1 > TOLERANCE_S:
            gaps.append((max(s.t1, c0), c1))
        state = "ok"
        if gaps:
            state = "behind" if s.series else "partial"
        rows.append({"src": s, "state": state, "pct": 100.0 * covered / total, "gaps": gaps})
    return rows


def _clock(t: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%m-%d %H:%M:%S")


def format_report(rows: list[dict], span: tuple[float, float]) -> str:
    """The printable audit, one line per source plus a verdict block."""
    c0, c1 = span
    out = [f"Coverage audit - capture {_clock(c0)} to {_clock(c1)} UTC "
           f"({(c1 - c0) / 60:.1f} min):"]
    width = max(len(r["src"].label) for r in rows) if rows else 0
    for r in rows:
        s = r["src"]
        if r["state"] == "absent":
            out.append(f"    {s.label:<{width}}      -  absent  ({s.detail})")
            continue
        mark = {"ok": "ok", "behind": "BEHIND", "partial": "partial"}[r["state"]]
        line = f"    {s.label:<{width}}  {r['pct']:5.1f}%  {mark}"
        if s.detail:
            line += f"  ({s.detail})"
        out.append(line)
        for g0, g1 in r["gaps"]:
            word = "missing" if r["state"] == "behind" else "does not reach"
            out.append(f"    {'':<{width}}          {word} {_clock(g0)} to {_clock(g1)} "
                       f"({(g1 - g0) / 60:.1f} min)")
        if r["state"] == "partial":
            out.append(f"    {'':<{width}}          (no time series is drawn from this, "
                       f"so the gap does not empty a chart)")
        if s.note:
            out.append(f"    {'':<{width}}          note: {s.note}")

    behind = [r for r in rows if r["state"] == "behind"]
    noted = [r for r in rows if r["src"].note and r["state"] != "behind"]
    if behind:
        out.append("")
        out.append(f"  {len(behind)} source(s) do NOT cover the whole capture. Charts drawn "
                   f"from them render empty over the missing interval, which in the app is")
        out.append("  indistinguishable from a quiet capture - see the module docstring.")
        for r in behind:
            out.append(f"    - {r['src'].label}: rebuild it, or scope the view to "
                       f"{_clock(max(c0, r['src'].t0))} to {_clock(min(c1, r['src'].t1))}")
    elif not noted:
        out.append("  All sources cover the capture.")
    return "\n".join(out)


def run(conn: sqlite3.Connection, cfg: dict, export_dir: Path,
        db_path: Path) -> tuple[str, int]:
    """Audit and render. Returns ``(report, n_bad)`` -- every source that is BEHIND, plus
    any REQUIRED source that is absent entirely."""
    span = capture_span(conn)
    if span is None:
        return ("Coverage audit - skipped: host_buckets is empty.", 0)
    rows = audit(sources(conn, cfg, export_dir, db_path), span)
    # BEHIND always counts, optional or not. `required` governs ABSENCE, which is a
    # deployment choice; being present and incomplete is never one. A source that exists is
    # a source the app will serve, and serving half a capture with no way to tell is the
    # exact failure this module was written for.
    n_bad = sum(1 for r in rows if r["state"] == "behind"
                or (r["state"] == "absent" and r["src"].required))
    return format_report(rows, span), n_bad


def main(argv=None) -> int:
    import argparse

    from config import load_config, resolve
    import db

    ap = argparse.ArgumentParser(
        description="Audit whether every derived, time-bounded source covers the capture.")
    ap.add_argument("--config", default=None, help="path to config.yaml")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when a REQUIRED source is behind the capture")
    args = ap.parse_args(argv)

    cfg = load_config(args.config) if args.config else load_config()
    paths = cfg.get("paths") or {}
    db_path = Path(resolve(paths.get("db_path", "data/network.db")))
    export_dir = Path(resolve(paths.get("export_dir", "viz/public/data")))

    conn = db.connect(str(db_path))
    try:
        report, n_bad = run(conn, cfg, export_dir, db_path)
    finally:
        conn.close()
    print(report)
    return 1 if (args.strict and n_bad) else 0


if __name__ == "__main__":
    raise SystemExit(main())

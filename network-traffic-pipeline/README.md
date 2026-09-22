# Network Traffic Pipeline

This package turns raw packet captures into connection statistics that you can
query. It reads the CDX 2009 capture files (`mypcap_*.pcap.xz`) and builds a SQLite
database of flows, hosts and host pairs. It labels the traffic against a
ground-truth attack catalogue. It then writes JSON files for a visualization.

This package contains the pipeline only. The browser application is not
included. `INTRODUCTION.md`, next to this file, introduces the whole project:
the visualization, the AI assistant, and two worked investigations.

## 1. What you need

- Python 3.10 or later. The pipeline was developed on Python 3.13.
- About 25 GB of network transfer for the 90-minute dataset.
- About 4 GB of free disk space.
- About 2 to 3 hours of run time. See section 4 for the measured numbers.

Check your Python version:

```bash
python --version
```

## 2. Install

```bash
pip install -r requirements.txt
```

This installs `dpkt`, `pandas`, `pyyaml`, `requests` and `tqdm`.

## 3. Add the download credentials

The capture files live on a share page that asks for a username and a password.

If this package holds a `.env` file, the link and the credentials are already
set. Go to section 4.

If it does not, the sender gives them to you separately. Copy the template and
fill in the three values:

```bash
cp .env.example .env            # bash
Copy-Item .env.example .env     # PowerShell
```

```
PCAP_DL_SOURCE_URL=<the set1 index page>
PCAP_DL_USERNAME=<your username>
PCAP_DL_PASSWORD=<your password>
```

The `.env` file stays on your machine. Do not commit it and do not share it.
Real environment variables take precedence over the values in `.env`.

If you already have the capture files on disk, you can skip this step. See
section 5.

## 4. How much data the 90-minute run needs

The dataset is one long capture that is cut into files of about 50 seconds each.
Each file is about 207 MB compressed and about 1 GB after decompression, and it
holds 1,000,000 packets. The file name carries the start time of the file.

The 90-minute dataset is the first 105 files, from
`mypcap_20091103082335.pcap.xz` to `mypcap_20091103095256.pcap.xz`. That is
13:23:30 to 14:53:35 UTC on 2009-11-03. The file names use a clock that is 5
hours behind UTC.

| Item | Value for 105 files |
| --- | --- |
| Download volume | about 22 GB |
| Peak disk use while the run works | about 1.5 GB |
| Parse time | about 55 minutes |
| Flows in the database | about 3.6 million |
| Size of `data/network.db` | about 1.4 GB |

The parse time comes from a measured 31 seconds for one file. The download runs
one file at a time, so your link speed adds to that number. Allow 2 to 3 hours
for the whole run.

Peak disk use stays low because the pipeline downloads one file, parses it, and
deletes it before it starts the next file. The decompressed 1 GB capture is
never written to disk.

`max_files: 105` is already set in `pipeline/config.yaml`. To try the pipeline
first on a small sample, run it with `--max-files 5`.

## 5. Run the pipeline

Download and process the first 105 files:

```bash
python pipeline/run.py
```

If you already have the capture files in the project folder or in `data/raw/`,
use them instead of the download:

```bash
python pipeline/run.py --skip-download --keep-raw
```

The run prints one line for each capture file, and then a summary in this
shape:

```
Total flows this run: 3,585,669
Edges: <N>  Hosts: <N>  Bucket-signal rows: <N>
Ground truth: 8,223 events  labeled <N>/3,585,669 flows (<P>%)
Detector: 14 regions  flagged <N> hosts / <N> edges in capture window
Exported -> data/export: <N> nodes, <N> edges, <N> arcs
```

The flow count above is the count for the first 105 files. The labeled share
stays small, because the ground truth covers ten days and the capture covers 90
minutes of them.

Only files inside `data/raw/` are ever deleted. Capture files that you put
somewhere else are never removed, even without `--keep-raw`.

If the run stops in the middle, start it again with `--append`. The pipeline
records every processed file in an `ingested` table, so it skips those files
instead of counting them twice.

```bash
python pipeline/run.py --append
```

## 6. What you get

`data/network.db` is a SQLite database with these tables:

- `flows`: one row for each 5-tuple, with packet, byte, time and TCP flag
  counts, plus the ground-truth label.
- `edges`: one row for each host pair.
- `hosts`: one row for each IP address, with fan-out and half-open SYN counts.
- `host_buckets`: per-host traffic in 10-second buckets.
- `gt_events`: the parsed ground-truth attack catalogue (8,223 events).
- `detector_regions` and `detector_pairs`: findings from the AI attack
  detector (14 regions).
- `pair_close_types_parsed`: how each host pair closed its connections.
- `ingested`: which capture files are already in the database.

`data/export/` holds `nodes.json`, `edges.json`, `timeline.json`, `meta.json`
and `detector.json`. The browser application reads these files.

Query the database directly:

```sql
-- top scanners by fan-out
SELECT ip, fanout, syn_no_synack FROM hosts ORDER BY fanout DESC LIMIT 10;

-- labeled attack flows
SELECT attack_type, COUNT(*) FROM flows WHERE label = 1 GROUP BY attack_type;

-- detector findings by confidence
SELECT attack_type, known_name, confidence, responder FROM detector_regions
ORDER BY confidence DESC;
```

To write the JSON export again without a new ingest, run:

```bash
python export_db.py
```

## 7. Make sure that the run kept up

Every run ends with a coverage audit. The audit compares the time range of the
capture with the time range of each derived source. You can run it at any time:

```bash
python pipeline/coverage.py            # print the report
python pipeline/coverage.py --strict   # exit 1 if a source is behind
```

```
Coverage audit - capture 11-03 13:23:30 to 11-03 14:53:35 UTC (90.1 min):
    flows table                                  99.9%  ok  (<N> rows)
    host_buckets grid (capture)                 100.0%  ok  (<N> x 10s buckets)
```

A `BEHIND` row names the source and the time range that it misses. The database
and the export are still valid, but a chart drawn from that source will be empty
over the missing range.

## 8. Settings in `pipeline/config.yaml`

| Key | What it does |
| --- | --- |
| `download.max_files` | How many files to fetch. 105 is the 90-minute dataset. 0 means all. |
| `download.skip` | How many files to skip first. Use it to fetch a later batch. |
| `paths.db_path` | Where the SQLite database goes. |
| `paths.export_dir` | Where the JSON export goes. |
| `parse.internal_cidr` | Which addresses count as internal. The default is `172.28.0.0/16`. |
| `parse.workers` | How many files to parse in parallel. This applies to `--skip-download` runs only. |
| `label.tolerance_seconds` | The time window for a match against a ground-truth event. |
| `export.top_n_nodes`, `export.top_n_edges` | How much the browser application loads. Attack traffic is always kept. |

Every key also works as a command-line flag. Run `python pipeline/run.py --help`
for the full list.

`paths.flow_shards_dir` is empty in this package. It points to an optional
archive of per-flow parquet files that is not included. The pipeline derives the
same connection close types from the TCP flags while it parses, so the result is
complete without the archive.

## 9. Get more than 90 minutes

The files after number 105 continue the same capture. To add the next batch to
the database that you have, pass `--append` with a skip count and a file count:

```bash
python pipeline/run.py --append --skip 105 --max-files 107   # up to 180 minutes
```

The full 180 minutes is 212 files, about 6.9 million flows and a 2.8 GB
database.

## 10. Troubleshooting

- "No download.source_url configured": `.env` is missing, or
  `PCAP_DL_SOURCE_URL` is empty. See section 3.
- HTTP 401, or a login that repeats: the username or the password is
  wrong. The page uses HTTP Basic Auth.
- "No captures found": you ran with `--skip-download`, but no `.pcap` or
  `.pcap.xz` file is in the project folder or in `data/raw/`. Add the files, or
  drop `--skip-download`.
- A download stops in the middle: the downloader retries 6 times and
  resumes from the bytes that it already has. If the whole run stops, start it
  again with `--append`.
- "Ground truth: 0 events": the date columns in
  `NETWORK_GROUNDTRUTH_DATA/GroundTruth_UTC_naive 2.csv` are no longer in the
  format `2009-11-03 13:36:00`. A spreadsheet program rewrites them to
  `11/3/2009 13:36` when it saves the file. Restore the original format, or
  open the file with a text editor only.
- Very few labeled flows: the ground truth covers 2009-11-03 to
  2009-11-13, and the capture covers 90 minutes of it. Only events inside the
  capture window can be labeled. This is expected.
- A `BEHIND` row in the coverage audit: see section 7.

## 11. What is in this package

```
INTRODUCTION.md             what the whole project does, and why
pipeline/run.py             the orchestrator, start here
pipeline/download.py        fetches the capture files, with resume
pipeline/parse_flows.py     streams .pcap.xz through lzma into dpkt
pipeline/aggregate.py       writes flows, then derives edges, hosts and signals
pipeline/label.py           joins flows to the ground-truth catalogue
pipeline/detector.py        overlays the AI detector findings
pipeline/close_types.py     optional parquet rollup, not used here
pipeline/export_json.py     writes the JSON that the browser application reads
pipeline/coverage.py        the coverage audit
pipeline/db.py              the SQLite schema
pipeline/config.py          configuration loading and .env loading
pipeline/config.yaml        all settings
export_db.py                runs the JSON export on its own
NETWORK_GROUNDTRUTH_DATA/   the ground-truth attack catalogue
                            `GroundTruth_UTC_naive 2.csv` is the pipeline input
                            `..._filtered_spambot.csv` is a reference list that
                            marks which events fall in the first 90 minutes
NETWORK_DETECTOR_RESULTS/   the AI detector findings
```

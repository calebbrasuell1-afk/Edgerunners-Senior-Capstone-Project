"""SQLite schema + helpers for the network-traffic pipeline.

Tables
------
flows      : one row per directional 5-tuple connection, with packet/byte/flag stats
edges      : host-pair (src_ip <-> dst_ip) rollups used by the graph views
hosts      : per-IP node statistics (fan-out, internal flag, in/out volume)
gt_events  : the parsed ground-truth attack catalogue
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    proto           TEXT NOT NULL,
    first_ts        REAL NOT NULL,
    last_ts         REAL NOT NULL,
    pkts            INTEGER NOT NULL,
    bytes           INTEGER NOT NULL,
    syn             INTEGER NOT NULL DEFAULT 0,
    synack          INTEGER NOT NULL DEFAULT 0,
    fin             INTEGER NOT NULL DEFAULT 0,
    rst             INTEGER NOT NULL DEFAULT 0,
    -- Phase-2 per-packet signals (populated only after a re-parse).
    first_syn_ts    REAL NOT NULL DEFAULT 0,    -- ts of first SYN sent in this direction
    first_synack_ts REAL NOT NULL DEFAULT 0,    -- ts of first SYN-ACK sent in this direction
    retrans         INTEGER NOT NULL DEFAULT 0, -- TCP retransmitted segments
    icmp_type       INTEGER NOT NULL DEFAULT -1,-- ICMP type (-1 = n/a)
    icmp_code       INTEGER NOT NULL DEFAULT -1,
    label           INTEGER NOT NULL DEFAULT 0, -- 1 if matched a ground-truth event
    attack_type     TEXT
);

-- Per-host, per-time-bucket counters (Phase 2). True packet-rate-over-time,
-- emitted at parse time because the raw capture is deleted afterwards.
CREATE TABLE IF NOT EXISTS host_buckets (
    ip          TEXT NOT NULL,
    bucket      INTEGER NOT NULL,    -- unix-second bucket start (BUCKET_SECONDS wide)
    pkts_in     INTEGER NOT NULL DEFAULT 0,
    pkts_out    INTEGER NOT NULL DEFAULT 0,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    syn_in      INTEGER NOT NULL DEFAULT 0,   -- SYNs received (connection attempts)
    synack_out  INTEGER NOT NULL DEFAULT 0,   -- SYN-ACKs sent (answered)
    rst         INTEGER NOT NULL DEFAULT 0,   -- RSTs involving the host
    retrans     INTEGER NOT NULL DEFAULT 0,   -- retransmits the host sent
    -- Flow-derived per-bucket signals, backfilled from the flows table by
    -- aggregate.build_bucket_signals (not accumulated at parse time). NULL means
    -- the rollup hasn't run yet; 0 is a real "none in this bucket".
    fanout          INTEGER,                  -- distinct dst IPs contacted
    ports_contacted INTEGER,                  -- distinct service ports requested (see
                                              -- aggregate.SERVICE_REQUEST_SQL)
    peers           INTEGER,                  -- distinct peers either direction
    syn_no_synack   INTEGER,                  -- outbound half-open attempts
    peak_conn_rate  INTEGER,                  -- busiest 1s of inbound new conns
    icmp_errors     INTEGER,                  -- ICMP unreachable/TTL-exceeded received
    rtt_ms          REAL,                     -- mean responder handshake RTT
    PRIMARY KEY (ip, bucket)
);

CREATE TABLE IF NOT EXISTS edges (
    src_ip             TEXT NOT NULL,
    dst_ip             TEXT NOT NULL,
    proto              TEXT NOT NULL,
    pkts               INTEGER NOT NULL,
    bytes              INTEGER NOT NULL,
    flow_count         INTEGER NOT NULL,
    distinct_dst_ports INTEGER NOT NULL,
    first_ts           REAL NOT NULL,
    last_ts            REAL NOT NULL,
    syn                INTEGER NOT NULL DEFAULT 0,   -- behavioral signals (flag sums)
    synack             INTEGER NOT NULL DEFAULT 0,
    rst                INTEGER NOT NULL DEFAULT 0,
    rst_rate           REAL NOT NULL DEFAULT 0,      -- RST packets / total packets
    malicious          INTEGER NOT NULL DEFAULT 0,
    attack_types       TEXT,
    detector_flag      INTEGER NOT NULL DEFAULT 0,   -- flagged by the AI detector
    detector_types     TEXT,
    PRIMARY KEY (src_ip, dst_ip, proto)
);

CREATE TABLE IF NOT EXISTS hosts (
    ip                       TEXT PRIMARY KEY,
    is_internal              INTEGER NOT NULL DEFAULT 0,
    pkts_in                  INTEGER NOT NULL DEFAULT 0,
    pkts_out                 INTEGER NOT NULL DEFAULT 0,
    bytes_in                 INTEGER NOT NULL DEFAULT 0,
    bytes_out                INTEGER NOT NULL DEFAULT 0,
    distinct_peers           INTEGER NOT NULL DEFAULT 0,
    -- distinct service ports this host requested; its own replies never count
    -- (see aggregate.SERVICE_REQUEST_SQL), so a pure responder scores 0.
    distinct_ports_contacted INTEGER NOT NULL DEFAULT 0,
    fanout                   INTEGER NOT NULL DEFAULT 0,   -- distinct dst IPs this host initiated to
    syn_no_synack            INTEGER NOT NULL DEFAULT 0,   -- outbound half-open attempts (scan signal)
    -- Behavioral / service-degradation signals (host as responder unless noted).
    syn_in                   INTEGER NOT NULL DEFAULT 0,   -- SYNs received (connection attempts)
    completion_ratio         REAL NOT NULL DEFAULT 1,      -- SYN-ACKs sent / SYNs received (1 = healthy)
    rst_rate                 REAL NOT NULL DEFAULT 0,      -- RST packets / total packets touching host
    peak_conn_rate           INTEGER NOT NULL DEFAULT 0,   -- max inbound new-connections / second
    anomaly_score            REAL NOT NULL DEFAULT 0,      -- max robust-z over behavioral signals
    anomaly_top              TEXT,                         -- which signal drove the score
    anomaly_breadth          INTEGER NOT NULL DEFAULT 0,   -- count of signals with z+ > 3.5
    anomaly_components        TEXT,                        -- JSON {signal: z+} for explainability
    -- Phase-2 service-degradation signals (populated only after a re-parse).
    retrans                  INTEGER NOT NULL DEFAULT 0,   -- retransmitted segments the host sent
    icmp_errors              INTEGER NOT NULL DEFAULT 0,   -- ICMP unreachable/time-exceeded received
    rtt_ms                   REAL NOT NULL DEFAULT 0,      -- mean responder handshake RTT (ms)
    malicious_flag           INTEGER NOT NULL DEFAULT 0,
    attack_types             TEXT,
    detector_flag            INTEGER NOT NULL DEFAULT 0,   -- flagged by the AI detector
    detector_types           TEXT,
    detector_confidence      REAL NOT NULL DEFAULT 0,
    detector_role            TEXT                          -- victim / attacker / infrastructure
);

CREATE TABLE IF NOT EXISTS detector_regions (
    region_id   INTEGER PRIMARY KEY,
    attack_type TEXT,
    known_name  TEXT,
    category    TEXT,
    confidence  REAL,
    responder   TEXT,
    port        INTEGER,
    t_min       REAL,
    t_max       REAL,
    n_ips       INTEGER,
    n_pairs     INTEGER,
    reason      TEXT,
    evidence    TEXT,
    roles_json  TEXT,
    explain     TEXT,
    ips_json    TEXT                          -- full region IP set (sources + responder)
);

CREATE TABLE IF NOT EXISTS detector_pairs (
    region_id   INTEGER,
    initiator   TEXT,
    responder   TEXT,
    count       INTEGER,
    close_type  TEXT,
    dst_port    INTEGER
);

-- Per-host-pair close_type distribution, rolled up from the archived per-flow
-- parquet shards (see pipeline/close_types.py). Pair is unordered (ip_a < ip_b
-- lexicographically) since a TCP close type is a property of the connection,
-- not its direction; export_json attaches the same distribution to both
-- directional edges between the pair.
CREATE TABLE IF NOT EXISTS pair_close_types (
    ip_a        TEXT NOT NULL,
    ip_b        TEXT NOT NULL,
    close_type  TEXT NOT NULL,
    n           INTEGER NOT NULL,
    PRIMARY KEY (ip_a, ip_b, close_type)
);

-- Same rollup as pair_close_types, but derived at parse time from the captures'
-- own TCP flags (parse_flows.classify_close) instead of the archived parquet
-- shards. Kept separate because close_types.build_pair_close_types wipes and
-- rewrites pair_close_types from the shards on every run, which would destroy
-- anything the parser wrote there. export_json sums the two.
CREATE TABLE IF NOT EXISTS pair_close_types_parsed (
    ip_a        TEXT NOT NULL,
    ip_b        TEXT NOT NULL,
    close_type  TEXT NOT NULL,
    n           INTEGER NOT NULL,
    PRIMARY KEY (ip_a, ip_b, close_type)
);

-- Resume guard for `run.py --close-types-only`. Separate from `ingested` because
-- that mode deliberately re-reads captures already parsed into `flows`: it must
-- skip files whose close types it has redone, not files that have been ingested.
CREATE TABLE IF NOT EXISTS close_types_done (
    name  TEXT PRIMARY KEY,
    n     INTEGER NOT NULL,
    ts    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ingested (
    name     TEXT PRIMARY KEY,   -- capture file name already parsed into `flows`
    n_flows  INTEGER NOT NULL,
    ts       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS gt_events (
    c2s_id     REAL,
    event_type TEXT,
    src        TEXT,
    src_ports  TEXT,
    dst        TEXT,
    dst_ports  TEXT,
    start_utc  REAL,
    stop_utc   REAL
);

CREATE INDEX IF NOT EXISTS idx_flows_src   ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst   ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_time  ON flows(first_ts, last_ts);
CREATE INDEX IF NOT EXISTS idx_hbuckets_ip ON host_buckets(ip);
CREATE INDEX IF NOT EXISTS idx_edges_src   ON edges(src_ip);
CREATE INDEX IF NOT EXISTS idx_edges_dst   ON edges(dst_ip);
CREATE INDEX IF NOT EXISTS idx_gt_src      ON gt_events(src);
CREATE INDEX IF NOT EXISTS idx_gt_dst      ON gt_events(dst);
CREATE INDEX IF NOT EXISTS idx_dpairs      ON detector_pairs(initiator, responder);
CREATE INDEX IF NOT EXISTS idx_pct_pair    ON pair_close_types(ip_a, ip_b);
CREATE INDEX IF NOT EXISTS idx_pctp_pair   ON pair_close_types_parsed(ip_a, ip_b);
"""

# Columns added after the first release; applied to pre-existing databases so a
# rebuild is not required. (CREATE TABLE above already includes them for new DBs.)
_MIGRATIONS = {
    "edges": [("detector_flag", "INTEGER NOT NULL DEFAULT 0"), ("detector_types", "TEXT"),
              ("syn", "INTEGER NOT NULL DEFAULT 0"), ("synack", "INTEGER NOT NULL DEFAULT 0"),
              ("rst", "INTEGER NOT NULL DEFAULT 0"), ("rst_rate", "REAL NOT NULL DEFAULT 0")],
    "hosts": [("detector_flag", "INTEGER NOT NULL DEFAULT 0"), ("detector_types", "TEXT"),
              ("detector_confidence", "REAL NOT NULL DEFAULT 0"), ("detector_role", "TEXT"),
              ("syn_in", "INTEGER NOT NULL DEFAULT 0"),
              ("completion_ratio", "REAL NOT NULL DEFAULT 1"),
              ("rst_rate", "REAL NOT NULL DEFAULT 0"),
              ("peak_conn_rate", "INTEGER NOT NULL DEFAULT 0"),
              ("anomaly_score", "REAL NOT NULL DEFAULT 0"),
              ("anomaly_top", "TEXT"),
              ("anomaly_breadth", "INTEGER NOT NULL DEFAULT 0"),
              ("anomaly_components", "TEXT"),
              ("retrans", "INTEGER NOT NULL DEFAULT 0"),
              ("icmp_errors", "INTEGER NOT NULL DEFAULT 0"),
              ("rtt_ms", "REAL NOT NULL DEFAULT 0")],
    "flows": [("first_syn_ts", "REAL NOT NULL DEFAULT 0"),
              ("first_synack_ts", "REAL NOT NULL DEFAULT 0"),
              ("retrans", "INTEGER NOT NULL DEFAULT 0"),
              ("icmp_type", "INTEGER NOT NULL DEFAULT -1"),
              ("icmp_code", "INTEGER NOT NULL DEFAULT -1")],
    "detector_regions": [("ips_json", "TEXT")],
    "host_buckets": [("fanout", "INTEGER"), ("ports_contacted", "INTEGER"),
                     ("peers", "INTEGER"), ("syn_no_synack", "INTEGER"),
                     ("peak_conn_rate", "INTEGER"), ("icmp_errors", "INTEGER"),
                     ("rtt_ms", "REAL")],
}


def migrate(conn: sqlite3.Connection) -> None:
    """Add any detector columns missing from an older database."""
    for table, cols in _MIGRATIONS.items():
        existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.commit()


def connect(db_path: str | Path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    # Pragmas tuned for bulk insert of a one-shot analytical DB.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    migrate(conn)
    conn.commit()


def reset_tables(conn: sqlite3.Connection, tables: list[str]) -> None:
    """Drop rows so a re-run is idempotent (schema preserved)."""
    for t in tables:
        conn.execute(f"DELETE FROM {t}")
    conn.commit()

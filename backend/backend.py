
# ============================================================
# NETWORK TRAFFIC EXPLORER - BACKEND STARTUP INSTRUCTIONS
# ============================================================
#
# REQUIREMENTS:
# - Python 3.14 or compatible version
# - FastAPI
# - Uvicorn
# - Ollama 3.2
#
# STEP 1: Open CMD (Command Prompt)
#
# STEP 2: Navigate to the backend directory:
# download backend folder and move to network-traffic-pipeline folder, so you have C:\network-traffic-pipeline\backend
#
# STEP 3: Install required dependencies (if not installed):
#    # python -m pip install fastapi uvicorn requests
   #
   # STEP 3b: Install Ollama (ollama.com), then run once: ollama pull llama3.2
#
# STEP 4: Start the FastAPI server:
# python -m uvicorn backend:app --reload
#
# STEP 5: Open the interactive API documentation:
# http://127.0.0.1:8000/docs
#
# STEP 6: Alternative API specification:
# http://127.0.0.1:8000/openapi.json
#
# STEP 7: Check database connection:
# http://127.0.0.1:8000/health
#
# STEP 8: Stop the server:
# Press CTRL + C in CMD.
#
# ============================================================
# AVAILABLE API ENDPOINTS
# ============================================================
#
# GET  /health       - Check backend and database connection
# GET  /hosts/top    - Retrieve highest-fanout hosts
# POST /host         - Retrieve information about a specific IP
# POST /sql
# POST /ask
# GET /regions
# POST /hosts/filter
# GET /timeline/{ip}
# POST /graph
# ============================================================
# IMPORTANT NOTES
# ============================================================
#
# - Keep the CMD window open while the server is running.
# - The database must exist in the project's data folder.
# - The default database path is:
#   network-traffic-pipeline/data/network.db
# - The --reload flag automatically restarts the server
#   when backend source code changes.
#
# ============================================================

import sqlite3
import ipaddress
import os
from pathlib import Path
import json, re, sys, time
from typing import Literal
import requests

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from fastapi.middleware.cors import CORSMiddleware



# DATABASE CONFIGURATION
ROOT = Path(__file__).resolve().parent.parent

DB_PATH = Path(
    os.getenv("NETWORK_DB_PATH", str(ROOT / "data" / "network.db"))
)
sys.path.insert(0, str(ROOT / "pipeline"))
import config  # noqa: F401  (loads .env)
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MAX_ROWS = 200


# FASTAPI APPLICATION
app = FastAPI(
    title="Network Traffic Explorer API",
    description="Backend API for network traffic analysis",
    version="1.0.0"
)
from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/docs")

# ALLOW FRONTEND CONNECTIONS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# DATABASE CONNECTION
def get_connection():
    if not DB_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Network database not found."
        )

    try:
        conn = sqlite3.connect(
            DB_PATH.as_uri() + "?mode=ro",
            uri=True
        )
        conn.row_factory = sqlite3.Row
        return conn

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to connect to database."
        )


# REQUEST VALIDATION
class HostRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Invalid IP address")

        return value


# HEALTH CHECK
@app.get("/health")
def health():
    conn = get_connection()

    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM flows"
        ).fetchone()[0]

        return {
            "status": "ok",
            "flows": count
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Database query failed."
        )

    finally:
        conn.close()


# GET TOP HOSTS
@app.get("/hosts/top")
def top_hosts(
    limit: int = Query(default=20, ge=1, le=200)
):
    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT ip, fanout, syn_no_synack
            FROM hosts
            ORDER BY fanout DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

        return {
            "hosts": [dict(row) for row in rows]
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve hosts."
        )

    finally:
        conn.close()


# GET INDIVIDUAL HOST
@app.post("/host")
def get_host(request: HostRequest):
    conn = get_connection()

    try:
        row = conn.execute(
            """
            SELECT ip, fanout, syn_no_synack
            FROM hosts
            WHERE ip = ?
            """,
            (request.ip,)
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Host not found."
            )

        return {
            "host": dict(row)
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve host."
        )

    finally:
        conn.close()


BLOCKED_TABLES = {"gt_events"}
BLOCKED_COLUMNS = {
    ("flows", "label"), ("flows", "attack_type"),
    ("edges", "malicious"), ("edges", "attack_types"),
    ("hosts", "malicious_flag"), ("hosts", "attack_types"),
}


def _authorizer(action, arg1, arg2, dbname, source):
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        if arg1 in BLOCKED_TABLES or (arg1, arg2) in BLOCKED_COLUMNS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY  # no writes, no PRAGMA, nothing else


def run_select(sql: str, params=(), max_rows: int = MAX_ROWS):
    s = sql.strip().rstrip(";").strip()
    if ";" in s or not re.match(r"(?is)(select|with)\b", s):
        raise ValueError("one SELECT statement only")
    deadline = time.time() + 5
    conn = get_connection()
    try:
        conn.set_authorizer(_authorizer)
        conn.set_progress_handler(lambda: time.time() > deadline, 10000)
        cur = conn.execute(s, params)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchmany(max_rows)
    finally:
        conn.close()
    return {"columns": cols, "rows": [list(r) for r in rows],
            "truncated": len(rows) == max_rows}


def check_ip(v: str) -> str:
    ipaddress.ip_address(v)  # raises ValueError if not an IP
    return v


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hosts: list[str] = Field(default_factory=list, max_length=200)
    time_start: float | None = None
    time_end: float | None = None

    @field_validator("hosts")
    @classmethod
    def _ips(cls, v):
        return [check_ip(i) for i in v]

    @model_validator(mode="after")
    def _times(self):
        if (self.time_start is not None and self.time_end is not None
                and self.time_start >= self.time_end):
            raise ValueError("time_start must be before time_end")
        return self


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)
    scope: Scope = Field(default_factory=Scope)


class SqlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sql: str = Field(min_length=1, max_length=4000)


# ---- the AI model ----
SYSTEM = (
    "You are a network-traffic analyst. Judge only from traffic behaviour. "
    "To read data, call the run_sql tool with ONE SQLite SELECT. "
    "Use ONLY these tables and columns:\n"
    "hosts(ip, is_internal, pkts_in, pkts_out, bytes_in, bytes_out, distinct_peers, "
    "distinct_ports_contacted, fanout, syn_no_synack, syn_in, completion_ratio, "
    "rst_rate, peak_conn_rate, anomaly_score, anomaly_top, retrans, icmp_errors, rtt_ms)\n"
    "edges(src_ip, dst_ip, proto, pkts, bytes, flow_count, distinct_dst_ports, "
    "first_ts, last_ts, syn, synack, rst, rst_rate)\n"
    "host_buckets(ip, bucket, pkts_in, pkts_out, bytes_in, bytes_out, syn_in, "
    "synack_out, rst, retrans, fanout, ports_contacted, peers, syn_no_synack, "
    "peak_conn_rate, icmp_errors, rtt_ms)\n"
    "flows(src_ip, dst_ip, src_port, dst_port, proto, first_ts, last_ts, pkts, bytes, "
    "syn, synack, fin, rst, retrans, icmp_type, icmp_code)\n"
    "Times are unix seconds. Text values use single quotes, for example ip = '1.2.3.4'. "
    "Never use SELECT *. Never invent columns. flows is huge: always filter it by "
    "src_ip or dst_ip and add LIMIT 50. Prefer hosts, edges and host_buckets. "
    "After you have data, answer in 2 to 4 sentences using only that data. "
    "Use select_nodes, spotlight_hosts and focus_time to draw your findings on the "
    "user's display. Focus on the user's scope below. If the evidence is thin, say so."
)

IPS = {"type": "array", "items": {"type": "string"}, "maxItems": 200}
TOOLS = [
    {"name": "run_sql",
     "description": "Read-only SELECT on tables flows, edges, hosts, host_buckets. Max 200 rows.",
     "input_schema": {"type": "object", "properties": {"sql": {"type": "string"}},
                      "required": ["sql"]}},
    {"name": "select_nodes", "description": "Select these hosts on the plot.",
     "input_schema": {"type": "object", "properties": {"ips": IPS}, "required": ["ips"]}},
    {"name": "spotlight_hosts", "description": "Spotlight these hosts on the plot.",
     "input_schema": {"type": "object", "properties": {"ips": IPS}, "required": ["ips"]}},
    {"name": "focus_time", "description": "Focus the time view on a window (unix seconds).",
     "input_schema": {"type": "object",
                      "properties": {"start": {"type": "number"}, "end": {"type": "number"}},
                      "required": ["start", "end"]}},
]

TOOLS.append({
    "name": "host_summary",
    "description": "Get the behaviour signals and the top 10 targets of ONE host. Use this first for any question about one host.",
    "input_schema": {"type": "object",
                     "properties": {"ip": {"type": "string"}},
                     "required": ["ip"]},
})

def handle_tool(name, args, display):
    result = _handle_tool(name, args, display)
    print("TOOL:", name, args, "->", str(result)[:300], flush=True)
    return result


def _handle_tool(name, args, display):
    try:
        if name == "run_sql":
            return json.dumps(run_select(args["sql"]))
        if name == "host_summary":
            ip = check_ip(args["ip"])
            h = run_select(
                "SELECT ip, is_internal, pkts_in, pkts_out, bytes_in, bytes_out, "
                "distinct_peers, fanout, syn_no_synack, syn_in, completion_ratio, "
                "rst_rate, peak_conn_rate, anomaly_score, anomaly_top, retrans, rtt_ms "
                "FROM hosts WHERE ip = ?", (ip,))
            t = run_select(
                "SELECT dst_ip, pkts, bytes, flow_count, rst_rate FROM edges "
                "WHERE src_ip = ? ORDER BY flow_count DESC LIMIT 10", (ip,))
            return json.dumps({"host": h, "top_targets": t})
        if name in ("select_nodes", "spotlight_hosts"):
            ips = [check_ip(i) for i in args["ips"]][:200]
            display.append({"action": name, "ips": ips})
            return "ok"
        if name == "focus_time":
            start, end = float(args["start"]), float(args["end"])
            if start >= end:
                raise ValueError("start must be before end")
            display.append({"action": "focus_time", "start": start, "end": end})
            return "ok"
        return "error: unknown tool"
    except Exception as e:  # tell the model what went wrong so it can retry
        return (f"error: {e}. Write one complete SELECT with quoted values, "
                "for example WHERE ip = '172.28.4.7'. Or call host_summary.")


def _text_tool_call(content: str):
    """Small models sometimes write the tool call as JSON text. Detect that."""
    m = re.search(r"\{.*\}", content or "", re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    name = d.get("name")
    args = d.get("parameters") or d.get("arguments") or {}
    if name in {t["name"] for t in TOOLS} and isinstance(args, dict):
        return name, args
    return None


def ask_model(question: str, scope: Scope):
    display: list[dict] = []
    tools = [{"type": "function",
              "function": {"name": t["name"], "description": t["description"],
                           "parameters": t["input_schema"]}} for t in TOOLS]

    if scope.hosts:
        scope_text = "Selected hosts: " + ", ".join(scope.hosts) + "."
    else:
        scope_text = "No hosts are selected."
    if scope.time_start is not None and scope.time_end is not None:
        scope_text += (f" Selected time window (unix seconds): "
                       f"{scope.time_start} to {scope.time_end}.")

    # Selected hosts: the backend fetches the facts itself and the model only summarizes.
    facts = ""
    for ip in scope.hosts[:3]:
        facts += f"\nDatabase facts for {ip}: "
        facts += _handle_tool("host_summary", {"ip": ip}, display)[:3000]

    if facts:
        user_text = (f"{question}\n\n{scope_text}\n{facts}\n\n"
                     "Answer in 2 to 4 sentences using only the database facts above. "
                     "Quote the numbers exactly. Do not write SQL.")
        r = requests.post(f"{OLLAMA_URL}/api/chat",
                          json={"model": MODEL,
                                "messages": [
                                    {"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": user_text}],
                                "stream": False, "options": {"temperature": 0}},
                          timeout=300)
        r.raise_for_status()
        content = r.json()["message"].get("content", "")
        print("MODEL:", content[:300], flush=True)
        display.append({"action": "spotlight_hosts", "ips": scope.hosts[:3]})
        if scope.time_start is not None and scope.time_end is not None:
            display.append({"action": "focus_time",
                            "start": scope.time_start, "end": scope.time_end})
        return content, display

    # No selection: the model may call tools.
    user_text = (f"{question}\n\n{scope_text}\n"
                 "Call run_sql with one complete SELECT and quoted values, "
                 "for example WHERE ip = '1.2.3.4'. Do not use host_buckets for totals.")
    messages = [
        {"role": "system", "content": SYSTEM + "\nScope: " + json.dumps(scope.model_dump())},
        {"role": "user", "content": user_text},
    ]
    seen: dict[str, int] = {}

    def repeated(name, args):
        key = name + json.dumps(args, sort_keys=True, default=str)
        seen[key] = seen.get(key, 0) + 1
        return seen[key] > 2

    giveup = "The local model kept repeating the same failing tool call. Try a simpler question."

    for _ in range(8):
        r = requests.post(f"{OLLAMA_URL}/api/chat",
                          json={"model": MODEL, "messages": messages, "tools": tools,
                                "stream": False, "options": {"temperature": 0}},
                          timeout=300)
        r.raise_for_status()
        msg = r.json()["message"]
        print("MODEL:", str(msg.get("content", ""))[:300], msg.get("tool_calls"), flush=True)
        calls = msg.get("tool_calls") or []
        if not calls:
            text_call = _text_tool_call(msg.get("content", ""))
            if text_call is None:
                return msg.get("content", ""), display
            name, args = text_call
            if repeated(name, args):
                return giveup, display
            result = handle_tool(name, args, display)
            messages.append({"role": "assistant", "content": msg.get("content", "")})
            messages.append({"role": "user",
                             "content": f"Result of {name}: {result}\n"
                                        "Now answer the question in 2 to 4 sentences, "
                                        "or make one more tool call."})
            continue
        messages.append(msg)
        for c in calls:
            name = c["function"]["name"]
            args = c["function"]["arguments"]
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            if repeated(name, args):
                return giveup, display
            messages.append({"role": "tool", "tool_name": name,
                             "content": handle_tool(name, args, display)})
    return "Stopped: too many tool steps. Try a narrower question.", display

@app.post("/sql")
def sql(req: SqlRequest):
    try:
        return run_select(req.sql)
    except (ValueError, sqlite3.Error) as e:
        raise HTTPException(400, str(e))


@app.post("/ask")
def ask(req: AskRequest):
    try:
        answer, display = ask_model(req.question, req.scope)
    except requests.exceptions.ConnectionError:
        raise HTTPException(503, "Ollama is not running. Start it and try again.")
    except requests.exceptions.RequestException as e:
        raise HTTPException(502, f"AI model error: {type(e).__name__}")
    return {"answer": answer, "display": display}


# ---- detector regions (time bands for the visualization) ----
@app.get("/regions")
def regions():
    return run_select(
        "SELECT region_id, attack_type, known_name, category, confidence, "
        "responder, port, t_min, t_max, n_ips, n_pairs "
        "FROM detector_regions ORDER BY t_min")


# ---- slider filter: every threshold must pass (AND) ----
SIGNALS = Literal["fanout", "distinct_peers", "distinct_ports_contacted",
                  "syn_no_synack", "syn_in", "peak_conn_rate", "rst_rate",
                  "retrans", "icmp_errors", "rtt_ms", "anomaly_score"]


class SignalFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signal: SIGNALS
    min: float


class FilterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filters: list[SignalFilter] = Field(min_length=1, max_length=12)
    limit: int = Field(default=100, ge=1, le=200)


@app.post("/hosts/filter")
def filter_hosts(req: FilterRequest):
    cols = sorted({f.signal for f in req.filters} | {"anomaly_score"})
    where = " AND ".join(f"{f.signal} >= ?" for f in req.filters)
    return run_select(
        f"SELECT ip, {', '.join(cols)} FROM hosts WHERE {where} "
        "ORDER BY anomaly_score DESC LIMIT ?",
        tuple(f.min for f in req.filters) + (req.limit,))


# ---- one host's traffic over time ----
@app.get("/timeline/{ip}")
def timeline(ip: str, start: float = 0, end: float = 4e9):
    try:
        check_ip(ip)
    except ValueError:
        raise HTTPException(422, "Invalid IP address")
    return run_select(
        "SELECT bucket, pkts_in, pkts_out, bytes_in, bytes_out, syn_in, rst, "
        "fanout, peak_conn_rate FROM host_buckets "
        "WHERE ip = ? AND bucket >= ? AND bucket <= ? ORDER BY bucket",
        (ip, start, end), max_rows=1000)


# ---- edges among the selected hosts (for the graph views) ----
@app.post("/graph")
def graph(scope: Scope):
    if not scope.hosts:
        raise HTTPException(422, "select at least one host")
    ph = ",".join("?" * len(scope.hosts))
    t0 = scope.time_start if scope.time_start is not None else 0
    t1 = scope.time_end if scope.time_end is not None else 4e9
    return run_select(
        "SELECT src_ip, dst_ip, proto, pkts, bytes, flow_count, rst_rate, "
        f"detector_flag FROM edges WHERE src_ip IN ({ph}) AND dst_ip IN ({ph}) "
        "AND last_ts >= ? AND first_ts <= ? ORDER BY flow_count DESC",
        tuple(scope.hosts) * 2 + (t0, t1), max_rows=2000)

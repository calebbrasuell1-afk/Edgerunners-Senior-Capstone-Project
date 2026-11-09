"""Streamlit UI for browsing a SQLite database and calling backend.py."""

#cd to the directory containing this file and run:

# pip install streamlit fastapi uvicorn requests

# streamlit run UI_0.1.py



import atexit
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st

from traffic_graph import show_traffic_graph
from graphs import show_graphs

st.set_page_config(page_title="Application Dashboard", layout="wide")
st.title("Application Dashboard")


ROOT = Path(__file__).resolve().parent.parent

database_path = os.getenv("NETWORK_DB_PATH", str(ROOT / "data" / "network.db"))
Backend_path = Path(os.getenv("BACKEND_PATH", str(ROOT / "backend" / "backend.py")))
API_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

http = requests.Session()
http.trust_env = False  # ignore HTTP_PROXY / HTTPS_PROXY


def backend_is_up():
    """True if anything answers on the backend URL (even with an error status)."""
    try:
        http.get(f"{API_URL}/health", timeout=1)
        return True
    except requests.exceptions.RequestException:
        return False


@st.cache_resource
def start_backend():
    """Start uvicorn once per Streamlit server process.

    Returns (process_or_None, log_path, message).
    """
    log_path = Backend_path.parent / "backend.log"

    if backend_is_up():
        return None, log_path, "Backend was already running."

    parsed = urlparse(API_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    if host not in ("127.0.0.1", "localhost"):
        return None, log_path, f"BACKEND_URL points to {host}; not starting a local backend."
    if not Backend_path.is_file():
        return None, log_path, f"backend.py not found at {Backend_path}"

    log_file = open(log_path, "w")
    process = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", f"{Backend_path.stem}:app",
            "--host", host, "--port", str(port),
        ],
        cwd=str(Backend_path.parent),
        env={**os.environ, "NETWORK_DB_PATH": database_path},
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    atexit.register(process.terminate)

    # Wait up to ~20 s for the server to come up (or crash).
    for _ in range(40):
        if process.poll() is not None:
            return process, log_path, "Backend exited during startup."
        if backend_is_up():
            return process, log_path, "Backend started."
        time.sleep(0.5)
    return process, log_path, "Backend is taking too long to start."


with st.spinner("Starting backend..."):
    backend_proc, backend_log, backend_msg = start_backend()


with st.sidebar:
    st.header("Connections")
    st.caption(f"SQLite database: `{database_path}`")
    try:
        r = http.get(f"{API_URL}/health", timeout=5)
        if r.ok:
            st.success(f"Backend OK ({r.json()['flows']} flows)")
        else:
            st.warning(f"Backend is up but unhealthy: {r.status_code} {r.json().get('detail', r.text)}")
    except Exception as e:
        st.warning(f"Backend not reachable: {backend_msg}")
        if backend_log.is_file():
            with st.expander("Backend log"):
                st.code(backend_log.read_text(errors="replace")[-3000:] or "(empty)")


database_tab, backend_tab, graphs_tab = st.tabs(["Database", "Backend", "Graphs"])

with database_tab:
    st.subheader("Browse database")
    db_path = Path(database_path)
    if not db_path.is_file():
        st.info("Database file not found. Set NETWORK_DB_PATH to the SQLite file location.")
    else:
        try:
            with sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True) as connection:
                tables = pd.read_sql_query(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name",
                    connection,
                )["name"].tolist()
                if not tables:
                    st.info("No tables were found in this database.")
                else:
                    table = st.selectbox("Table", tables)
                    safe_table = '"' + table.replace('"', '""') + '"'
                    rows = pd.read_sql_query(f"SELECT * FROM {safe_table} LIMIT 500", connection)
                    st.dataframe(rows, use_container_width=True, hide_index=True)
                    st.caption("Showing at most 500 rows.")
                    show_traffic_graph(connection)

        except Exception as error:
            st.error(f"Unable to read database: {error}")

with backend_tab:
    st.subheader("Ask the backend")
    question = st.text_area("Question", placeholder="Which hosts look like scanners?")
    hosts_text = st.text_input("Hosts in scope (optional, comma-separated IPs)")

    if st.button("Send request", type="primary", disabled=not question.strip()):
        hosts = [h.strip() for h in hosts_text.split(",") if h.strip()]
        payload = {"question": question.strip(), "scope": {"hosts": hosts}}
        try:
            with st.spinner("Processing..."):
                r = http.post(f"{API_URL}/ask", json=payload, timeout=300)
            if r.ok:
                data = r.json()
                st.write(data["answer"])
                if data["display"]:
                    with st.expander("Display instructions"):
                        st.json(data["display"])
            else:
                st.error(f"{r.status_code}: {r.json().get('detail', r.text)}")
        except requests.exceptions.ConnectionError:
            st.error("Can't reach the backend. Check the Backend log in the sidebar.")
with graphs_tab:
    show_graphs(database_path)

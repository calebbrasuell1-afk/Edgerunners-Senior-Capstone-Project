"""Streamlit UI for browsing a SQLite database and calling backend.py."""

#cd to the directory containing this file and run:

# pip install streamlit

# streamlit run UI_0.1.py

import importlib
import os
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

from traffic_graph import show_traffic_graph

st.set_page_config(page_title="Application Dashboard", layout="wide")
st.title("Application Dashboard")


ROOT = Path(__file__).resolve().parent.parent

database_path = os.getenv("NETWORK_DB_PATH", str(ROOT / "data" / "network.db"))

Backend_path = os.getenv("BACKEND_PATH", str(ROOT / "backend" /"backend.py"))

def load_backend_module(backend_path):
	spec = importlib.util.spec_from_file_location("backend", backend_path)
	backend_module = importlib.util.module_from_spec(spec)
	sys.modules["backend"] = backend_module
	spec.loader.exec_module(backend_module)
	return backend_module

@st.cache_resource
def get_backend():
	try:
		return load_backend_module(Backend_path)
	except Exception as error:
		return error


backend = get_backend()

with st.sidebar:
	st.header("Connections")
	st.caption(f"SQLite database: `{database_path}`")
	if isinstance(backend, Exception):
		st.warning(f"backend.py could not be loaded: {backend}")
	else:
		st.success("backend.py loaded")

database_tab, backend_tab = st.tabs(["Database", "Backend"])

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
	st.subheader("Send a request to the backend")
	message = st.text_area("Request", placeholder="Enter a message...")
	if st.button("Send request", type="primary", disabled=not message.strip()):
		if isinstance(backend, Exception):
			st.error("Place backend.py beside this UI file and install its dependencies.")
		else:
			handler = next(
				(
					getattr(backend, name)
					for name in ("process_request", "handle_request", "process", "run")
					if callable(getattr(backend, name, None))
				),
				None,
			)
			if handler is None:
				st.error(
					"backend.py must provide process_request(message), "
					"handle_request(message), process(message), or run(message)."
				)
			else:
				try:
					with st.spinner("Processing..."):
						response = handler(message.strip())
					st.write("Response")
					if isinstance(response, (dict, list)):
						st.json(response)
					else:
						st.write(response)
				except Exception as error:
					st.error(f"Backend request failed: {error}")

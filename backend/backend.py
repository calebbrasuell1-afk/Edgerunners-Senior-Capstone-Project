
# ============================================================
# NETWORK TRAFFIC EXPLORER - BACKEND STARTUP INSTRUCTIONS
# ============================================================
#
# REQUIREMENTS:
# - Python 3.14 or compatible version
# - FastAPI
# - Uvicorn
#
# STEP 1: Open CMD (Command Prompt)
#
# STEP 2: Navigate to the backend directory:
# download backend folder and move to network-traffic-pipeline folder, so you have C:\network-traffic-pipeline\backend
#
# STEP 3: Install required dependencies (if not installed):
# python -m pip install fastapi uvicorn
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
#
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

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, field_validator
from fastapi.middleware.cors import CORSMiddleware


# DATABASE CONFIGURATION
ROOT = Path(__file__).resolve().parent.parent

DB_PATH = Path(
    os.getenv("NETWORK_DB_PATH", str(ROOT / "data" / "network.db"))
)


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

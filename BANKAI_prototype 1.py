#!/usr/bin/env python3
"""BANKAI / VPNGuard — pure Python + pandas + SQLite + HTML prototype.

External dependencies: pandas + scikit-learn.
SQLite, HTTP server, GUI, JSON and networking use Python standard library.
Python standard library handles the HTTP server, SQLite, GUI, JSON, networking
and CSV upload. HTML/CSS/JavaScript are embedded in this single file.

Run:
    python BANKAI_prototype.py

The program is a controlled local lab prototype. The attacker page only sends
requests to the local/private target configured by the app; it does not accept
arbitrary public targets.
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import socket
import sqlite3
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
import tkinter as tk
from tkinter import ttk, messagebox

import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None

APP_NAME = "BANKAI — VPNGuard"
HOST = "127.0.0.1"
PORT = 8000
RUNTIME = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".bankai"))) / "BANKAI_PURE_FINAL"
DB_PATH = RUNTIME / "bankai.db"
RUNTIME.mkdir(parents=True, exist_ok=True)
DASHBOARD_TOKEN = "BANKAI-DASHBOARD-2026"

VALID_USERS = {
    "alice@company.local": "Alice123!",
    "bob@company.local": "Bob123!",
    "charlie@company.local": "Charlie123!",
    "david@company.local": "David123!",
    "eve@company.local": "Eve123!",
    "frank@company.local": "Frank123!",
    "grace@company.local": "Grace123!",
    "heidi@company.local": "Heidi123!",
    "ivan@company.local": "Ivan123!",
    "judy@company.local": "Judy123!",
}

DEMO_GEO = {
    "10.0.0.24": (28.6139, 77.2090, "Delhi", "India"),
    "10.0.0.42": (38.9072, -77.0369, "Ashburn", "USA"),
    "10.0.0.81": (55.7558, 37.6176, "Moscow", "Russia"),
    "10.0.0.90": (50.1109, 8.6821, "Frankfurt", "Germany"),
    "10.8.0.5": (52.5200, 13.4050, "Berlin VPN", "Germany"),
    "127.0.0.1": (28.6139, 77.2090, "Local Lab", "India"),
}


DB_LOCK = threading.Lock()
SERVER: ThreadingHTTPServer | None = None
IF_MODEL = None
IF_MODEL_LOCK = threading.Lock()
TRAINED_MODEL_PATH = RUNTIME / "isolation_forest.pkl"
DATASET_MODEL_PATH = RUNTIME / "dataset_isolation_forest.pkl"
SESSION_TOKEN = ""

ATTACK_MITRE = {
    "brute_force": "T1110.001",
    "password_spraying": "T1110.003",
    "vpn_spray": "T1110.003",
    "impossible_travel": "T1078",
    "ml_anomaly": "T1110",
}

ROLE_PORTS={"observer":8000,"gateway":8100,"target":8200,"attacker":8300}
CONFIG_PATH=RUNTIME/"control_center.json"
SERVERS={}
SERVER_THREADS={}
TARGET_LOG_LOCK=threading.Lock()
TARGET_LOG=[]
GATEWAY_LOG_LOCK=threading.Lock()
GATEWAY_LOG=[]
DEFAULT_CONFIG={"mode":"Single Laptop — All-in-One","bind_host":"127.0.0.1","sentinel_ip":"127.0.0.1","auth_gateway_ip":"127.0.0.1","client_ip":"127.0.0.1","dashboard_token":DASHBOARD_TOKEN}
try:
    CONFIG=json.loads(CONFIG_PATH.read_text(encoding="utf-8")) if CONFIG_PATH.exists() else dict(DEFAULT_CONFIG)
except Exception:
    CONFIG=dict(DEFAULT_CONFIG)
for _k,_v in DEFAULT_CONFIG.items(): CONFIG.setdefault(_k,_v)

def save_config(cfg):
    global CONFIG
    CONFIG=dict(DEFAULT_CONFIG); CONFIG.update(cfg)
    CONFIG_PATH.write_text(json.dumps(CONFIG,indent=2),encoding="utf-8")

def service_url(service,path=""):
    host={"observer":CONFIG["sentinel_ip"],"gateway":CONFIG["auth_gateway_ip"],"target":CONFIG["auth_gateway_ip"],"attacker":CONFIG["client_ip"]}[service]
    return f"http://{host}:{ROLE_PORTS[service]}{path}"

def is_private_lab_host(host):
    return host in {"localhost","127.0.0.1","0.0.0.0"} or host.startswith(("10.","192.168.","172.16.","172.17.","172.18.","172.19.","172.2","172.3","198.51.100.","203.0.113."))

def protective_status():
    cutoff=datetime.fromtimestamp(time.time()-300,tz=timezone.utc).isoformat()
    with DB_LOCK, db() as c:
        critical=int(c.execute("SELECT COUNT(*) FROM alerts WHERE created_at>=? AND severity='CRITICAL'",(cutoff,)).fetchone()[0])
        alerts=int(c.execute("SELECT COUNT(*) FROM alerts WHERE created_at>=?",(cutoff,)).fetchone()[0])
        incidents=int(c.execute("SELECT COUNT(*) FROM incidents WHERE created_at>=?",(cutoff,)).fetchone()[0])
        types=int(c.execute("SELECT COUNT(DISTINCT event_type) FROM alerts WHERE created_at>=?",(cutoff,)).fetchone()[0])
    risk=min(100.0,critical*18+alerts*6+incidents*8+types*5)
    return {"risk":round(risk,1),"shutdown_alert":risk>=75,"action":"TARGET SHUTDOWN ALERT — review/contain immediately" if risk>=75 else ("ELEVATED THREAT" if risk>=50 else "NORMAL"),"critical_alerts":critical,"recent_alerts":alerts,"recent_incidents":incidents}

def public_status():
    m=metrics(); p=protective_status()
    with DB_LOCK, db() as c:
        rows=c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 6").fetchall()
    return {"ok":True,"events":m["total_events"],"alerts":m["total_alerts"],"incidents":m["incidents"],"risk":p["risk"],"shutdown_alert":p["shutdown_alert"],"attack_distribution":m["alerts_by_type"],"latest_incidents":[_map_incident(r) for r in rows]}

def http_json(url,payload=None,headers=None,timeout=5):
    data=None; method="GET"; hdr=dict(headers or {})
    if payload is not None:
        data=json.dumps(payload).encode(); hdr["Content-Type"]="application/json"; method="POST"
    req=Request(url,data=data,headers=hdr,method=method)
    try:
        with urlopen(req,timeout=timeout) as r: return r.status,json.loads(r.read().decode() or "{}")
    except Exception as e:
        if hasattr(e,"code"):
            try: return int(e.code),json.loads(e.read().decode() or "{}")
            except Exception: return int(e.code),{}
        raise


def severity_for_risk(risk: float) -> tuple[str, str]:
    """Return a tier and display severity using the challenge's tiered model."""
    r = float(risk)
    if r >= 76:
        return "P1", "CRITICAL"
    if r >= 51:
        return "P2", "HIGH"
    if r >= 26:
        return "P3", "MEDIUM"
    return "P4", "LOW"


def _if_features_from_rows(rows):
    """Build behavioral, source-level features for Isolation Forest."""
    grouped = {}
    for row in rows:
        grouped.setdefault(row["source_ip"], []).append(row)
    features = []
    keys = []
    for ip, items in grouped.items():
        failures = sum(1 for r in items if int(r["status"]) == 401)
        users = len({r["username"] for r in items})
        total = len(items)
        fail_ratio = failures / total if total else 0.0
        velocity = total / max(1.0, 1.0)  # recent-events window, normalized to events/window
        geo_users = len({r["username"] for r in items if r["latitude"] is not None and r["longitude"] is not None})
        features.append([total, failures, users, fail_ratio, velocity, geo_users])
        keys.append(ip)
    return keys, features


def ensure_if_model():
    """Create a lightweight unsupervised baseline model for secondary anomaly corroboration."""
    global IF_MODEL
    if IsolationForest is None:
        return None
    with IF_MODEL_LOCK:
        if IF_MODEL is not None:
            return IF_MODEL
        if TRAINED_MODEL_PATH.exists():
            try:
                import pickle
                with TRAINED_MODEL_PATH.open("rb") as f:
                    IF_MODEL = pickle.load(f)
                    return IF_MODEL
            except Exception:
                IF_MODEL = None
        # Benign behavioral baseline. This is not a performance benchmark.
        baseline = [
            [1, 0, 1, 0.00, 1.0, 1],
            [2, 0, 1, 0.00, 2.0, 1],
            [3, 0, 1, 0.00, 3.0, 1],
            [4, 1, 1, 0.25, 4.0, 1],
            [5, 1, 2, 0.20, 5.0, 2],
            [6, 1, 2, 0.17, 6.0, 2],
            [4, 0, 2, 0.00, 4.0, 2],
            [7, 1, 2, 0.14, 7.0, 2],
            [3, 1, 2, 0.33, 3.0, 2],
            [8, 2, 3, 0.25, 8.0, 3],
        ]
        IF_MODEL = IsolationForest(n_estimators=100, contamination=0.10, random_state=42)
        IF_MODEL.fit(baseline)
        return IF_MODEL


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with DB_LOCK, db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                status INTEGER NOT NULL,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                source_type TEXT DEFAULT 'client',
                ground_truth TEXT DEFAULT 'NORMAL',
                target TEXT DEFAULT 'local-auth'
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                severity TEXT NOT NULL,
                risk REAL NOT NULL,
                mitre TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT DEFAULT 'NEW',
                false_positive_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                users INTEGER NOT NULL,
                severity TEXT NOT NULL,
                risk REAL NOT NULL,
                mitre TEXT NOT NULL,
                status TEXT DEFAULT 'NEW',
                evidence TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                rows INTEGER NOT NULL,
                precision REAL,
                recall REAL,
                f1 REAL,
                fpr REAL
            );
            """
        )
        # Lightweight migrations for databases created by older BANKAI builds.
        cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)").fetchall()}
        if "status" not in cols:
            c.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'NEW'")
        if "false_positive_reason" not in cols:
            c.execute("ALTER TABLE alerts ADD COLUMN false_positive_reason TEXT")
        cols = {row[1] for row in c.execute("PRAGMA table_info(incidents)").fetchall()}
        if "false_positive_reason" not in cols:
            c.execute("ALTER TABLE incidents ADD COLUMN false_positive_reason TEXT")
        c.commit()


def geo_for(ip: str):
    return DEMO_GEO.get(ip, (20.5937, 78.9629, "India", "India"))


def recent_events(seconds: int = 60) -> list[sqlite3.Row]:
    cutoff = time.time() - seconds
    iso_cutoff = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
    with DB_LOCK, db() as c:
        return c.execute("SELECT * FROM events WHERE ts >= ? ORDER BY id DESC", (iso_cutoff,)).fetchall()


def count_events() -> int:
    with DB_LOCK, db() as c:
        return int(c.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def insert_event(username: str, source_ip: str, status: int, source_type='client', ground_truth='NORMAL',
                 city=None, country=None, lat=None, lon=None, target='local-auth') -> dict:
    if city is None or country is None or lat is None or lon is None:
        lat, lon, city, country = geo_for(source_ip)
    ts = now_iso()
    with DB_LOCK, db() as c:
        cur = c.execute(
            "INSERT INTO events(ts,username,source_ip,status,country,city,latitude,longitude,source_type,ground_truth,target) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (ts, username, source_ip, status, country, city, lat, lon, source_type, ground_truth, target),
        )
        eid = cur.lastrowid
        c.commit()
    run_detection(source_ip)
    return {"id": eid, "ts": ts, "username": username, "source_ip": source_ip, "status": status}


def add_alert(event_type: str, source_ip: str, username: str | None, severity: str, risk: float, mitre: str, evidence: str) -> None:
    with DB_LOCK, db() as c:
        exists = c.execute(
            "SELECT 1 FROM alerts WHERE event_type=? AND source_ip=? AND created_at >= ? ORDER BY id DESC LIMIT 1",
            (event_type, source_ip, datetime.fromtimestamp(time.time() - 45, tz=timezone.utc).isoformat()),
        ).fetchone()
        if exists:
            return
        c.execute(
            "INSERT INTO alerts(created_at,event_type,source_ip,username,severity,risk,mitre,evidence) VALUES(?,?,?,?,?,?,?,?)",
            (now_iso(), event_type, source_ip, username, severity, risk, mitre, evidence),
        )
        c.commit()


def add_incident(event_type: str, source_ip: str, users: int, severity: str, risk: float, mitre: str, evidence: str) -> None:
    with DB_LOCK, db() as c:
        exists = c.execute(
            "SELECT 1 FROM incidents WHERE event_type=? AND source_ip=? AND created_at >= ? ORDER BY id DESC LIMIT 1",
            (event_type, source_ip, datetime.fromtimestamp(time.time() - 45, tz=timezone.utc).isoformat()),
        ).fetchone()
        if exists:
            return
        c.execute(
            "INSERT INTO incidents(created_at,event_type,source_ip,users,severity,risk,mitre,evidence) VALUES(?,?,?,?,?,?,?,?)",
            (now_iso(), event_type, source_ip, users, severity, risk, mitre, evidence),
        )
        c.commit()


def run_detection(source_ip: str | None = None) -> None:
    """Detect behavioral attack stories, not isolated events."""
    ev = recent_events(300)
    if not ev:
        return

    grouped = {}
    for r in ev:
        grouped.setdefault(r["source_ip"], []).append(r)

    flagged_ips = set()
    for ip, rows in grouped.items():
        if source_ip and ip != source_ip:
            continue
        failures = [r for r in rows if int(r["status"]) == 401]
        users = {r["username"] for r in failures}

        # Brute force: one source -> one/few target users -> repeated failures.
        per_user = {}
        for r in failures:
            per_user[r["username"]] = per_user.get(r["username"], 0) + 1
        biggest_user = max(per_user.items(), key=lambda x: x[1], default=(None, 0))
        if biggest_user[1] >= 5 and (len(users) <= 2):
            risk = min(99.0, 55.0 + biggest_user[1] * 4.0)
            tier, severity = severity_for_risk(risk)
            evd = f"{biggest_user[1]} failures against one account from {ip} in rolling window"
            add_alert("brute_force", ip, biggest_user[0], severity, risk, ATTACK_MITRE["brute_force"], f"{tier} {evd}")
            add_incident("brute_force", ip, 1, severity, risk, ATTACK_MITRE["brute_force"], f"{tier} {evd}")
            flagged_ips.add(ip)

        # Password/VPN spray: one source -> many distinct identities -> repeated failures.
        if len(users) >= 5 and len(failures) >= 5:
            is_vpn = any(r["source_type"] == "vpn" for r in failures) or ip == "10.8.0.5"
            typ = "vpn_spray" if is_vpn else "password_spraying"
            risk = min(99.0, 70.0 + len(users) * 2.0)
            tier, severity = severity_for_risk(risk)
            evd = f"{len(failures)} failures across {len(users)} users from {ip}"
            add_alert(typ, ip, None, severity, risk, ATTACK_MITRE[typ], f"{tier} {evd}")
            add_incident(typ, ip, len(users), severity, risk, ATTACK_MITRE[typ], f"{tier} {evd}")
            flagged_ips.add(ip)

    # Impossible travel: same user -> distant successful logins at impossible velocity.
    with DB_LOCK, db() as c:
        rows = c.execute("SELECT * FROM events WHERE status=200 ORDER BY id DESC LIMIT 300").fetchall()
    by_user = {}
    for r in rows:
        by_user.setdefault(r["username"], []).append(r)
    for username, items in by_user.items():
        for a, b in zip(items, items[1:]):
            try:
                ta = datetime.fromisoformat(a["ts"]); tb = datetime.fromisoformat(b["ts"])
                hours = max(abs((ta - tb).total_seconds()) / 3600.0, 1 / 3600.0)
                dist = haversine_km(float(a["latitude"]), float(a["longitude"]), float(b["latitude"]), float(b["longitude"]))
                speed = dist / hours
                if dist > 500 and speed > 900:
                    evd = f"{dist:.0f} km displacement; estimated velocity {speed:.0f} km/h"
                    add_alert("impossible_travel", a["source_ip"], username, "CRITICAL", 92.0, ATTACK_MITRE["impossible_travel"], f"P1 {evd}")
                    add_incident("impossible_travel", a["source_ip"], 1, "CRITICAL", 92.0, ATTACK_MITRE["impossible_travel"], f"P1 {evd}")
                    break
            except Exception:
                continue

    # Secondary Isolation Forest corroboration. It never overrides the rule engine.
    try:
        model = ensure_if_model()
        if model is not None:
            keys, features = _if_features_from_rows(ev)
            if len(features) >= 3:
                preds = model.predict(features)
                for ip, pred, feat in zip(keys, preds, features):
                    total, failures, users, fail_ratio, _velocity, _geo_users = feat
                    if pred == -1 and ip not in flagged_ips and (failures >= 2 or users >= 3):
                        risk = min(74.0, 40.0 + failures * 4.0 + users * 2.0)
                        tier, severity = severity_for_risk(risk)
                        evd = f"Isolation Forest anomaly on behavioral window: {total} events, {failures} failures, {users} users"
                        add_alert("ml_anomaly", ip, None, severity, risk, ATTACK_MITRE["ml_anomaly"], f"{tier} {evd}")
                        add_incident("ml_anomaly", ip, users, severity, risk, ATTACK_MITRE["ml_anomaly"], f"{tier} {evd}")
    except Exception:
        # ML is secondary; rule-based detection must remain available even if the model cannot score.
        pass

def _incident_users(source_ip: str, limit: int = 50) -> list[str]:
    with DB_LOCK, db() as c:
        rows = c.execute("SELECT DISTINCT username FROM events WHERE source_ip=? ORDER BY id DESC LIMIT ?", (source_ip, limit)).fetchall()
    return [r[0] for r in rows]


def _map_alert(row):
    return {
        "alert_id": f"ALT-{int(row['id']):04d}",
        "attack_type": row["event_type"],
        "severity": row["severity"],
        "risk_score": float(row["risk"]),
        "mitre": row["mitre"],
        "status": row["status"] or "NEW",
        "created_at": row["created_at"],
        "last_seen": row["created_at"],
        "source_ips": [row["source_ip"]],
        "affected_users": [row["username"]] if row["username"] else _incident_users(row["source_ip"], 20),
        "evidence": row["evidence"],
        "severity_tier": severity_for_risk(float(row["risk"]))[0],
    }


def _map_incident(row):
    users = _incident_users(row["source_ip"], max(1, int(row["users"])))
    return {
        "incident_id": f"INC-{int(row['id']):04d}",
        "attack_types": [row["event_type"]],
        "source_ips": [row["source_ip"]],
        "affected_users": users,
        "severity": row["severity"],
        "risk_score": float(row["risk"]),
        "mitre": row["mitre"],
        "status": row["status"] or "NEW",
        "created_at": row["created_at"],
        "last_seen": row["created_at"],
        "evidence": row["evidence"],
        "severity_tier": severity_for_risk(float(row["risk"]))[0],
    }


def metrics() -> dict:
    with DB_LOCK, db() as c:
        total_alerts = int(c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        incidents_count = int(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
        event_count = int(c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        by_type = {r[0]: int(r[1]) for r in c.execute("SELECT event_type, COUNT(*) FROM alerts GROUP BY event_type")}
        critical_alerts = int(c.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0])
        tracked = int(c.execute("SELECT COUNT(DISTINCT source_ip) FROM events WHERE ts >= ?", (datetime.fromtimestamp(time.time()-3600, tz=timezone.utc).isoformat(),)).fetchone()[0])
        geo_users = int(c.execute("SELECT COUNT(DISTINCT username) FROM events WHERE latitude IS NOT NULL AND longitude IS NOT NULL").fetchone()[0])
    return {
        "total_events": event_count,
        "ingested_events": event_count,
        "total_alerts": total_alerts,
        "active_alerts": total_alerts,
        "incidents": incidents_count,
        "critical_alerts": critical_alerts,
        "events_per_minute": round(event_count / 60.0, 2),
        "alerts_by_type": {
            "brute_force": by_type.get("brute_force", 0),
            "password_spraying": by_type.get("password_spraying", 0),
            "vpn_spray": by_type.get("vpn_spray", 0),
            "impossible_travel": by_type.get("impossible_travel", 0),
            "anomaly": by_type.get("ml_anomaly", 0),
            "ml_anomaly": by_type.get("ml_anomaly", 0),
        },
        "attack_distribution": {
            "brute_force": by_type.get("brute_force", 0),
            "password_spraying": by_type.get("password_spraying", 0),
            "vpn_spray": by_type.get("vpn_spray", 0),
            "impossible_travel": by_type.get("impossible_travel", 0),
        },
        "tracked_sources": tracked,
        "tracked_geo_users": geo_users,
    }


def activity_series(minutes: int = 60) -> list[dict]:
    minutes = max(1, min(int(minutes), 1440))
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    buckets = []
    for i in range(minutes-1, -1, -1):
        ts = now - __import__('datetime').timedelta(minutes=i)
        buckets.append({"timestamp": ts.isoformat(), "total": 0, "failures": 0, "successes": 0})
    index = {b["timestamp"]: b for b in buckets}
    with DB_LOCK, db() as c:
        rows = c.execute("SELECT ts,status FROM events WHERE ts >= ? ORDER BY id ASC", (buckets[0]["timestamp"],)).fetchall()
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["ts"]).astimezone(timezone.utc).replace(second=0, microsecond=0).isoformat()
        except Exception:
            continue
        if ts in index:
            b = index[ts]; b["total"] += 1; b["failures"] += int(int(r["status"]) == 401); b["successes"] += int(int(r["status"]) == 200)
    return buckets


def evaluation_payload() -> dict:
    with DB_LOCK, db() as c:
        row = c.execute("SELECT * FROM dataset_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return {"available": False}
    precision, recall, f1, fpr = row["precision"], row["recall"], row["f1"], row["fpr"]
    return {
        "available": precision is not None,
        "evaluation_type": "USER_UPLOADED_DATASET",
        "macro_precision": precision,
        "macro_recall": recall,
        "macro_f1": f1,
        "fpr": fpr,
        "not_real_world_benchmark": True,
    }

def _parse_query(path: str):
    parsed = urlparse(path)
    return parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}


def api_payload(path: str, query: dict | None = None) -> dict | list:
    query = query or {}
    if path == "/api/metrics":
        return metrics()
    if path == "/api/activity":
        return activity_series(int(query.get("minutes", 60)))
    if path == "/api/evaluation":
        return evaluation_payload()
    if path == "/api/alerts":
        limit = min(int(query.get("limit", 50)), 200)
        with DB_LOCK, db() as c:
            sql = "SELECT * FROM alerts WHERE 1=1"; args=[]
            if query.get("attack_type"): sql += " AND event_type=?"; args.append(query["attack_type"])
            if query.get("severity"): sql += " AND severity=?"; args.append(query["severity"])
            if query.get("status"): sql += " AND status=?"; args.append(query["status"])
            if query.get("source_ip"): sql += " AND source_ip=?"; args.append(query["source_ip"])
            sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
            rows = c.execute(sql, args).fetchall()
        return [_map_alert(r) for r in rows]
    if path == "/api/incidents":
        limit = min(int(query.get("limit", 50)), 200)
        with DB_LOCK, db() as c:
            rows = c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [_map_incident(r) for r in rows]
    if path == "/api/geo":
        limit = min(int(query.get("limit", 500)), 1000)
        since = datetime.fromtimestamp(time.time()-int(query.get("minutes", 1440))*60, tz=timezone.utc).isoformat()
        with DB_LOCK, db() as c:
            rows = c.execute("SELECT latitude,longitude,city,country,source_ip,username,status,ts FROM events WHERE ts>=? ORDER BY id DESC LIMIT ?", (since, limit)).fetchall()
            alert_by_ip = {r[0]: r[1] for r in c.execute("SELECT source_ip,event_type FROM alerts ORDER BY id DESC").fetchall()}
        points=[]
        for r in rows:
            d=dict(r); d["timestamp"]=d.pop("ts"); d["status"]="failure" if int(d["status"])==401 else "success"; d["attack_type"]=alert_by_ip.get(d["source_ip"]); points.append(d)
        return {"points":points,"count":len(points),"source":"sqlite_events"}
    if path == "/api/dataset-runs":
        with DB_LOCK, db() as c:
            rows = c.execute("SELECT * FROM dataset_runs ORDER BY id DESC LIMIT 10").fetchall()
        return {"items":[dict(r) for r in rows]}
    if path.startswith("/api/investigate/ip/"):
        ip = path.rsplit('/',1)[-1]
        with DB_LOCK, db() as c:
            rows = c.execute("SELECT * FROM events WHERE source_ip=? ORDER BY id ASC LIMIT 5000", (ip,)).fetchall(); alerts = c.execute("SELECT * FROM alerts WHERE source_ip=? ORDER BY id DESC", (ip,)).fetchall()
        return {"source_ip":ip,"attempts":len(rows),"failures":sum(int(r["status"])==401 for r in rows),"successes":sum(int(r["status"])==200 for r in rows),"targeted_users":sorted({r["username"] for r in rows}),"countries":sorted({r["country"] for r in rows if r["country"]}),"attack_types":sorted({r["event_type"] for r in alerts}),"timeline":[dict(r) for r in rows[-200:]],"alerts":[_map_alert(r) for r in alerts]}
    if path.startswith("/api/investigate/user/"):
        user = path.rsplit('/',1)[-1]
        with DB_LOCK, db() as c:
            rows = c.execute("SELECT * FROM events WHERE username=? ORDER BY id ASC LIMIT 5000", (user,)).fetchall()
        return {"username":user,"attempts":len(rows),"failures":sum(int(r["status"])==401 for r in rows),"successes":sum(int(r["status"])==200 for r in rows),"countries":sorted({r["country"] for r in rows if r["country"]}),"devices":[],"typical_hours":sorted({datetime.fromisoformat(r["ts"]).hour for r in rows}),"recent_events":[dict(r) for r in rows[-200:]]}
    if path.startswith("/api/alerts/"):
        aid=int(path.rsplit('/',1)[-1].replace('ALT-',''))
        with DB_LOCK, db() as c: row=c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return _map_alert(row) if row else {"detail":"not found"}
    if path.startswith("/api/incidents/"):
        iid=int(path.rsplit('/',1)[-1].replace('INC-',''))
        with DB_LOCK, db() as c: row=c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        return _map_incident(row) if row else {"detail":"not found"}
    return {"error":"not_found"}

def evaluate_csv(text: str) -> dict:
    """Evaluate a user-supplied authentication CSV with post-detection labels.

    Detection uses only behavioral columns. Ground-truth labels are read only
    after predictions are produced, so labels do not leak into detection.
    """
    df = pd.read_csv(io.StringIO(text))
    cols = {c.lower().strip(): c for c in df.columns}
    required = {"status", "username", "source_ip"}
    missing = [c for c in required if c not in cols]
    if missing:
        raise ValueError(f"CSV missing required columns: {', '.join(missing)}")

    status_col = cols["status"]
    user_col = cols["username"]
    ip_col = cols["source_ip"]
    time_col = next((cols[k] for k in ("timestamp", "time", "ts", "datetime") if k in cols), None)
    lat_col = next((cols[k] for k in ("latitude", "lat") if k in cols), None)
    lon_col = next((cols[k] for k in ("longitude", "lon", "lng") if k in cols), None)
    label_col = next((cols[k] for k in ("ground_truth_label", "ground_truth", "label") if k in cols), None)

    work = df.copy()
    work[status_col] = pd.to_numeric(work[status_col], errors="coerce").fillna(401).astype(int)
    work["_pred"] = "NORMAL"

    failures = work[status_col].eq(401)
    failure_df = work.loc[failures]
    for ip, g in failure_df.groupby(ip_col, dropna=False):
        per_user = g.groupby(user_col, dropna=False).size()
        if not per_user.empty and int(per_user.max()) >= 5:
            work.loc[g.index, "_pred"] = "ATTACK_BRUTE_FORCE"
        if g[user_col].nunique(dropna=True) >= 5:
            work.loc[g.index, "_pred"] = "ATTACK_PASSWORD_SPRAY"

    # Impossible-travel scoring from supplied geo/time columns, when available.
    if time_col and lat_col and lon_col:
        temp = work[[user_col, time_col, lat_col, lon_col]].copy()
        temp["_time"] = pd.to_datetime(temp[time_col], errors="coerce", utc=True)
        temp["_lat"] = pd.to_numeric(temp[lat_col], errors="coerce")
        temp["_lon"] = pd.to_numeric(temp[lon_col], errors="coerce")
        temp = temp.dropna(subset=["_time", "_lat", "_lon"])
        for user, g in temp.groupby(user_col, dropna=False):
            g = g.sort_values("_time")
            rows = list(g.itertuples())
            for prev, cur in zip(rows, rows[1:]):
                dt_hours = abs((cur._time - prev._time).total_seconds()) / 3600.0
                dt_hours = max(dt_hours, 1 / 3600.0)
                dist = haversine_km(float(prev._lat), float(prev._lon), float(cur._lat), float(cur._lon))
                speed = dist / dt_hours
                if dist > 1000 and speed > 800:
                    work.loc[cur.Index, "_pred"] = "ATTACK_IMPOSSIBLE_TRAVEL"

    if label_col:
        y = work[label_col].fillna("NORMAL").astype(str).str.upper().str.strip()
        p = work["_pred"].astype(str).str.upper().str.strip()
        actual_attack = ~y.eq("NORMAL")
        pred_attack = ~p.eq("NORMAL")
        tp = int((actual_attack & pred_attack).sum())
        fp = int((~actual_attack & pred_attack).sum())
        fn = int((actual_attack & ~pred_attack).sum())
        tn = int((~actual_attack & ~pred_attack).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
    else:
        precision = recall = f1 = fpr = None

    # Incident-level operational metrics: collapse event predictions into source/type stories.
    pred_groups = set()
    actual_groups = set()
    if label_col:
        for _, r in work.iterrows():
            pred = str(r["_pred"]).upper()
            actual = str(r[label_col]).upper()
            if pred != "NORMAL":
                typ = "ATTACK_PASSWORD_SPRAY" if pred in {"ATTACK_PASSWORD_SPRAY", "VPN_SPRAY"} else pred
                pred_groups.add((str(r[ip_col]), typ))
            if actual != "NORMAL":
                typ = "ATTACK_PASSWORD_SPRAY" if actual == "ATTACK_PASSWORD_SPRAY" else actual
                actual_groups.add((str(r[ip_col]), typ))
    tp_incidents = len(pred_groups & actual_groups)
    alert_count = len(pred_groups)
    alert_tp = (alert_count / tp_incidents) if tp_incidents else (float(alert_count) if alert_count else None)
    incident_precision = tp_incidents / len(pred_groups) if pred_groups else 0.0
    incident_recall = tp_incidents / len(actual_groups) if actual_groups else 0.0
    incident_f1 = (2*incident_precision*incident_recall/(incident_precision+incident_recall)) if incident_precision+incident_recall else 0.0
    raw_attack_events = int((~work[label_col].fillna("NORMAL").astype(str).str.upper().eq("NORMAL")).sum()) if label_col else 0
    incident_compression = (raw_attack_events / alert_count) if alert_count else None
    event_level = {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}
    incident_level = {"precision": incident_precision, "recall": incident_recall, "f1": incident_f1, "alert_to_true_positive_ratio": alert_tp, "mttd_seconds": 0.0 if alert_count else None, "incident_compression": incident_compression, "true_positive_incidents": tp_incidents, "predicted_incidents": alert_count}
    out = {
        "rows": int(len(df)),
        "predicted_attacks": int((work["_pred"] != "NORMAL").sum()),
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "event_level": event_level, "incident_level": incident_level,
        "macro_precision": precision, "macro_recall": recall, "macro_f1": f1,
        "labels_used_post_detection": bool(label_col),
        "predicted_attack_types": {k: int((work["_pred"] == k).sum()) for k in sorted(set(work["_pred"])) if k != "NORMAL"},
        "not_real_world_benchmark": True,
    }
    with DB_LOCK, db() as c:
        c.execute(
            "INSERT INTO dataset_runs(created_at,rows,precision,recall,f1,fpr) VALUES(?,?,?,?,?,?)",
            (now_iso(), out["rows"], precision, recall, f1, fpr),
        )
        c.commit()
    return out



def _dataset_behavioral_frame(df: pd.DataFrame) -> pd.DataFrame:
    cols = {c.lower().strip(): c for c in df.columns}
    required = {"status", "username", "source_ip"}
    missing = [c for c in required if c not in cols]
    if missing:
        raise ValueError(f"CSV missing required columns: {', '.join(missing)}")
    status_col, user_col, ip_col = cols["status"], cols["username"], cols["source_ip"]
    status = pd.to_numeric(df[status_col], errors="coerce").fillna(401).astype(int)
    work = pd.DataFrame({
        "status": status,
        "username": df[user_col].astype(str),
        "source_ip": df[ip_col].astype(str),
    })
    work["is_failure"] = work["status"].eq(401).astype(int)
    grouped = work.groupby("source_ip", dropna=False)
    rows = []
    for ip, g in grouped:
        total = int(len(g))
        failures = int(g["is_failure"].sum())
        users = int(g["username"].nunique(dropna=True))
        fail_ratio = failures / total if total else 0.0
        rows.append({
            "source_ip": str(ip),
            "total_events": total,
            "failures": failures,
            "users": users,
            "fail_ratio": fail_ratio,
            "velocity": float(total),
        })
    out = pd.DataFrame(rows)
    if out.empty:
        raise ValueError("CSV contains no usable authentication rows.")
    return out


def train_dataset_model(text: str) -> dict:
    if IsolationForest is None:
        raise RuntimeError("scikit-learn / IsolationForest is unavailable in this environment.")
    df = pd.read_csv(io.StringIO(text))
    if len(df) > 50000:
        raise ValueError("CSV exceeds the 50,000-row dataset limit.")
    feat = _dataset_behavioral_frame(df)
    X = feat[["total_events", "failures", "users", "fail_ratio", "velocity"]].astype(float).values
    if len(X) < 3:
        raise ValueError("At least 3 distinct source IP behavioral groups are required for training.")
    contamination = min(0.25, max(0.02, 1.0 / len(X)))
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(X)
    import pickle
    with DATASET_MODEL_PATH.open("wb") as f:
        pickle.dump(model, f)
    return {
        "rows": int(len(df)),
        "behavioral_groups": int(len(feat)),
        "features": ["total_events", "failures", "users", "fail_ratio", "velocity"],
        "model": "IsolationForest",
        "model_path": str(DATASET_MODEL_PATH),
        "contamination": contamination,
        "trained_from_user_uploaded_dataset": True,
        "metrics": None,
        "not_real_world_benchmark": True,
    }


def analyze_dataset_model(text: str) -> dict:
    if IsolationForest is None:
        raise RuntimeError("scikit-learn / IsolationForest is unavailable in this environment.")
    import pickle
    if not DATASET_MODEL_PATH.exists():
        raise ValueError("No dataset Isolation Forest model has been trained yet.")
    df = pd.read_csv(io.StringIO(text))
    if len(df) > 50000:
        raise ValueError("CSV exceeds the 50,000-row dataset limit.")
    feat = _dataset_behavioral_frame(df)
    with DATASET_MODEL_PATH.open("rb") as f:
        model = pickle.load(f)
    X = feat[["total_events", "failures", "users", "fail_ratio", "velocity"]].astype(float).values
    preds = model.predict(X)
    scores = model.decision_function(X)
    results = []
    for row, pred, score in zip(feat.to_dict("records"), preds, scores):
        results.append({
            **row,
            "prediction": "ANOMALY" if int(pred) == -1 else "NORMAL",
            "decision_score": round(float(score), 6),
        })
    anomalies = [r for r in results if r["prediction"] == "ANOMALY"]
    return {
        "rows": int(len(df)),
        "behavioral_groups": int(len(results)),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "normal_count": len(results) - len(anomalies),
        "model": "IsolationForest",
        "uses_ground_truth_labels": False,
        "not_real_world_benchmark": True,
    }


WORLD_MAP_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 500" preserveAspectRatio="none">
<rect width="1000" height="500" fill="#020a05"/>
<line x1="0" y1="0" x2="0" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="100" y1="0" x2="100" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="200" y1="0" x2="200" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="300" y1="0" x2="300" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="400" y1="0" x2="400" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="500" y1="0" x2="500" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="600" y1="0" x2="600" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="700" y1="0" x2="700" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="800" y1="0" x2="800" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="900" y1="0" x2="900" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="1000" y1="0" x2="1000" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="0" x2="1000" y2="0" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="50" x2="1000" y2="50" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="100" x2="1000" y2="100" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="150" x2="1000" y2="150" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="200" x2="1000" y2="200" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="250" x2="1000" y2="250" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="300" x2="1000" y2="300" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="350" x2="1000" y2="350" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="400" x2="1000" y2="400" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="450" x2="1000" y2="450" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<line x1="0" y1="500" x2="1000" y2="500" stroke="#0a3a2c" stroke-width="0.7" opacity="0.45"/>
<g fill="#071b14" stroke="#1b7d63" stroke-width="1.0" opacity="0.92">
<path d="M 1000.0,294.6 L 1000.0,296.0 L 996.5,297.3 L 996.1,296.2 L 1000.0,294.6 Z"/>
<path d="M 993.5,298.3 L 996.4,299.0 L 996.0,300.4 L 992.7,300.5 L 993.5,298.3 Z"/>
<path d="M 0.0,294.6 L 0.2,295.8 L 0.0,296.0 L 0.0,294.6 Z"/>
<path d="M 594.2,252.6 L 604.7,258.6 L 604.9,260.2 L 608.9,263.0 L 607.6,266.4 L 607.8,268.0 L 609.6,269.0 L 608.9,273.6 L 612.0,278.7 L 609.8,280.3 L 601.4,282.6 L 596.0,282.0 L 593.7,276.2 L 585.4,273.2 L 582.3,268.1 L 581.5,262.5 L 585.4,259.3 L 584.6,256.7 L 585.6,254.7 L 584.5,253.2 L 594.2,252.6 Z"/>
<path d="M 475.9,173.2 L 475.9,178.1 L 466.8,178.0 L 466.8,185.1 L 464.2,185.3 L 464.1,190.8 L 453.2,190.7 L 452.6,191.7 L 452.7,190.5 L 459.0,190.3 L 461.4,184.2 L 465.3,181.2 L 466.6,177.7 L 468.4,175.3 L 475.6,174.7 L 475.9,173.2 Z"/>
<path d="M 158.8,113.9 L 151.0,110.0 L 146.0,108.8 L 144.5,106.3 L 144.9,104.6 L 141.3,103.5 L 140.8,101.2 L 137.5,99.2 L 138.9,94.7 L 134.1,92.9 L 129.6,87.7 L 123.7,83.9 L 118.2,86.4 L 113.8,83.3 L 108.3,82.5 L 108.4,56.4 L 120.8,58.6 L 126.6,56.6 L 130.8,56.9 L 139.5,55.0 L 141.4,56.2 L 144.1,54.2 L 150.7,57.0 L 154.4,55.1 L 154.8,57.2 L 162.6,56.1 L 179.9,58.6 L 183.6,60.0 L 179.7,61.4 L 184.7,62.0 L 194.6,61.2 L 197.6,62.8 L 200.6,61.4 L 197.7,60.2 L 199.5,59.3 L 205.1,58.9 L 210.2,61.1 L 218.2,62.1 L 226.5,61.7 L 226.2,60.0 L 228.7,59.5 L 233.0,60.4 L 233.0,63.1 L 234.8,60.9 L 237.0,60.9 L 238.2,58.1 L 232.0,55.3 L 232.2,52.2 L 235.5,50.2 L 242.0,51.9 L 245.8,55.0 L 243.3,56.4 L 248.5,57.0 L 248.5,59.8 L 252.2,57.6 L 255.5,59.4 L 254.7,61.5 L 257.4,63.3 L 262.3,58.9 L 262.4,55.9 L 270.5,56.5 L 274.2,57.9 L 274.4,59.3 L 272.3,60.7 L 274.3,62.2 L 273.9,63.6 L 268.5,65.5 L 261.8,65.1 L 257.4,70.1 L 254.2,71.9 L 248.0,73.3 L 247.9,75.1 L 244.6,75.5 L 238.2,80.8 L 237.0,86.3 L 241.1,86.7 L 243.6,91.4 L 247.5,90.9 L 263.9,96.4 L 271.5,96.8 L 271.9,102.0 L 273.9,105.1 L 278.0,107.8 L 280.2,106.9 L 281.7,104.0 L 280.2,99.6 L 278.3,98.1 L 282.7,96.8 L 287.4,93.0 L 285.3,88.7 L 281.9,86.7 L 285.2,83.7 L 283.0,76.9 L 294.9,76.5 L 301.7,80.2 L 306.7,80.4 L 307.5,86.2 L 312.1,88.3 L 316.1,86.8 L 320.6,82.4 L 329.5,91.8 L 328.3,93.5 L 334.5,96.7 L 340.7,98.3 L 341.8,100.6 L 345.1,102.0 L 345.3,105.1 L 333.2,110.4 L 315.6,110.5 L 309.7,113.7 L 302.5,119.9 L 304.8,119.5 L 309.3,115.8 L 315.1,113.5 L 319.3,113.2 L 321.7,114.6 L 319.1,116.5 L 320.9,121.6 L 324.5,122.9 L 329.1,122.5 L 331.9,119.4 L 332.1,121.4 L 333.9,122.4 L 318.4,129.0 L 316.3,128.8 L 316.2,126.5 L 321.0,124.2 L 313.5,124.6 L 311.7,123.0 L 311.7,119.3 L 307.7,118.2 L 303.7,123.7 L 301.4,125.0 L 292.0,125.0 L 286.6,128.8 L 281.3,128.8 L 280.1,129.3 L 280.7,130.9 L 271.0,134.2 L 269.1,133.4 L 271.8,129.0 L 270.7,124.0 L 264.2,119.7 L 254.5,115.8 L 245.4,116.3 L 238.0,114.8 L 236.6,112.8 L 235.7,112.8 L 235.7,113.9 L 158.8,113.9 Z"/>
<path d="M 266.7,76.5 L 268.7,75.2 L 272.6,75.3 L 269.3,77.3 L 266.7,76.5 Z"/>
<path d="M 278.4,47.8 L 275.3,46.3 L 275.5,45.3 L 283.2,45.4 L 288.2,47.7 L 278.4,47.8 Z"/>
<path d="M 276.9,77.5 L 278.0,76.7 L 279.8,77.3 L 278.7,78.8 L 276.9,77.5 Z"/>
<path d="M 240.0,41.7 L 238.5,42.8 L 231.1,41.9 L 236.5,39.9 L 240.0,41.7 Z"/>
<path d="M 239.3,34.7 L 232.9,34.6 L 232.1,33.8 L 237.7,33.8 L 239.3,34.7 Z"/>
<path d="M 226.0,30.9 L 234.6,32.2 L 233.8,33.2 L 229.7,33.7 L 227.4,33.1 L 226.0,30.9 Z"/>
<path d="M 255.1,43.4 L 243.3,42.1 L 242.0,39.2 L 239.2,38.0 L 230.2,36.8 L 231.3,35.7 L 245.5,36.7 L 247.9,37.6 L 247.3,38.7 L 252.3,40.0 L 274.6,39.7 L 278.2,41.9 L 272.4,43.2 L 255.1,43.4 Z"/>
<path d="M 190.9,32.9 L 194.8,33.3 L 188.7,35.0 L 184.6,34.1 L 190.9,32.9 Z"/>
<path d="M 190.3,31.0 L 195.4,31.7 L 187.4,32.2 L 190.3,31.0 Z"/>
<path d="M 346.1,106.7 L 342.2,111.6 L 344.0,110.7 L 345.9,111.3 L 344.9,112.3 L 351.5,113.2 L 350.6,115.2 L 352.5,114.8 L 353.8,118.0 L 352.6,120.4 L 349.5,120.0 L 350.1,117.7 L 349.3,117.4 L 346.1,119.8 L 344.5,119.7 L 346.4,118.4 L 343.7,117.7 L 335.4,117.8 L 334.9,116.9 L 336.7,116.0 L 335.5,115.2 L 340.7,109.1 L 344.8,106.6 L 346.1,106.7 Z"/>
<path d="M 261.4,67.4 L 273.2,71.0 L 273.5,72.3 L 277.5,73.0 L 275.0,73.9 L 270.7,73.2 L 269.1,71.9 L 262.4,74.9 L 261.5,73.2 L 257.7,73.5 L 260.1,72.1 L 261.4,67.4 Z"/>
<path d="M 275.7,49.8 L 283.8,47.9 L 293.8,50.6 L 294.2,51.9 L 299.3,51.2 L 302.2,53.0 L 308.9,54.1 L 314.0,57.8 L 308.9,59.1 L 319.8,61.5 L 323.8,64.1 L 328.2,64.3 L 327.3,66.2 L 322.4,69.4 L 314.7,65.6 L 311.1,65.9 L 310.7,67.5 L 318.6,71.2 L 320.4,73.9 L 319.4,75.9 L 308.9,72.9 L 316.2,78.0 L 308.7,76.9 L 292.1,70.3 L 292.2,71.1 L 284.1,71.6 L 281.8,70.6 L 283.6,68.6 L 294.6,68.2 L 293.6,67.2 L 294.6,65.8 L 298.2,63.1 L 296.4,60.9 L 286.5,58.6 L 288.3,57.9 L 280.7,55.1 L 274.2,56.3 L 253.7,54.4 L 251.4,53.4 L 254.3,52.2 L 250.3,52.2 L 249.4,49.3 L 251.6,46.9 L 254.4,45.7 L 261.6,45.0 L 259.5,46.8 L 261.7,48.5 L 264.3,46.3 L 271.3,45.1 L 276.1,48.0 L 275.7,49.8 Z"/>
<path d="M 237.5,44.1 L 243.3,44.2 L 248.6,44.8 L 238.1,49.9 L 235.0,49.8 L 233.3,46.0 L 237.5,44.1 Z"/>
<path d="M 158.7,38.6 L 169.2,34.7 L 177.2,34.3 L 176.8,36.5 L 174.7,37.4 L 162.5,39.2 L 158.7,38.6 Z"/>
<path d="M 130.1,99.5 L 134.0,99.7 L 133.2,102.8 L 135.6,105.1 L 130.4,101.6 L 130.1,99.5 Z"/>
<path d="M 207.0,29.7 L 219.9,31.1 L 223.1,33.6 L 207.8,32.3 L 210.5,31.5 L 207.2,30.8 L 207.0,29.7 Z"/>
<path d="M 156.9,115.2 L 151.0,114.4 L 147.1,111.6 L 144.3,111.1 L 143.4,109.0 L 150.7,110.3 L 156.9,115.2 Z"/>
<path d="M 153.0,43.6 L 173.5,43.9 L 179.1,45.9 L 168.8,48.6 L 165.4,50.5 L 165.4,51.7 L 158.1,53.1 L 150.2,50.4 L 155.7,45.3 L 153.0,43.6 Z"/>
<path d="M 200.5,39.3 L 205.9,39.0 L 206.4,40.3 L 204.7,41.7 L 188.3,43.3 L 184.0,43.3 L 183.7,42.4 L 189.5,41.2 L 173.0,41.0 L 179.4,37.6 L 197.0,40.4 L 193.1,37.7 L 195.6,36.7 L 198.5,37.0 L 200.5,39.3 Z"/>
<path d="M 198.9,47.0 L 207.2,48.1 L 209.8,52.8 L 219.5,55.5 L 219.2,56.7 L 214.6,56.9 L 216.4,58.0 L 215.5,59.0 L 205.7,57.8 L 185.2,59.6 L 183.7,58.3 L 177.5,57.9 L 174.1,55.7 L 187.7,54.5 L 172.5,54.1 L 171.0,53.0 L 177.5,51.9 L 168.3,51.2 L 172.6,48.0 L 180.0,46.3 L 182.9,46.9 L 181.5,48.2 L 187.7,47.3 L 191.5,48.7 L 194.7,47.3 L 197.2,48.2 L 199.5,51.0 L 200.9,49.8 L 198.9,47.0 Z"/>
<path d="M 221.0,48.0 L 217.9,46.2 L 221.2,44.9 L 229.5,45.1 L 230.2,45.9 L 227.6,47.2 L 231.8,48.4 L 231.3,50.9 L 226.8,52.0 L 215.3,48.6 L 215.3,47.7 L 221.0,48.0 Z"/>
<path d="M 202.9,45.9 L 207.6,45.4 L 209.7,46.1 L 207.3,47.9 L 202.9,45.9 Z"/>
<path d="M 226.4,36.9 L 228.5,38.2 L 227.3,41.7 L 222.8,42.0 L 219.8,41.5 L 219.8,39.9 L 215.3,40.1 L 215.1,38.0 L 226.4,36.9 Z"/>
<path d="M 231.4,27.3 L 238.1,25.1 L 236.8,24.4 L 243.3,24.3 L 246.9,25.8 L 256.1,26.9 L 261.6,29.6 L 252.7,32.5 L 242.0,32.4 L 239.0,31.2 L 239.1,30.2 L 241.3,29.5 L 236.2,29.5 L 231.4,27.3 Z"/>
<path d="M 245.6,22.5 L 262.5,20.4 L 268.9,21.3 L 271.1,19.8 L 279.7,19.1 L 297.7,18.8 L 328.2,20.5 L 328.1,21.2 L 312.1,23.6 L 318.1,23.6 L 307.0,26.1 L 302.3,28.3 L 286.4,29.7 L 290.2,30.0 L 288.3,30.5 L 290.6,31.9 L 278.4,35.5 L 283.6,36.7 L 276.2,38.4 L 251.4,37.6 L 251.1,36.2 L 256.2,35.6 L 254.8,33.6 L 264.0,34.6 L 260.2,32.8 L 255.7,32.3 L 263.6,29.6 L 259.7,28.5 L 258.5,27.1 L 268.3,27.5 L 272.6,26.5 L 256.7,26.3 L 251.8,25.4 L 245.6,22.5 Z"/>
<path d="M 291.1,62.7 L 286.1,63.6 L 285.5,62.3 L 286.6,60.7 L 289.2,60.3 L 291.3,61.1 L 291.1,62.7 Z"/>
<path d="M 227.2,55.2 L 234.3,58.0 L 232.6,59.0 L 222.8,57.2 L 227.2,55.2 Z"/>
<path d="M 320.8,111.5 L 325.4,111.9 L 328.3,113.6 L 323.4,112.8 L 320.8,111.5 Z"/>
<path d="M 322.2,119.3 L 323.2,120.7 L 327.7,121.0 L 325.3,122.3 L 321.8,121.1 L 321.1,120.2 L 322.2,119.3 Z"/>
<path d="M 158.8,113.9 L 235.7,113.9 L 235.7,112.8 L 236.6,112.8 L 238.0,114.8 L 245.4,116.3 L 254.5,115.8 L 264.2,119.7 L 270.7,124.0 L 271.8,129.0 L 269.1,133.1 L 270.3,134.2 L 280.7,130.9 L 280.1,129.3 L 281.3,128.8 L 286.6,128.8 L 292.0,125.0 L 301.4,125.0 L 303.7,123.7 L 307.7,118.2 L 311.7,119.3 L 311.7,123.0 L 314.0,125.5 L 305.2,128.7 L 303.3,132.4 L 304.2,133.9 L 305.3,133.9 L 305.0,132.9 L 305.9,133.5 L 305.7,134.3 L 295.2,136.3 L 300.2,136.3 L 294.6,136.8 L 293.9,139.7 L 291.9,141.8 L 290.2,140.3 L 291.5,143.3 L 289.1,146.6 L 289.7,144.6 L 288.2,143.6 L 287.9,141.3 L 288.0,144.2 L 286.1,143.8 L 288.1,144.7 L 289.6,151.2 L 287.9,153.3 L 280.4,157.0 L 274.1,162.7 L 274.1,166.6 L 277.6,175.3 L 276.7,180.0 L 274.5,180.0 L 273.0,178.1 L 269.8,172.5 L 270.4,170.7 L 267.5,166.8 L 263.6,167.7 L 260.0,165.6 L 251.1,166.2 L 251.6,169.0 L 241.0,167.3 L 237.0,168.1 L 230.2,172.7 L 230.2,178.1 L 229.1,178.2 L 224.9,176.7 L 219.6,168.4 L 215.3,167.3 L 213.6,169.5 L 211.3,168.7 L 204.1,161.8 L 199.3,161.8 L 199.3,162.9 L 191.6,163.0 L 181.3,159.1 L 174.6,159.6 L 170.8,155.5 L 164.9,153.9 L 154.4,138.0 L 155.0,133.3 L 154.1,131.2 L 155.8,123.5 L 153.6,116.2 L 158.0,116.6 L 159.5,119.2 L 160.2,118.4 L 158.8,113.9 Z"/>
<path d="M 67.1,193.7 L 70.0,195.8 L 67.5,197.5 L 66.5,195.3 L 67.1,193.7 Z"/>
<path d="M 66.7,192.3 L 65.5,192.9 L 64.7,191.9 L 65.0,191.6 L 66.7,192.3 Z"/>
<path d="M 63.2,191.1 L 64.5,191.5 L 63.0,191.4 L 63.2,191.1 Z"/>
<path d="M 61.0,189.7 L 62.1,190.8 L 61.9,190.9 L 60.8,190.8 L 61.0,189.7 Z"/>
<path d="M 56.7,188.2 L 57.0,189.2 L 56.1,188.7 L 56.7,188.2 Z"/>
<path d="M 34.8,82.7 L 39.8,82.5 L 40.1,83.6 L 38.4,84.0 L 34.8,82.7 Z"/>
<path d="M 74.4,89.0 L 77.4,90.0 L 72.2,92.4 L 70.8,91.7 L 70.4,90.4 L 74.4,89.0 Z"/>
<path d="M 108.4,56.4 L 108.3,82.5 L 113.8,83.3 L 118.2,86.4 L 123.7,83.9 L 129.6,87.7 L 134.1,92.9 L 138.9,94.7 L 138.9,96.4 L 137.4,97.8 L 133.4,95.8 L 132.6,93.4 L 129.1,91.2 L 127.6,88.5 L 120.5,88.3 L 111.5,84.6 L 100.1,83.3 L 91.3,80.9 L 88.3,81.5 L 88.8,83.4 L 78.6,85.7 L 78.2,84.0 L 79.4,81.3 L 82.4,80.5 L 81.6,79.8 L 72.2,85.1 L 74.2,86.5 L 71.6,88.5 L 65.8,90.5 L 59.9,94.5 L 47.0,98.1 L 41.8,98.4 L 50.5,94.7 L 54.0,94.4 L 59.2,91.6 L 61.9,90.1 L 63.8,86.3 L 58.2,87.7 L 56.4,86.3 L 55.6,87.3 L 54.6,85.9 L 50.1,87.0 L 50.3,84.4 L 48.6,83.4 L 44.9,83.9 L 40.7,81.9 L 40.7,80.4 L 38.6,79.2 L 39.6,77.6 L 42.9,74.6 L 47.0,74.8 L 53.4,72.9 L 51.3,71.1 L 53.4,70.0 L 47.9,71.3 L 41.8,71.0 L 37.7,70.3 L 33.0,67.6 L 43.1,65.1 L 45.4,65.1 L 45.0,66.5 L 50.9,66.3 L 40.6,61.0 L 36.8,60.1 L 38.3,58.7 L 43.2,58.6 L 50.3,54.6 L 65.1,51.8 L 71.3,53.6 L 77.2,53.3 L 81.3,54.4 L 108.4,56.4 Z"/>
<path d="M 23.0,72.8 L 26.4,73.1 L 31.4,74.2 L 29.1,75.1 L 23.5,74.1 L 23.0,72.8 Z"/>
<path d="M 742.7,113.3 L 740.6,115.1 L 738.2,115.4 L 738.1,118.2 L 736.6,119.4 L 731.1,118.5 L 729.1,123.5 L 722.1,125.2 L 724.6,130.1 L 722.7,130.8 L 722.9,132.4 L 719.8,131.0 L 710.1,130.9 L 706.1,129.7 L 704.6,130.3 L 704.1,131.9 L 697.7,131.4 L 697.1,132.6 L 691.9,135.0 L 690.6,137.0 L 688.8,135.7 L 685.3,135.6 L 684.8,133.4 L 683.4,133.3 L 683.6,130.6 L 680.3,128.5 L 672.3,129.2 L 669.6,126.7 L 662.5,123.4 L 655.4,125.0 L 655.5,135.3 L 654.0,135.4 L 650.2,132.4 L 645.8,133.9 L 645.8,131.1 L 642.6,130.2 L 639.7,126.1 L 642.4,126.3 L 642.5,124.3 L 647.3,124.3 L 647.3,119.9 L 642.2,119.3 L 636.4,121.1 L 635.0,120.7 L 635.3,119.2 L 633.5,117.4 L 631.4,117.5 L 629.1,115.6 L 632.1,109.8 L 634.9,111.5 L 635.3,109.4 L 641.0,106.4 L 645.4,106.3 L 654.8,109.4 L 657.7,108.2 L 662.1,108.2 L 665.7,109.6 L 666.5,108.8 L 670.4,108.9 L 671.1,107.6 L 666.6,105.7 L 669.2,104.3 L 668.7,103.6 L 671.4,102.8 L 669.4,100.9 L 670.7,100.0 L 681.1,99.0 L 691.9,96.2 L 696.8,96.8 L 697.7,99.6 L 700.6,99.0 L 704.2,99.9 L 704.0,101.4 L 713.6,98.6 L 712.6,99.5 L 716.1,101.7 L 722.3,108.7 L 723.8,107.3 L 727.6,108.9 L 731.6,108.1 L 737.6,112.0 L 741.2,111.6 L 742.7,113.3 Z"/>
<path d="M 655.5,135.3 L 655.4,125.0 L 662.5,123.4 L 669.6,126.7 L 672.3,129.2 L 680.3,128.5 L 683.6,130.6 L 683.4,133.3 L 684.8,133.4 L 685.3,135.6 L 688.8,135.7 L 689.6,137.0 L 697.1,132.6 L 697.9,132.9 L 695.6,134.7 L 702.9,136.5 L 699.4,138.5 L 696.1,138.3 L 696.3,136.2 L 692.6,136.9 L 690.4,140.2 L 688.1,140.1 L 687.3,141.3 L 689.4,141.9 L 690.0,144.0 L 688.4,146.8 L 684.8,146.2 L 684.9,144.5 L 678.3,142.0 L 673.3,138.7 L 671.9,135.9 L 668.0,135.5 L 666.9,134.9 L 666.6,132.7 L 662.9,131.2 L 658.1,133.8 L 658.6,135.2 L 655.5,135.3 Z"/>
<path d="M 891.7,257.2 L 901.6,260.7 L 905.1,263.5 L 905.5,265.2 L 910.1,266.9 L 910.8,268.4 L 908.3,268.7 L 908.9,270.5 L 913.2,275.3 L 914.7,275.2 L 914.6,276.4 L 918.9,278.6 L 918.6,279.4 L 910.9,278.1 L 905.7,272.4 L 902.1,271.2 L 898.0,272.9 L 898.4,275.0 L 896.2,275.9 L 891.8,275.3 L 891.7,257.2 Z"/>
<path d="M 924.0,260.2 L 925.4,262.5 L 924.5,263.2 L 923.4,260.5 L 918.5,257.6 L 919.3,256.9 L 924.0,260.2 Z"/>
<path d="M 920.3,266.2 L 915.9,267.5 L 912.0,266.0 L 912.2,265.1 L 916.2,265.3 L 917.1,263.9 L 917.3,265.4 L 918.9,265.2 L 921.2,263.2 L 920.9,261.6 L 922.6,261.5 L 923.1,263.5 L 920.3,266.2 Z"/>
<path d="M 929.2,264.3 L 933.4,268.2 L 933.0,268.9 L 931.0,268.2 L 929.2,264.3 Z"/>
<path d="M 891.7,257.2 L 891.8,275.3 L 889.3,273.0 L 882.3,273.4 L 883.4,271.1 L 885.2,270.3 L 883.1,265.0 L 871.3,259.8 L 869.4,261.4 L 868.8,259.2 L 866.6,257.8 L 871.6,256.9 L 871.4,256.2 L 867.3,256.1 L 862.6,252.6 L 867.7,251.0 L 872.2,252.2 L 873.4,257.7 L 876.3,259.4 L 878.6,256.4 L 881.8,254.7 L 891.7,257.2 Z"/>
<path d="M 847.1,274.7 L 847.5,276.1 L 845.7,278.2 L 842.9,278.4 L 844.4,275.8 L 847.1,274.7 Z"/>
<path d="M 872.8,269.2 L 872.5,267.1 L 873.6,265.1 L 874.2,267.3 L 872.8,269.2 Z"/>
<path d="M 827.5,238.5 L 825.9,241.0 L 827.9,243.6 L 827.4,244.9 L 830.5,247.5 L 827.3,247.8 L 826.4,252.2 L 823.8,254.1 L 822.6,261.1 L 822.2,260.2 L 819.1,261.4 L 818.0,259.7 L 814.6,258.7 L 811.3,259.7 L 810.3,258.3 L 806.2,258.2 L 805.8,254.4 L 803.0,251.3 L 802.6,248.8 L 803.0,246.3 L 804.6,244.4 L 807.0,247.9 L 810.5,247.5 L 813.5,245.8 L 816.1,246.6 L 818.4,246.0 L 821.8,238.0 L 827.5,238.5 Z"/>
<path d="M 855.9,257.9 L 862.4,258.6 L 863.4,260.7 L 861.1,259.6 L 855.3,259.4 L 855.9,257.9 Z"/>
<path d="M 852.4,260.5 L 850.5,260.0 L 850.0,258.8 L 852.8,258.7 L 853.5,259.6 L 852.4,260.5 Z"/>
<path d="M 855.4,244.0 L 855.6,245.5 L 857.2,245.7 L 857.5,246.9 L 857.3,249.3 L 855.9,249.0 L 855.5,250.7 L 856.6,252.2 L 855.8,252.5 L 853.9,247.2 L 855.4,244.0 Z"/>
<path d="M 835.8,246.4 L 844.7,247.5 L 847.4,245.4 L 847.9,246.1 L 845.7,248.8 L 843.6,249.3 L 833.8,249.3 L 833.4,251.4 L 835.9,253.9 L 837.4,252.7 L 842.6,251.7 L 842.4,253.0 L 841.2,252.6 L 837.5,255.3 L 840.2,258.9 L 839.6,259.8 L 842.1,263.0 L 842.1,264.8 L 840.6,265.7 L 839.5,264.7 L 840.9,262.4 L 838.2,263.5 L 837.5,262.7 L 837.8,261.6 L 835.8,260.0 L 836.0,257.3 L 834.2,258.1 L 834.5,265.4 L 832.8,265.8 L 831.6,264.9 L 831.9,259.7 L 830.8,259.7 L 829.9,257.8 L 832.8,249.6 L 835.8,246.4 Z"/>
<path d="M 834.2,278.5 L 830.5,276.5 L 833.1,276.0 L 835.5,277.7 L 834.2,278.5 Z"/>
<path d="M 835.3,272.9 L 838.9,273.5 L 841.4,272.5 L 841.0,274.0 L 833.1,274.5 L 833.1,273.5 L 835.3,272.9 Z"/>
<path d="M 827.5,272.5 L 830.2,273.0 L 830.9,274.2 L 824.3,275.1 L 827.5,272.5 Z"/>
<path d="M 801.4,267.8 L 801.7,268.8 L 807.1,269.1 L 807.7,268.0 L 812.8,269.3 L 813.8,271.1 L 821.4,273.3 L 818.2,274.3 L 800.8,271.6 L 792.7,269.0 L 794.6,266.4 L 801.4,267.8 Z"/>
<path d="M 789.9,253.0 L 791.4,256.5 L 793.4,256.7 L 794.7,258.5 L 793.9,266.3 L 790.9,266.3 L 785.0,261.7 L 775.7,249.5 L 773.9,244.9 L 764.9,236.2 L 764.7,234.8 L 770.8,235.4 L 779.6,244.2 L 782.4,244.2 L 784.7,246.1 L 788.4,249.7 L 787.3,252.0 L 789.9,253.0 Z"/>
<path d="M 309.3,396.2 L 311.8,399.6 L 319.3,401.9 L 318.1,403.3 L 315.4,403.5 L 314.0,402.5 L 309.4,402.4 L 309.3,396.2 Z"/>
<path d="M 339.9,333.9 L 337.5,345.6 L 341.0,348.0 L 340.7,349.9 L 342.4,351.1 L 342.3,352.5 L 339.6,356.1 L 335.5,357.6 L 326.8,357.9 L 327.4,363.0 L 325.7,364.0 L 322.9,364.4 L 320.2,363.3 L 319.1,364.1 L 319.5,366.8 L 321.4,367.7 L 322.9,366.8 L 323.7,368.2 L 318.9,370.8 L 317.9,375.1 L 315.3,375.1 L 313.1,376.5 L 312.3,378.6 L 317.7,381.2 L 316.7,383.7 L 313.4,385.3 L 311.6,388.5 L 307.9,390.9 L 308.8,393.8 L 310.7,395.4 L 300.2,394.5 L 299.1,390.8 L 296.3,389.9 L 296.1,387.0 L 299.1,384.0 L 300.9,374.9 L 302.2,374.4 L 300.6,372.8 L 301.5,371.6 L 300.2,370.6 L 299.6,367.4 L 300.7,366.8 L 300.2,363.4 L 301.6,358.1 L 303.3,357.1 L 302.4,351.8 L 304.5,350.0 L 304.5,347.7 L 306.1,345.0 L 304.1,337.1 L 305.8,334.3 L 306.5,329.1 L 310.3,324.7 L 309.5,323.6 L 310.0,318.1 L 313.0,316.7 L 313.6,313.2 L 315.9,310.6 L 319.5,311.3 L 321.2,313.3 L 322.3,311.1 L 325.4,311.2 L 331.0,316.3 L 339.5,319.9 L 339.9,321.1 L 337.2,325.3 L 345.3,326.1 L 347.8,323.9 L 348.3,321.5 L 349.6,321.0 L 351.0,322.6 L 351.0,324.8 L 339.9,333.9 Z"/>
<path d="M 309.3,396.2 L 309.4,402.4 L 314.0,402.5 L 310.7,404.5 L 302.8,402.9 L 292.6,396.8 L 302.5,400.2 L 304.8,397.0 L 309.3,396.2 Z"/>
<path d="M 306.7,298.8 L 309.9,303.9 L 309.0,306.6 L 311.6,313.5 L 313.9,313.9 L 313.0,316.7 L 310.0,318.1 L 309.5,323.6 L 310.3,324.7 L 306.5,329.1 L 305.8,334.3 L 304.1,337.1 L 306.1,345.0 L 304.5,347.7 L 304.5,350.0 L 302.4,351.8 L 303.3,357.1 L 301.6,358.1 L 300.2,363.4 L 300.7,366.8 L 299.6,367.4 L 300.2,370.6 L 301.5,371.6 L 300.6,372.8 L 302.2,374.4 L 300.9,374.9 L 299.1,384.0 L 296.1,387.0 L 296.3,389.9 L 299.1,390.8 L 300.2,394.5 L 309.5,395.3 L 303.2,396.9 L 302.8,399.5 L 301.6,399.6 L 291.8,395.2 L 290.0,385.2 L 291.2,382.5 L 294.1,380.4 L 289.9,379.6 L 292.5,377.1 L 293.5,372.5 L 296.6,373.5 L 298.0,367.7 L 296.1,367.0 L 295.3,370.5 L 293.5,370.1 L 295.3,361.0 L 296.6,359.1 L 295.6,353.2 L 296.8,353.1 L 301.6,340.1 L 301.4,330.2 L 303.0,326.8 L 305.3,309.4 L 304.5,301.0 L 306.7,298.8 Z"/>
<path d="M 580.6,257.9 L 582.3,268.1 L 585.4,273.2 L 579.8,273.7 L 578.8,282.8 L 581.5,284.3 L 582.3,283.8 L 582.5,286.8 L 580.4,286.8 L 575.5,282.2 L 573.8,283.1 L 567.5,281.3 L 567.4,280.4 L 561.5,280.8 L 560.4,270.3 L 557.0,270.3 L 557.2,269.3 L 555.8,269.3 L 553.9,269.9 L 552.8,272.2 L 548.5,272.4 L 545.4,266.3 L 534.2,266.9 L 533.8,266.1 L 535.1,263.9 L 537.8,262.5 L 540.5,263.8 L 544.5,259.8 L 545.6,254.8 L 549.0,251.2 L 551.5,238.3 L 554.1,236.0 L 562.2,238.8 L 563.4,236.9 L 571.3,235.4 L 576.0,235.5 L 579.0,238.1 L 582.5,237.2 L 585.6,240.3 L 585.5,243.5 L 586.6,243.9 L 583.0,248.3 L 580.6,257.9 Z"/>
<path d="M 615.5,254.7 L 613.9,252.4 L 613.8,242.3 L 617.0,238.2 L 618.8,238.2 L 621.3,236.2 L 624.9,236.1 L 635.9,223.7 L 636.0,218.3 L 642.0,216.6 L 640.4,224.4 L 635.0,235.2 L 629.3,242.1 L 619.8,249.2 L 615.5,254.7 Z"/>
<path d="M 608.9,263.0 L 604.9,260.2 L 604.7,258.6 L 594.2,252.6 L 594.1,249.7 L 597.3,244.7 L 594.5,238.2 L 598.1,234.7 L 599.5,235.2 L 600.4,237.6 L 602.4,237.6 L 605.9,240.0 L 609.9,240.5 L 613.2,238.2 L 616.3,239.1 L 613.8,242.3 L 613.9,252.4 L 615.5,254.7 L 611.8,257.1 L 608.9,263.0 Z"/>
<path d="M 568.2,227.1 L 566.1,225.9 L 565.2,225.1 L 565.4,222.0 L 561.9,214.9 L 560.9,215.0 L 564.0,206.4 L 566.4,206.6 L 566.3,194.4 L 569.4,194.4 L 569.4,188.9 L 602.4,188.9 L 604.1,198.3 L 606.7,200.0 L 602.4,202.9 L 600.8,212.3 L 595.2,220.5 L 594.4,225.9 L 593.7,221.3 L 592.2,220.2 L 592.2,216.2 L 591.0,216.0 L 589.1,216.7 L 590.0,219.2 L 587.1,222.7 L 585.7,223.0 L 583.3,221.4 L 580.5,223.9 L 574.3,223.7 L 571.6,221.1 L 569.6,221.5 L 568.2,225.2 L 566.4,226.1 L 568.2,227.1 Z"/>
<path d="M 566.2,195.6 L 566.4,206.6 L 564.0,206.4 L 560.9,215.0 L 561.9,214.9 L 563.5,219.0 L 560.3,220.6 L 558.3,223.7 L 552.3,225.0 L 552.5,226.0 L 549.9,228.1 L 542.4,229.4 L 541.6,225.6 L 538.8,223.5 L 539.4,222.2 L 543.0,222.3 L 541.5,219.7 L 540.5,213.0 L 538.8,212.9 L 537.6,210.1 L 538.8,206.4 L 542.4,203.8 L 544.2,193.4 L 541.9,190.8 L 541.3,186.5 L 544.1,185.0 L 566.2,195.6 Z"/>
<path d="M 300.8,195.2 L 300.8,199.9 L 294.7,199.9 L 293.2,199.0 L 293.4,198.2 L 299.1,198.1 L 297.8,195.9 L 296.1,195.4 L 296.7,194.7 L 300.8,195.2 Z"/>
<path d="M 301.7,201.1 L 300.2,198.3 L 301.1,194.8 L 305.7,195.4 L 310.2,198.3 L 309.2,199.4 L 303.7,198.8 L 301.7,201.1 Z"/>
<path d="M 996.5,52.5 L 1000.0,51.3 L 1000.0,53.2 L 997.0,53.4 L 996.5,52.5 Z"/>
<path d="M 636.4,121.1 L 629.7,126.1 L 635.0,133.9 L 632.8,135.7 L 626.3,131.9 L 611.0,129.3 L 601.9,124.3 L 603.9,123.9 L 606.2,121.6 L 604.6,120.5 L 608.7,119.3 L 606.2,119.2 L 606.3,117.9 L 610.4,116.9 L 611.3,112.2 L 598.2,109.5 L 597.3,107.8 L 595.1,107.6 L 595.5,106.2 L 593.8,104.6 L 588.3,105.3 L 587.0,102.6 L 590.8,101.8 L 585.4,97.7 L 585.8,95.7 L 578.3,94.0 L 577.1,91.0 L 575.8,90.3 L 577.0,89.5 L 576.2,86.9 L 577.7,84.8 L 580.9,83.3 L 578.0,81.9 L 587.5,75.4 L 583.4,73.5 L 584.6,71.7 L 582.1,69.6 L 583.9,67.2 L 580.7,64.0 L 583.3,61.9 L 579.0,60.1 L 579.4,58.2 L 589.3,55.8 L 593.8,57.5 L 601.4,58.2 L 614.1,62.6 L 614.2,64.5 L 606.6,66.7 L 592.2,64.9 L 596.7,66.9 L 597.1,71.1 L 602.8,72.6 L 603.2,71.3 L 601.5,70.1 L 603.3,69.0 L 610.0,70.8 L 612.3,70.1 L 610.5,68.1 L 616.9,65.3 L 622.1,66.5 L 623.7,64.6 L 621.4,62.9 L 622.7,61.2 L 620.7,59.5 L 628.5,60.4 L 630.1,62.0 L 626.5,62.3 L 626.6,63.9 L 628.7,64.8 L 633.0,64.2 L 633.7,62.4 L 649.2,58.7 L 651.3,58.9 L 648.6,60.6 L 652.0,60.8 L 663.3,58.7 L 666.5,60.3 L 669.7,58.5 L 666.8,56.9 L 668.2,56.0 L 676.4,56.8 L 690.3,60.9 L 692.2,59.4 L 689.3,57.3 L 685.9,57.1 L 686.8,55.8 L 685.3,52.7 L 694.3,47.1 L 701.6,47.8 L 702.2,49.4 L 699.6,51.6 L 702.2,54.5 L 701.6,58.3 L 704.6,60.0 L 698.0,65.8 L 701.2,66.2 L 708.5,61.8 L 706.9,60.2 L 708.2,58.4 L 705.1,58.1 L 704.4,56.6 L 706.7,53.8 L 703.1,51.5 L 708.0,49.7 L 707.4,47.7 L 710.2,49.2 L 709.1,51.8 L 712.1,52.4 L 710.8,50.3 L 715.5,49.3 L 721.3,49.1 L 726.4,50.7 L 723.9,48.4 L 723.6,45.4 L 741.2,44.6 L 738.9,43.2 L 742.1,41.3 L 759.0,38.8 L 768.6,39.1 L 779.9,37.7 L 783.3,35.3 L 789.9,34.2 L 794.6,35.1 L 790.8,35.8 L 797.1,36.2 L 797.9,37.6 L 808.5,36.9 L 817.0,39.3 L 816.3,40.8 L 803.9,43.9 L 813.9,44.5 L 815.4,46.3 L 821.0,45.1 L 829.9,45.6 L 830.6,46.9 L 842.2,47.3 L 842.4,45.2 L 852.7,45.7 L 857.2,47.1 L 858.5,48.9 L 856.8,50.1 L 864.7,53.4 L 867.4,50.5 L 871.8,51.7 L 888.5,51.4 L 886.5,48.8 L 890.2,47.6 L 915.3,49.4 L 924.9,53.2 L 941.7,53.1 L 944.0,54.3 L 943.6,56.3 L 947.1,57.1 L 966.2,56.7 L 971.0,59.2 L 974.5,58.3 L 972.2,56.5 L 973.5,55.3 L 988.1,55.9 L 1000.0,58.4 L 1000.0,69.5 L 996.4,70.7 L 992.8,70.5 L 998.3,75.0 L 997.9,76.9 L 992.7,76.3 L 982.4,78.7 L 973.1,83.7 L 969.2,81.7 L 961.9,83.9 L 960.7,82.9 L 958.0,84.1 L 954.3,83.7 L 950.0,88.2 L 950.1,89.3 L 953.3,90.0 L 952.9,94.0 L 950.4,94.1 L 949.2,96.4 L 950.3,97.6 L 945.5,99.0 L 944.5,102.2 L 940.4,102.9 L 939.5,105.7 L 935.5,108.3 L 931.8,96.2 L 933.1,92.3 L 935.4,90.7 L 935.6,89.4 L 939.9,88.7 L 954.6,80.2 L 956.9,76.2 L 953.5,76.5 L 951.8,78.8 L 944.8,81.8 L 942.5,78.4 L 935.3,79.3 L 928.4,84.0 L 930.7,85.7 L 920.2,86.7 L 920.4,84.7 L 916.1,84.3 L 912.6,85.7 L 895.0,86.0 L 875.4,98.0 L 879.7,98.3 L 881.1,100.1 L 883.8,100.7 L 885.6,99.3 L 888.6,99.5 L 892.6,102.5 L 892.7,104.9 L 890.5,107.7 L 889.1,115.4 L 874.6,129.4 L 870.9,131.1 L 867.4,129.8 L 863.3,132.7 L 862.9,130.8 L 864.3,130.8 L 864.7,127.5 L 864.0,125.1 L 866.3,124.1 L 869.7,124.6 L 875.1,115.3 L 868.1,117.3 L 863.9,117.2 L 862.7,114.6 L 859.4,112.7 L 854.6,111.8 L 849.9,103.4 L 843.3,101.5 L 836.1,102.1 L 833.8,103.5 L 835.3,104.1 L 835.4,105.7 L 831.3,109.5 L 831.4,110.7 L 827.4,112.5 L 817.7,110.4 L 813.6,112.4 L 807.4,113.5 L 801.3,113.1 L 796.9,110.3 L 788.0,110.9 L 784.0,109.7 L 783.5,107.6 L 774.6,105.4 L 771.7,108.3 L 772.9,109.9 L 770.2,111.9 L 756.2,108.9 L 742.7,113.3 L 741.2,111.6 L 737.6,112.0 L 731.6,108.1 L 727.6,108.9 L 723.8,107.3 L 722.3,108.7 L 716.1,101.7 L 712.6,99.5 L 713.6,98.6 L 704.0,101.4 L 704.2,99.9 L 700.6,99.0 L 697.7,99.6 L 696.8,96.8 L 691.9,96.2 L 681.1,99.0 L 670.7,100.0 L 669.4,100.9 L 671.4,102.8 L 668.7,103.6 L 669.2,104.3 L 666.6,105.7 L 671.1,107.6 L 670.4,108.9 L 666.5,108.8 L 665.7,109.6 L 662.1,108.2 L 657.7,108.2 L 654.8,109.4 L 645.4,106.3 L 641.0,106.4 L 635.3,109.4 L 634.9,111.5 L 632.1,109.8 L 629.1,115.6 L 631.4,117.5 L 633.5,117.4 L 635.3,119.2 L 635.0,120.7 L 636.4,121.1 Z"/>
<path d="M 753.3,26.8 L 766.5,24.3 L 778.3,28.4 L 777.6,30.9 L 771.5,31.2 L 759.2,29.4 L 757.1,27.4 L 753.3,26.8 Z"/>
<path d="M 781.3,29.9 L 792.7,31.4 L 791.9,32.5 L 776.2,33.6 L 781.3,29.9 Z"/>
<path d="M 882.0,39.0 L 893.0,38.6 L 903.0,40.1 L 900.8,42.2 L 886.0,42.7 L 880.5,40.9 L 882.0,39.0 Z"/>
<path d="M 906.6,40.3 L 918.7,41.4 L 915.5,42.5 L 905.9,41.2 L 906.6,40.3 Z"/>
<path d="M 888.5,46.2 L 894.6,44.8 L 898.9,46.6 L 894.7,46.7 L 888.5,46.2 Z"/>
<path d="M 624.6,26.1 L 634.2,25.6 L 634.8,26.3 L 639.0,25.2 L 643.1,25.8 L 632.2,27.7 L 629.2,27.1 L 630.8,26.2 L 624.6,26.1 Z"/>
<path d="M 563.1,99.1 L 558.0,99.1 L 554.6,98.8 L 555.2,97.6 L 559.1,96.7 L 563.2,97.6 L 563.1,99.1 Z"/>
<path d="M 648.6,45.1 L 655.3,42.7 L 654.5,41.4 L 669.9,38.2 L 689.3,36.3 L 691.3,37.4 L 671.1,40.9 L 662.4,43.6 L 653.9,49.0 L 654.5,51.3 L 659.8,53.6 L 649.1,53.4 L 648.4,52.2 L 643.3,51.5 L 642.9,50.0 L 645.8,49.4 L 645.7,47.8 L 651.2,45.5 L 648.6,45.1 Z"/>
<path d="M 896.3,99.0 L 897.9,106.2 L 901.8,114.0 L 897.7,113.0 L 896.0,117.1 L 898.7,119.9 L 898.6,121.8 L 896.5,120.2 L 894.7,122.3 L 894.9,108.5 L 893.3,105.7 L 893.6,101.9 L 896.1,100.7 L 895.0,99.4 L 896.3,99.0 Z"/>
<path d="M 14.1,63.3 L 13.8,65.0 L 15.7,65.7 L 15.1,63.7 L 22.6,64.1 L 28.1,66.7 L 20.7,68.2 L 20.7,70.9 L 19.6,71.5 L 11.2,69.7 L 10.5,68.5 L 4.6,68.4 L 3.0,67.4 L 3.6,66.4 L 0.3,67.0 L 1.6,68.3 L 0.0,69.5 L 0.0,58.4 L 14.1,63.3 Z"/>
<path d="M 6.7,52.0 L 0.0,53.2 L 0.0,51.3 L 6.7,52.0 Z"/>
<path d="M 590.2,124.1 L 593.6,121.6 L 598.6,123.9 L 601.5,123.7 L 600.9,124.7 L 594.1,126.8 L 592.6,126.2 L 593.2,124.9 L 590.2,124.1 Z"/>
<path d="M 280.6,175.6 L 283.8,175.4 L 283.8,176.2 L 280.8,176.6 L 280.6,175.6 Z"/>
<path d="M 283.9,174.9 L 286.1,176.1 L 285.6,178.1 L 285.2,176.3 L 283.9,174.9 Z"/>
<path d="M 282.8,180.0 L 283.6,180.1 L 284.6,184.0 L 282.2,181.7 L 282.8,180.0 Z"/>
<path d="M 330.0,394.0 L 333.3,392.4 L 335.7,393.1 L 337.4,391.9 L 339.6,393.2 L 335.0,395.0 L 333.8,394.0 L 331.4,395.3 L 330.0,394.0 Z"/>
<path d="M 542.1,28.7 L 543.1,27.7 L 547.2,27.6 L 559.8,30.7 L 552.9,31.8 L 551.3,33.8 L 548.9,34.3 L 547.6,36.6 L 544.2,36.7 L 538.2,35.1 L 540.7,34.1 L 531.2,30.9 L 529.0,28.7 L 536.6,27.7 L 538.1,28.7 L 542.1,28.7 Z"/>
<path d="M 586.4,56.8 L 579.4,58.2 L 580.6,56.2 L 577.0,55.1 L 572.7,56.0 L 571.4,58.1 L 568.7,59.3 L 562.1,58.8 L 559.0,57.3 L 555.6,58.2 L 555.2,60.0 L 550.0,59.5 L 549.2,61.1 L 546.6,61.1 L 537.7,70.0 L 538.7,71.0 L 537.7,72.1 L 534.9,72.0 L 533.1,74.6 L 533.3,78.3 L 535.1,79.7 L 534.2,83.0 L 530.6,86.5 L 528.8,84.8 L 523.3,88.0 L 519.6,88.7 L 515.7,87.3 L 513.9,77.9 L 529.2,70.9 L 541.0,61.6 L 553.3,56.1 L 564.0,55.0 L 568.2,52.7 L 578.2,52.3 L 586.9,54.3 L 583.3,55.0 L 586.4,56.8 Z"/>
<path d="M 576.1,27.6 L 572.0,29.1 L 564.0,29.4 L 555.8,29.0 L 548.2,26.9 L 563.7,26.0 L 576.1,27.6 Z"/>
<path d="M 568.7,33.7 L 562.5,34.9 L 557.6,34.2 L 559.5,33.5 L 557.8,32.6 L 563.6,32.1 L 568.7,33.7 Z"/>
<path d="M 370.1,20.5 L 392.7,17.9 L 424.7,18.0 L 442.1,20.2 L 437.0,21.3 L 411.4,21.7 L 431.0,22.8 L 436.4,22.0 L 438.7,23.0 L 435.6,24.6 L 456.2,22.5 L 464.5,23.0 L 466.1,24.2 L 453.2,26.8 L 444.3,27.3 L 450.7,27.4 L 445.3,31.2 L 445.4,34.3 L 448.7,36.2 L 439.8,37.1 L 444.9,38.6 L 445.6,41.0 L 442.6,41.2 L 446.2,43.6 L 440.0,43.8 L 443.2,45.0 L 442.3,45.9 L 434.5,46.4 L 438.0,48.3 L 438.1,49.5 L 432.6,48.3 L 431.1,49.1 L 438.5,51.5 L 439.6,53.7 L 434.6,54.2 L 429.0,51.6 L 430.0,53.5 L 426.8,54.9 L 437.9,55.2 L 422.9,59.8 L 411.7,60.8 L 405.0,64.8 L 389.4,68.2 L 387.0,69.9 L 385.6,73.7 L 381.1,75.9 L 382.2,78.1 L 379.5,83.1 L 375.6,83.2 L 371.5,81.0 L 365.9,80.9 L 356.6,73.3 L 354.8,69.0 L 350.9,66.4 L 351.9,64.3 L 350.1,63.4 L 352.8,60.1 L 357.0,59.1 L 358.7,55.8 L 351.5,57.5 L 348.1,56.6 L 349.0,53.3 L 357.2,54.0 L 350.0,51.3 L 344.9,51.0 L 348.0,48.4 L 340.8,42.5 L 337.2,41.4 L 337.3,40.2 L 329.8,38.6 L 309.7,38.7 L 301.7,36.1 L 314.5,35.1 L 296.4,33.2 L 296.8,32.1 L 317.5,29.5 L 318.5,28.4 L 311.0,27.5 L 327.1,24.1 L 326.0,22.9 L 341.1,21.7 L 352.7,22.5 L 360.0,21.0 L 376.3,23.2 L 369.7,21.7 L 370.1,20.5 Z"/>
<path d="M 691.5,385.1 L 695.9,386.3 L 696.0,386.8 L 695.2,388.1 L 691.0,388.3 L 691.5,385.1 Z"/>
<path d="M 847.1,274.7 L 849.9,273.4 L 853.7,273.3 L 847.5,276.1 L 847.1,274.7 Z"/>
<path d="M 545.4,329.4 L 546.7,328.0 L 548.3,330.0 L 551.3,330.7 L 555.3,329.1 L 555.3,318.8 L 557.7,321.9 L 558.0,324.5 L 560.0,324.2 L 564.8,320.2 L 567.3,321.3 L 571.3,320.8 L 572.1,318.6 L 573.6,318.4 L 575.3,315.5 L 581.8,311.4 L 586.6,311.8 L 588.7,317.7 L 588.4,321.8 L 586.2,321.5 L 585.2,324.3 L 586.9,325.8 L 589.1,324.3 L 591.2,324.3 L 589.5,329.9 L 578.4,341.0 L 571.6,344.3 L 562.7,344.1 L 555.8,346.7 L 551.0,344.8 L 549.8,340.6 L 550.7,340.1 L 550.6,337.9 L 545.4,329.4 Z"/>
<path d="M 579.3,329.6 L 581.5,331.3 L 578.1,334.8 L 577.1,335.1 L 575.0,333.0 L 578.0,330.1 L 579.3,329.6 Z"/>
<path d="M 174.6,159.6 L 181.3,159.1 L 191.6,163.0 L 199.3,162.9 L 199.3,161.8 L 204.1,161.8 L 211.3,168.7 L 213.6,169.5 L 215.3,167.3 L 217.6,167.3 L 223.6,173.5 L 224.9,176.7 L 230.2,178.1 L 228.1,187.7 L 230.0,192.7 L 233.6,197.7 L 237.7,199.6 L 246.1,197.6 L 247.9,196.4 L 249.2,191.7 L 258.2,190.2 L 258.8,192.1 L 256.6,195.4 L 256.0,199.3 L 254.2,198.6 L 253.2,200.3 L 247.2,200.5 L 247.2,202.1 L 246.0,202.1 L 248.7,205.4 L 245.1,205.4 L 243.8,209.6 L 239.2,205.7 L 237.0,205.0 L 231.8,206.5 L 212.5,199.2 L 207.0,194.6 L 206.3,193.2 L 207.2,193.0 L 207.6,190.5 L 205.5,186.7 L 198.9,180.1 L 196.5,178.9 L 196.4,176.5 L 193.4,174.5 L 192.7,172.6 L 188.3,169.6 L 185.7,163.4 L 181.2,161.7 L 180.7,162.8 L 181.5,166.2 L 190.0,175.9 L 192.6,182.5 L 194.0,182.6 L 196.1,185.1 L 194.8,186.6 L 188.4,181.3 L 188.1,177.7 L 180.4,173.0 L 181.7,172.9 L 182.9,170.6 L 179.1,167.9 L 174.6,159.6 Z"/>
<path d="M 339.9,333.9 L 341.7,333.6 L 350.6,339.0 L 352.2,340.9 L 351.0,342.2 L 351.7,343.8 L 350.5,345.5 L 347.4,347.1 L 343.8,346.8 L 339.4,345.7 L 337.7,344.2 L 339.9,333.9 Z"/>
<path d="M 351.7,343.8 L 351.0,342.2 L 352.2,340.9 L 350.6,339.0 L 341.7,333.6 L 339.9,333.9 L 351.0,324.8 L 351.0,322.6 L 349.6,321.0 L 348.3,321.5 L 349.2,316.7 L 346.1,316.5 L 345.0,312.1 L 339.1,311.4 L 338.4,306.0 L 340.3,300.5 L 338.1,298.0 L 338.2,295.3 L 332.9,295.2 L 331.9,288.3 L 321.3,284.6 L 318.3,282.1 L 318.5,277.1 L 314.9,277.6 L 310.4,280.6 L 304.0,280.6 L 304.2,276.4 L 301.9,278.0 L 299.5,277.9 L 298.4,276.4 L 296.6,276.3 L 297.2,275.1 L 294.5,270.9 L 296.9,268.4 L 297.5,264.7 L 303.3,261.8 L 305.9,261.9 L 307.2,253.1 L 305.5,248.5 L 307.6,248.3 L 307.7,247.3 L 306.1,247.0 L 306.1,245.2 L 311.5,245.3 L 312.4,244.3 L 313.7,246.9 L 317.9,247.8 L 324.0,243.9 L 321.5,243.1 L 321.2,239.5 L 320.0,238.7 L 324.7,239.5 L 330.6,237.4 L 331.3,235.6 L 333.4,236.1 L 333.0,237.3 L 334.6,239.0 L 333.4,242.3 L 334.3,245.0 L 336.0,246.3 L 340.7,244.6 L 344.5,245.0 L 344.5,243.0 L 352.9,244.1 L 357.5,238.3 L 359.7,244.7 L 361.2,245.2 L 361.3,247.1 L 359.2,249.4 L 360.0,250.2 L 364.9,250.7 L 365.0,253.4 L 367.2,251.6 L 375.3,254.3 L 376.6,255.9 L 376.2,257.5 L 379.4,256.6 L 388.9,258.0 L 396.6,263.4 L 401.1,264.3 L 403.5,270.4 L 402.4,275.0 L 392.6,286.3 L 390.9,299.6 L 386.3,310.9 L 384.0,312.1 L 383.4,313.8 L 376.0,314.9 L 367.6,319.1 L 365.3,321.9 L 364.2,329.7 L 351.7,343.8 Z"/>
<path d="M 306.9,280.4 L 310.4,280.6 L 314.9,277.6 L 318.5,277.1 L 318.3,282.1 L 321.3,284.6 L 331.9,288.3 L 332.9,295.2 L 338.2,295.3 L 338.1,298.0 L 340.3,300.5 L 339.3,305.5 L 338.4,306.0 L 335.8,303.8 L 328.4,304.5 L 325.9,311.8 L 322.3,311.1 L 321.2,313.3 L 319.5,311.3 L 315.9,310.6 L 313.6,313.2 L 311.6,313.5 L 309.0,306.6 L 309.9,303.9 L 306.7,298.8 L 308.4,295.8 L 307.4,291.5 L 309.3,284.9 L 306.9,280.4 Z"/>
<path d="M 305.9,261.9 L 303.3,261.8 L 297.5,264.7 L 296.9,268.4 L 294.5,270.9 L 297.2,275.1 L 296.6,276.3 L 298.4,276.4 L 299.5,277.9 L 301.9,278.0 L 304.2,276.4 L 304.0,280.6 L 306.9,280.4 L 309.3,284.9 L 307.4,291.5 L 308.4,295.8 L 305.9,300.3 L 304.5,301.0 L 288.9,290.7 L 288.2,287.6 L 278.4,270.0 L 274.3,267.0 L 275.2,265.8 L 273.9,263.2 L 276.9,259.5 L 276.5,262.3 L 278.8,262.4 L 280.0,263.8 L 281.6,262.6 L 283.8,258.3 L 287.1,257.2 L 290.2,254.3 L 291.4,250.2 L 295.4,253.5 L 297.0,256.4 L 303.3,256.3 L 305.4,257.6 L 303.6,260.4 L 305.9,261.9 Z"/>
<path d="M 314.2,246.5 L 312.4,244.3 L 311.5,245.3 L 306.1,245.2 L 306.1,247.0 L 307.7,247.3 L 307.6,248.3 L 305.5,248.5 L 307.2,253.1 L 305.9,261.9 L 303.6,260.4 L 305.4,257.6 L 303.3,256.3 L 297.0,256.4 L 295.4,253.5 L 291.4,250.2 L 284.9,248.9 L 280.6,245.3 L 285.8,239.3 L 284.7,238.6 L 285.2,233.8 L 283.7,229.9 L 285.4,228.0 L 284.8,226.3 L 289.8,223.8 L 290.3,220.5 L 291.9,219.2 L 296.1,218.8 L 301.7,215.6 L 301.9,217.3 L 300.1,217.8 L 297.5,221.0 L 296.4,224.6 L 297.8,224.8 L 298.8,229.4 L 300.1,230.6 L 305.3,230.7 L 307.3,233.1 L 312.9,233.1 L 311.6,237.5 L 313.0,240.8 L 311.6,242.2 L 314.2,246.5 Z"/>
<path d="M 285.1,225.9 L 285.4,228.0 L 283.7,229.9 L 282.1,227.6 L 282.8,226.9 L 280.2,225.0 L 276.7,226.9 L 277.8,229.0 L 275.3,229.9 L 274.8,228.3 L 273.6,228.6 L 273.0,227.5 L 269.9,227.6 L 269.6,223.7 L 273.8,225.6 L 280.5,223.5 L 285.1,225.9 Z"/>
<path d="M 270.7,223.4 L 269.6,223.7 L 269.5,227.2 L 264.0,222.0 L 263.6,223.5 L 262.1,222.4 L 261.3,219.7 L 262.3,218.8 L 267.6,219.6 L 270.7,223.4 Z"/>
<path d="M 267.6,219.6 L 261.9,219.2 L 256.5,214.1 L 259.1,213.2 L 259.0,211.8 L 261.7,211.6 L 264.1,208.9 L 269.0,208.3 L 267.1,218.4 L 267.6,219.6 Z"/>
<path d="M 269.0,208.3 L 264.1,208.9 L 261.7,211.6 L 259.0,211.8 L 259.1,213.2 L 257.5,213.9 L 255.9,211.4 L 254.2,211.5 L 251.8,209.9 L 252.3,208.1 L 255.8,205.9 L 263.9,205.6 L 269.0,208.3 Z"/>
<path d="M 251.8,209.9 L 256.3,211.7 L 255.8,213.5 L 249.7,211.8 L 251.8,209.9 Z"/>
<path d="M 243.8,209.6 L 245.1,205.4 L 248.7,205.4 L 246.0,202.1 L 247.2,202.1 L 247.2,200.5 L 252.4,200.5 L 252.1,205.9 L 254.9,206.3 L 252.3,208.1 L 251.8,209.9 L 249.7,211.8 L 243.8,209.6 Z"/>
<path d="M 252.4,200.5 L 254.2,198.6 L 255.3,199.0 L 254.6,204.1 L 253.0,205.9 L 252.1,205.9 L 252.4,200.5 Z"/>
<path d="M 331.3,235.6 L 330.6,237.4 L 324.7,239.5 L 320.0,238.7 L 321.2,239.5 L 321.5,243.1 L 324.0,243.9 L 317.9,247.8 L 315.8,248.0 L 311.6,242.2 L 313.0,240.8 L 311.6,237.5 L 312.9,233.1 L 307.3,233.1 L 305.3,230.7 L 300.1,230.6 L 298.8,229.4 L 297.8,224.8 L 296.4,224.6 L 297.5,221.0 L 300.1,217.8 L 301.9,217.3 L 300.1,218.3 L 301.0,221.0 L 299.8,222.6 L 300.8,224.8 L 302.0,224.6 L 302.7,222.6 L 301.7,219.5 L 305.1,218.4 L 304.7,217.1 L 305.7,216.2 L 306.7,218.2 L 308.7,218.2 L 310.6,220.7 L 316.0,220.4 L 319.7,222.0 L 321.3,220.4 L 328.1,220.2 L 325.7,221.1 L 326.7,222.4 L 331.0,223.9 L 331.5,226.2 L 334.0,226.8 L 331.8,228.4 L 332.5,230.4 L 330.1,231.4 L 329.4,233.4 L 331.3,235.6 Z"/>
<path d="M 342.9,244.7 L 340.7,244.6 L 337.4,246.5 L 334.3,245.0 L 333.4,242.3 L 334.6,239.0 L 333.0,237.3 L 333.4,236.1 L 331.3,235.6 L 329.4,233.4 L 330.1,231.4 L 332.5,230.4 L 331.8,228.4 L 334.0,226.8 L 341.3,233.4 L 338.8,238.7 L 342.9,244.7 Z"/>
<path d="M 348.5,243.6 L 344.5,243.0 L 344.5,245.0 L 342.9,244.7 L 340.9,240.7 L 340.0,240.7 L 338.8,238.7 L 341.3,233.4 L 350.1,234.0 L 348.7,236.4 L 350.0,239.9 L 348.5,243.6 Z"/>
<path d="M 356.5,238.5 L 352.9,244.1 L 348.5,243.6 L 350.0,239.9 L 348.7,236.4 L 350.1,234.0 L 353.1,235.0 L 356.5,238.5 Z"/>
<path d="M 511.9,111.4 L 522.5,113.8 L 520.7,117.7 L 518.7,117.9 L 516.8,120.2 L 516.7,121.5 L 518.1,121.0 L 519.0,122.2 L 519.7,124.1 L 518.7,124.9 L 519.5,127.1 L 521.0,127.4 L 520.7,128.6 L 518.1,130.2 L 512.7,129.4 L 508.6,130.3 L 508.3,132.0 L 505.1,132.4 L 495.8,130.5 L 494.7,129.4 L 496.2,127.7 L 496.7,122.2 L 491.8,117.9 L 487.5,116.8 L 487.2,114.8 L 495.5,114.9 L 494.6,111.7 L 497.3,112.9 L 503.7,110.8 L 504.6,108.5 L 507.0,107.9 L 511.9,111.4 Z"/>
<path d="M 524.3,131.6 L 526.1,130.5 L 526.6,132.9 L 525.6,135.1 L 524.4,134.5 L 524.3,131.6 Z"/>
<path d="M 290.6,250.4 L 290.2,254.3 L 287.1,257.2 L 283.8,258.3 L 281.6,262.6 L 280.0,263.8 L 278.8,262.4 L 276.5,262.3 L 278.4,257.4 L 277.8,256.2 L 276.8,257.5 L 275.1,256.2 L 275.2,252.9 L 276.2,252.5 L 277.5,247.9 L 281.0,246.2 L 284.9,248.9 L 288.1,248.8 L 290.6,250.4 Z"/>
<path d="M 313.6,198.6 L 317.8,199.4 L 313.4,200.1 L 313.6,198.6 Z"/>
<path d="M 282.4,199.4 L 286.4,198.9 L 288.3,200.3 L 285.5,200.8 L 282.4,199.4 Z"/>
<path d="M 267.3,186.7 L 276.1,185.8 L 279.8,187.8 L 282.4,187.5 L 287.4,191.1 L 290.0,191.6 L 289.8,192.4 L 293.9,193.7 L 291.8,194.7 L 284.0,194.8 L 285.9,193.3 L 283.0,192.4 L 281.3,190.0 L 271.8,187.8 L 272.8,187.1 L 270.1,187.0 L 266.5,189.1 L 264.0,189.2 L 267.3,186.7 Z"/>
<path d="M 586.6,311.8 L 581.8,311.4 L 577.8,309.7 L 577.0,306.9 L 572.7,303.6 L 570.2,299.3 L 575.1,299.8 L 580.4,294.6 L 584.1,293.1 L 584.3,294.1 L 586.6,294.1 L 591.2,296.4 L 590.7,306.4 L 586.6,311.8 Z"/>
<path d="M 581.8,311.4 L 575.3,315.5 L 573.6,318.4 L 572.1,318.6 L 571.3,320.8 L 567.3,321.3 L 564.8,320.2 L 560.0,324.2 L 558.0,324.5 L 557.7,321.9 L 555.3,318.8 L 555.3,310.7 L 558.0,310.6 L 558.1,300.7 L 564.4,299.6 L 565.5,300.8 L 570.2,299.3 L 572.7,303.6 L 577.0,306.9 L 577.8,309.7 L 581.8,311.4 Z"/>
<path d="M 555.3,310.7 L 555.3,329.1 L 551.3,330.7 L 548.3,330.0 L 546.7,328.0 L 545.4,329.4 L 542.3,325.3 L 539.6,311.4 L 532.8,300.2 L 532.6,298.1 L 537.4,297.1 L 539.1,298.4 L 550.7,298.1 L 552.7,299.4 L 559.4,299.8 L 566.8,298.0 L 569.7,298.8 L 565.5,300.8 L 564.4,299.6 L 558.1,300.7 L 558.0,310.6 L 555.3,310.7 Z"/>
<path d="M 453.6,212.2 L 451.0,209.1 L 455.2,204.3 L 459.5,203.9 L 462.7,205.4 L 466.2,209.4 L 468.0,215.4 L 453.7,215.6 L 453.2,213.5 L 461.5,212.5 L 458.1,211.5 L 453.6,212.2 Z"/>
<path d="M 468.2,216.5 L 466.2,209.4 L 467.6,207.3 L 470.4,208.0 L 473.5,207.0 L 484.6,206.9 L 485.2,205.0 L 482.1,180.7 L 486.3,180.6 L 508.7,195.3 L 508.8,197.1 L 511.9,196.8 L 511.9,203.2 L 510.1,206.8 L 503.8,207.4 L 502.8,208.4 L 497.0,208.4 L 491.4,212.4 L 488.9,212.6 L 485.5,217.5 L 485.0,221.2 L 477.7,221.6 L 474.6,215.8 L 471.8,217.1 L 468.2,216.5 Z"/>
<path d="M 452.6,191.7 L 453.2,190.7 L 464.1,190.8 L 464.2,185.3 L 466.8,185.1 L 466.8,178.0 L 475.9,178.1 L 475.9,173.9 L 486.3,180.6 L 482.1,180.7 L 485.2,205.0 L 484.6,206.9 L 473.5,207.0 L 470.4,208.0 L 467.6,207.3 L 466.2,209.4 L 462.7,205.4 L 459.5,203.9 L 454.3,205.2 L 454.8,194.2 L 452.6,191.7 Z"/>
<path d="M 507.5,232.6 L 505.2,232.9 L 504.6,224.6 L 502.1,220.9 L 504.0,217.9 L 507.9,216.0 L 510.0,217.6 L 510.5,220.2 L 507.6,226.4 L 507.5,232.6 Z"/>
<path d="M 541.3,186.5 L 541.9,190.8 L 544.2,193.4 L 542.4,203.8 L 538.8,206.4 L 537.6,210.1 L 538.8,212.9 L 540.5,213.0 L 539.4,215.3 L 536.3,212.2 L 534.2,213.8 L 530.5,212.8 L 525.0,214.4 L 521.7,212.9 L 518.9,213.6 L 515.1,211.5 L 511.4,212.4 L 510.0,217.6 L 507.9,216.0 L 506.0,216.8 L 506.0,214.9 L 502.8,214.3 L 501.0,208.5 L 510.1,206.8 L 511.9,203.2 L 511.9,196.8 L 515.8,195.6 L 533.3,184.8 L 537.7,186.0 L 539.3,187.5 L 541.3,186.5 Z"/>
<path d="M 507.5,232.6 L 507.6,226.4 L 510.3,222.0 L 510.2,215.1 L 512.1,211.8 L 515.1,211.5 L 518.9,213.6 L 521.7,212.9 L 525.0,214.4 L 530.5,212.8 L 534.2,213.8 L 536.3,212.2 L 540.5,216.4 L 537.7,220.0 L 532.6,230.6 L 530.7,231.5 L 528.1,230.4 L 525.6,232.1 L 523.6,236.7 L 516.4,238.2 L 512.0,232.6 L 507.5,232.6 Z"/>
<path d="M 540.3,214.3 L 543.0,222.3 L 539.4,222.2 L 538.8,223.5 L 541.6,225.6 L 542.9,228.6 L 540.4,232.7 L 540.2,236.9 L 544.1,241.6 L 544.3,245.2 L 539.8,243.8 L 526.8,243.7 L 527.2,241.5 L 523.6,237.5 L 524.3,234.8 L 525.6,232.1 L 528.1,230.4 L 530.7,231.5 L 532.6,230.6 L 537.7,220.0 L 540.0,217.9 L 540.5,216.4 L 539.4,215.3 L 540.3,214.3 Z"/>
<path d="M 502.5,219.5 L 502.1,220.9 L 504.6,224.6 L 505.2,232.9 L 502.9,233.5 L 501.6,230.8 L 501.0,221.7 L 499.9,220.3 L 500.1,219.4 L 502.5,219.5 Z"/>
<path d="M 500.1,219.4 L 502.0,226.9 L 501.6,230.8 L 502.9,233.5 L 494.5,236.9 L 492.1,236.1 L 491.0,232.6 L 492.9,227.2 L 491.8,219.5 L 500.1,219.4 Z"/>
<path d="M 477.7,221.6 L 481.0,221.8 L 482.8,220.8 L 483.2,222.0 L 485.0,221.2 L 488.0,223.3 L 490.2,222.5 L 492.1,223.2 L 492.9,227.2 L 491.0,232.6 L 492.1,236.1 L 487.1,235.6 L 478.6,237.9 L 479.0,234.1 L 476.1,232.0 L 476.9,226.9 L 478.2,226.2 L 476.9,222.8 L 477.7,221.6 Z"/>
<path d="M 461.9,215.0 L 468.0,215.4 L 468.2,216.5 L 471.8,217.1 L 474.6,215.8 L 477.7,221.6 L 476.9,222.8 L 478.2,226.2 L 476.9,226.9 L 477.0,228.6 L 474.4,229.7 L 472.9,226.3 L 470.8,226.8 L 469.1,222.1 L 465.5,222.7 L 463.2,225.3 L 458.0,219.3 L 461.8,217.2 L 461.9,215.0 Z"/>
<path d="M 453.7,215.6 L 461.9,215.0 L 461.8,217.2 L 458.0,219.3 L 455.3,218.0 L 453.7,215.6 Z"/>
<path d="M 476.6,228.6 L 476.1,232.0 L 479.0,234.1 L 478.6,237.9 L 475.0,236.6 L 468.2,231.2 L 471.6,226.6 L 472.9,226.3 L 474.4,229.7 L 476.6,228.6 Z"/>
<path d="M 463.2,225.3 L 465.5,222.7 L 469.1,222.1 L 470.8,226.8 L 471.6,226.6 L 468.2,231.2 L 464.0,228.3 L 463.2,225.3 Z"/>
<path d="M 485.0,221.2 L 485.5,217.5 L 488.1,213.3 L 491.4,212.4 L 497.0,208.4 L 501.0,208.5 L 502.8,214.3 L 506.0,214.9 L 505.4,217.7 L 502.5,219.5 L 491.8,219.5 L 492.1,223.2 L 490.2,222.5 L 488.0,223.3 L 485.0,221.2 Z"/>
<path d="M 576.0,235.5 L 567.8,235.8 L 563.4,236.9 L 562.2,238.8 L 554.1,236.0 L 551.5,238.3 L 551.3,240.3 L 547.6,239.6 L 544.5,243.7 L 544.1,241.6 L 540.2,236.9 L 540.2,234.9 L 542.4,229.4 L 549.9,228.1 L 552.5,226.0 L 552.3,225.0 L 558.3,223.7 L 560.3,220.6 L 563.5,219.0 L 565.4,222.0 L 565.2,225.1 L 569.8,228.3 L 576.0,235.5 Z"/>
<path d="M 551.3,240.3 L 549.0,251.2 L 545.6,254.8 L 544.5,259.8 L 540.5,263.8 L 539.3,262.5 L 536.8,263.6 L 535.1,262.3 L 533.1,264.0 L 530.8,261.1 L 532.9,259.5 L 531.9,257.7 L 534.7,256.6 L 534.9,255.4 L 536.4,256.7 L 538.9,256.9 L 540.1,253.7 L 538.5,249.9 L 539.7,246.7 L 536.9,246.3 L 536.3,243.7 L 544.3,245.2 L 547.6,239.6 L 551.3,240.3 Z"/>
<path d="M 531.3,243.7 L 536.0,243.6 L 536.9,246.3 L 539.7,246.7 L 538.5,249.9 L 540.1,253.7 L 538.9,256.9 L 536.4,256.7 L 534.9,255.4 L 534.7,256.6 L 531.9,257.7 L 532.9,259.5 L 530.8,261.1 L 524.4,253.1 L 526.4,247.2 L 531.3,247.1 L 531.3,243.7 Z"/>
<path d="M 526.8,243.7 L 531.3,243.7 L 531.3,247.1 L 526.4,247.2 L 526.8,243.7 Z"/>
<path d="M 585.4,273.2 L 592.3,276.9 L 592.5,284.5 L 590.8,288.1 L 592.3,288.8 L 583.8,291.1 L 584.1,293.1 L 580.4,294.6 L 575.1,299.8 L 568.6,298.2 L 564.5,298.7 L 560.8,294.7 L 560.9,285.8 L 566.7,285.9 L 566.4,280.4 L 570.6,281.5 L 571.5,282.7 L 575.5,282.2 L 580.4,286.8 L 582.5,286.8 L 582.3,283.8 L 581.5,284.3 L 578.8,282.8 L 579.0,275.5 L 580.6,273.4 L 585.4,273.2 Z"/>
<path d="M 591.0,275.6 L 593.7,276.2 L 595.2,278.2 L 596.0,287.7 L 598.0,288.6 L 599.1,290.6 L 599.4,294.2 L 597.3,296.7 L 595.5,295.0 L 595.7,290.6 L 590.8,288.1 L 592.5,284.5 L 592.0,282.2 L 593.0,279.2 L 591.0,275.6 Z"/>
<path d="M 596.0,282.0 L 604.1,282.1 L 612.0,278.7 L 613.3,290.8 L 609.6,296.4 L 603.9,298.9 L 596.6,305.0 L 596.4,306.9 L 598.8,311.4 L 598.5,317.0 L 591.7,320.4 L 590.5,321.5 L 591.2,324.3 L 589.1,324.3 L 588.7,317.7 L 586.6,311.8 L 590.7,306.4 L 591.2,296.4 L 586.6,294.1 L 584.3,294.1 L 583.8,291.1 L 592.3,288.8 L 595.7,290.6 L 595.5,295.0 L 597.3,296.7 L 599.4,294.2 L 599.1,290.6 L 598.0,288.6 L 596.0,287.7 L 595.2,284.1 L 596.0,282.0 Z"/>
<path d="M 589.1,324.3 L 586.9,325.8 L 585.2,324.3 L 586.2,321.5 L 588.4,321.8 L 589.1,324.3 Z"/>
<path d="M 536.1,263.3 L 535.1,263.9 L 533.8,266.1 L 533.1,264.0 L 535.1,262.3 L 536.1,263.3 Z"/>
<path d="M 534.2,266.9 L 545.4,266.3 L 548.5,272.4 L 552.8,272.2 L 553.9,269.9 L 555.8,269.3 L 557.2,269.3 L 557.0,270.3 L 560.4,270.3 L 561.5,280.8 L 565.2,280.2 L 566.7,281.2 L 566.7,285.9 L 560.9,285.8 L 560.8,294.7 L 564.5,298.7 L 559.4,299.8 L 552.7,299.4 L 550.7,298.1 L 539.1,298.4 L 537.4,297.1 L 532.6,298.1 L 533.8,290.1 L 538.2,281.4 L 535.8,275.5 L 536.8,273.8 L 534.2,266.9 Z"/>
<path d="M 584.6,256.7 L 585.4,259.3 L 581.5,262.5 L 580.6,257.9 L 584.6,256.7 Z"/>
<path d="M 599.2,159.1 L 597.7,159.6 L 597.2,161.5 L 597.8,161.8 L 597.0,162.9 L 598.3,162.5 L 598.4,163.6 L 597.0,168.1 L 595.2,163.3 L 597.5,158.1 L 599.5,157.6 L 599.2,159.1 Z"/>
<path d="M 599.5,157.6 L 597.6,158.1 L 600.0,153.8 L 601.2,153.9 L 601.7,155.0 L 599.5,157.6 Z"/>
<path d="M 636.7,283.4 L 639.9,293.6 L 639.4,294.4 L 638.5,292.8 L 638.0,293.6 L 638.3,296.9 L 630.8,319.3 L 626.1,321.1 L 622.3,319.4 L 620.4,313.3 L 620.6,309.3 L 621.9,308.8 L 623.5,304.0 L 622.1,298.4 L 623.5,295.0 L 628.6,293.8 L 632.5,290.5 L 633.0,288.0 L 634.1,288.3 L 636.7,283.4 Z"/>
<path d="M 598.3,162.5 L 597.0,162.9 L 597.7,159.6 L 598.7,160.0 L 598.3,162.5 Z"/>
<path d="M 453.6,212.2 L 458.1,211.5 L 461.5,212.5 L 453.2,213.5 L 453.6,212.2 Z"/>
<path d="M 526.3,165.8 L 525.2,160.8 L 521.1,157.4 L 520.9,155.3 L 522.6,153.7 L 523.4,147.4 L 526.4,146.3 L 528.4,146.6 L 528.3,148.0 L 530.6,147.0 L 529.4,148.9 L 530.0,153.2 L 528.2,154.6 L 528.7,156.2 L 531.9,158.0 L 531.8,160.1 L 527.6,162.8 L 527.7,165.2 L 526.3,165.8 Z"/>
<path d="M 475.9,173.9 L 475.9,169.9 L 485.4,166.7 L 489.7,164.2 L 489.9,162.1 L 496.4,160.4 L 496.9,159.3 L 494.0,152.3 L 496.6,150.8 L 504.1,148.3 L 514.8,148.0 L 517.4,146.9 L 523.4,147.4 L 522.6,153.7 L 520.9,155.3 L 521.1,157.4 L 525.2,160.8 L 527.2,168.3 L 527.0,176.4 L 525.9,177.5 L 528.6,182.3 L 529.9,181.8 L 533.3,184.8 L 515.8,195.6 L 508.8,197.1 L 508.7,195.3 L 475.9,173.9 Z"/>
<path d="M 597.0,168.1 L 599.2,159.1 L 602.3,160.2 L 607.8,157.3 L 608.9,160.7 L 602.8,162.5 L 605.6,165.3 L 600.2,168.9 L 597.0,168.1 Z"/>
<path d="M 643.3,182.7 L 650.0,183.0 L 655.8,177.6 L 656.3,178.6 L 656.7,180.8 L 655.2,180.8 L 655.5,183.0 L 654.2,183.5 L 652.8,187.5 L 644.4,186.1 L 643.3,182.7 Z"/>
<path d="M 641.1,181.2 L 641.0,179.2 L 642.5,177.5 L 643.4,180.0 L 642.7,181.6 L 641.1,181.2 Z"/>
<path d="M 633.3,166.7 L 634.5,170.7 L 629.4,169.2 L 631.4,166.5 L 633.3,166.7 Z"/>
<path d="M 608.9,160.7 L 607.8,157.3 L 613.9,154.4 L 614.7,149.0 L 618.8,146.2 L 624.4,146.7 L 626.2,150.1 L 628.0,150.9 L 628.2,152.5 L 626.2,155.6 L 628.1,158.3 L 631.5,159.8 L 632.9,161.9 L 632.5,163.9 L 634.9,166.9 L 631.4,166.5 L 629.4,169.2 L 624.2,168.9 L 616.4,163.4 L 608.9,160.7 Z"/>
<path d="M 653.4,186.9 L 654.2,183.5 L 655.5,183.0 L 655.2,180.8 L 656.7,180.8 L 659.5,183.7 L 663.1,184.5 L 666.1,188.0 L 662.5,193.3 L 660.6,193.8 L 660.3,197.4 L 657.2,198.4 L 656.3,200.3 L 654.6,200.3 L 652.2,202.9 L 647.5,203.7 L 644.4,197.2 L 652.8,194.4 L 654.6,188.9 L 653.4,186.9 Z"/>
<path d="M 656.3,178.6 L 655.8,177.6 L 656.6,176.7 L 656.9,176.9 L 656.3,178.6 Z"/>
<path d="M 964.5,294.1 L 966.2,295.7 L 965.3,296.1 L 964.5,294.1 Z"/>
<path d="M 964.6,293.7 L 962.9,292.8 L 962.9,290.6 L 964.2,291.5 L 964.6,293.7 Z"/>
<path d="M 787.5,220.5 L 784.3,212.8 L 786.1,210.5 L 789.7,210.0 L 794.6,211.4 L 795.8,209.5 L 798.3,210.5 L 798.9,212.4 L 798.6,215.7 L 793.9,217.9 L 795.1,219.6 L 787.5,220.5 Z"/>
<path d="M 792.3,210.4 L 786.1,210.5 L 784.3,212.8 L 785.0,216.1 L 780.1,214.9 L 780.5,212.7 L 778.0,212.8 L 775.6,224.3 L 777.4,224.4 L 779.1,229.4 L 783.7,232.7 L 781.0,234.2 L 780.8,232.8 L 778.0,232.0 L 773.6,226.7 L 773.2,228.3 L 772.6,226.8 L 776.6,217.0 L 775.3,211.6 L 772.8,208.0 L 774.7,205.1 L 770.5,198.8 L 772.9,195.3 L 778.1,193.3 L 779.5,195.8 L 781.3,195.9 L 780.7,201.4 L 783.6,199.7 L 786.1,200.1 L 786.7,199.1 L 788.8,199.3 L 790.9,201.6 L 791.1,204.3 L 793.3,206.7 L 792.3,210.4 Z"/>
<path d="M 798.3,210.5 L 795.8,209.5 L 794.6,211.4 L 792.3,210.4 L 793.3,206.7 L 788.8,199.3 L 783.6,199.7 L 780.7,201.4 L 781.3,195.9 L 779.5,195.8 L 778.1,193.3 L 781.1,190.5 L 782.8,191.2 L 782.4,188.0 L 783.8,187.6 L 786.7,192.3 L 790.1,192.3 L 791.2,194.8 L 788.6,196.5 L 791.9,198.1 L 798.1,205.8 L 798.3,210.5 Z"/>
<path d="M 778.1,193.3 L 772.9,195.3 L 770.5,198.8 L 774.7,205.1 L 772.8,208.0 L 775.3,211.6 L 776.6,217.0 L 773.8,222.4 L 773.6,213.5 L 769.9,203.0 L 764.9,206.3 L 761.6,205.5 L 762.6,202.0 L 762.0,199.4 L 759.8,196.2 L 760.2,195.2 L 756.6,192.6 L 756.4,190.3 L 757.4,190.8 L 757.4,188.8 L 758.8,188.1 L 759.2,183.1 L 761.4,183.7 L 764.2,176.2 L 767.8,174.3 L 769.8,174.8 L 770.4,171.5 L 772.0,171.3 L 774.1,173.6 L 774.1,178.0 L 771.5,180.3 L 771.1,183.6 L 774.1,183.2 L 774.7,185.7 L 776.5,186.3 L 775.7,188.6 L 778.9,190.1 L 781.0,189.3 L 781.1,190.5 L 778.1,193.3 Z"/>
<path d="M 789.8,220.9 L 795.1,219.6 L 793.9,217.9 L 798.6,215.7 L 798.8,207.8 L 791.9,198.1 L 788.6,196.5 L 791.2,194.8 L 790.1,192.3 L 786.7,192.3 L 783.8,187.6 L 790.2,186.6 L 792.6,185.1 L 796.5,186.7 L 796.0,188.3 L 797.3,189.4 L 800.1,190.1 L 796.4,192.5 L 793.5,197.1 L 802.4,207.6 L 803.7,212.7 L 803.3,217.6 L 792.1,226.1 L 791.1,224.3 L 791.9,222.4 L 789.8,220.9 Z"/>
<path d="M 863.3,132.7 L 863.3,132.7 L 863.3,132.7 L 863.3,132.7 Z"/>
<path d="M 862.9,132.2 L 860.2,134.4 L 860.3,136.4 L 854.3,139.6 L 853.8,141.1 L 856.5,142.7 L 856.1,143.4 L 848.0,145.4 L 846.4,144.1 L 848.3,140.6 L 845.2,139.1 L 847.4,137.3 L 852.4,133.8 L 856.1,134.8 L 855.7,133.3 L 860.0,132.2 L 861.1,130.6 L 862.9,132.2 Z"/>
<path d="M 850.5,145.1 L 856.5,142.7 L 859.6,147.8 L 859.6,151.0 L 858.6,152.5 L 851.3,154.5 L 851.6,150.9 L 850.3,148.0 L 852.4,147.5 L 850.5,145.1 Z"/>
<path d="M 743.8,113.1 L 756.2,108.9 L 770.2,111.9 L 772.9,109.9 L 771.7,108.3 L 774.6,105.4 L 783.5,107.6 L 784.0,109.7 L 788.0,110.9 L 796.9,110.3 L 801.3,113.1 L 807.4,113.5 L 813.6,112.4 L 817.7,110.4 L 820.8,111.7 L 824.1,111.4 L 820.8,116.3 L 821.5,117.4 L 825.8,117.5 L 828.0,116.5 L 832.7,119.3 L 832.4,120.3 L 826.2,120.4 L 815.2,125.5 L 810.8,124.7 L 809.3,126.5 L 810.6,128.5 L 806.7,130.9 L 794.8,133.0 L 791.6,134.5 L 780.1,131.5 L 767.6,131.3 L 764.7,127.1 L 759.7,125.1 L 752.6,124.2 L 751.6,123.0 L 752.7,119.8 L 750.8,117.5 L 744.5,115.0 L 743.8,113.1 Z"/>
<path d="M 770.4,171.5 L 769.8,174.8 L 767.8,174.3 L 764.2,176.2 L 761.4,183.7 L 759.2,183.1 L 758.8,188.1 L 757.4,188.8 L 756.0,184.4 L 754.7,186.2 L 753.2,184.7 L 756.6,180.6 L 749.8,179.8 L 749.5,177.9 L 746.0,176.5 L 745.0,178.4 L 747.0,179.9 L 744.7,181.9 L 746.4,182.7 L 746.9,189.7 L 741.6,190.3 L 741.8,192.4 L 740.3,194.0 L 736.3,195.9 L 728.3,202.7 L 728.3,204.0 L 723.1,205.8 L 721.8,221.2 L 720.4,221.4 L 719.1,223.5 L 720.0,224.4 L 717.4,225.2 L 715.4,227.9 L 712.8,225.3 L 708.0,214.6 L 706.8,209.4 L 704.3,205.6 L 701.8,190.7 L 697.7,192.3 L 695.8,192.0 L 692.1,188.6 L 693.5,187.6 L 692.6,186.5 L 689.4,184.2 L 691.2,182.3 L 697.3,182.3 L 694.9,176.4 L 693.1,175.2 L 696.2,172.3 L 699.4,172.5 L 706.7,163.9 L 706.7,162.0 L 709.1,160.4 L 706.8,159.0 L 704.9,154.7 L 706.2,153.5 L 713.5,153.7 L 716.2,151.4 L 719.2,154.7 L 718.9,156.9 L 720.0,158.3 L 719.9,159.8 L 717.9,159.4 L 718.7,162.5 L 725.3,166.2 L 722.5,170.0 L 731.4,174.0 L 744.6,176.6 L 744.8,172.6 L 746.5,172.0 L 746.8,174.7 L 749.3,175.8 L 755.6,175.4 L 755.8,173.7 L 754.7,172.9 L 757.0,172.5 L 762.7,168.7 L 765.0,169.4 L 767.0,168.2 L 768.3,169.9 L 767.4,171.1 L 770.4,171.5 Z"/>
<path d="M 757.4,188.8 L 756.6,192.6 L 753.9,186.8 L 751.4,186.7 L 750.8,189.3 L 747.3,188.7 L 745.9,184.4 L 746.4,182.7 L 744.7,181.9 L 747.0,179.9 L 745.0,178.4 L 746.0,176.5 L 749.5,177.9 L 749.8,179.8 L 756.6,180.6 L 753.2,184.7 L 754.7,186.2 L 756.0,184.4 L 757.4,188.8 Z"/>
<path d="M 750.0,171.4 L 755.8,173.7 L 755.6,175.4 L 749.3,175.8 L 746.8,174.7 L 750.0,171.4 Z"/>
<path d="M 744.8,172.6 L 744.6,176.6 L 742.3,176.7 L 731.4,174.0 L 722.5,170.0 L 723.5,167.4 L 726.5,165.5 L 738.4,171.7 L 744.8,172.6 Z"/>
<path d="M 716.2,151.4 L 713.5,153.7 L 706.2,153.5 L 704.9,154.7 L 706.8,159.0 L 709.1,160.4 L 706.7,162.0 L 706.7,163.9 L 699.4,172.5 L 696.2,172.3 L 693.1,175.2 L 694.9,176.4 L 697.3,182.3 L 691.2,182.3 L 689.4,184.2 L 687.3,183.5 L 684.4,179.4 L 670.8,180.3 L 671.9,177.1 L 675.9,175.7 L 674.3,173.9 L 674.2,171.5 L 671.6,170.3 L 669.1,167.1 L 673.7,168.6 L 684.3,167.0 L 684.4,164.6 L 685.9,163.0 L 692.5,161.4 L 692.4,159.7 L 695.3,157.3 L 694.3,155.5 L 696.9,155.6 L 698.9,152.4 L 698.0,149.8 L 699.6,148.6 L 708.8,146.9 L 710.8,148.1 L 711.6,150.3 L 716.2,151.4 Z"/>
<path d="M 682.6,145.4 L 692.2,146.8 L 693.1,145.5 L 694.8,145.6 L 696.7,143.1 L 698.2,143.7 L 698.5,147.0 L 699.6,147.9 L 703.5,145.8 L 708.8,146.9 L 699.6,148.6 L 698.0,149.8 L 698.9,152.4 L 696.9,155.6 L 694.3,155.5 L 695.3,157.3 L 692.4,159.7 L 692.5,161.4 L 685.9,163.0 L 684.4,164.6 L 684.3,167.0 L 673.7,168.6 L 669.1,167.1 L 671.6,164.6 L 671.4,162.8 L 669.3,162.4 L 668.2,158.4 L 669.3,156.9 L 668.1,156.5 L 670.0,151.0 L 675.0,151.7 L 675.5,150.4 L 679.3,149.1 L 679.9,146.9 L 682.6,145.4 Z"/>
<path d="M 688.4,146.8 L 690.0,144.0 L 689.4,141.9 L 687.3,141.3 L 688.1,140.1 L 690.4,140.2 L 692.6,136.9 L 696.3,136.2 L 695.7,137.5 L 697.3,138.2 L 696.2,139.1 L 693.2,138.6 L 693.0,140.2 L 704.7,140.5 L 705.4,143.0 L 708.0,143.4 L 708.3,146.1 L 703.5,145.8 L 699.6,147.9 L 698.5,147.0 L 698.2,143.7 L 696.7,143.1 L 694.8,145.6 L 693.1,145.5 L 692.2,146.8 L 688.4,146.8 Z"/>
<path d="M 697.1,132.6 L 699.6,131.0 L 704.1,131.9 L 704.6,130.3 L 706.1,129.7 L 710.1,130.9 L 719.8,131.0 L 722.9,132.4 L 717.2,135.6 L 713.6,135.9 L 712.6,137.7 L 707.7,137.9 L 705.1,139.2 L 704.7,140.5 L 693.0,140.2 L 693.2,138.6 L 699.4,138.5 L 702.9,136.5 L 695.6,134.7 L 697.9,132.9 L 697.1,132.6 Z"/>
<path d="M 645.8,133.9 L 650.2,132.4 L 654.0,135.4 L 658.6,135.2 L 658.1,133.8 L 662.9,131.2 L 666.6,132.7 L 666.9,134.9 L 668.0,135.5 L 671.9,135.9 L 673.3,138.7 L 678.3,142.0 L 684.9,144.5 L 684.8,146.2 L 682.6,145.4 L 679.9,146.9 L 679.3,149.1 L 672.9,152.0 L 670.0,151.0 L 669.8,148.6 L 659.3,144.4 L 654.2,144.5 L 649.8,146.7 L 649.7,141.8 L 647.5,140.9 L 648.2,139.0 L 646.4,138.8 L 647.0,136.5 L 649.6,137.1 L 652.0,136.2 L 649.2,133.0 L 647.0,133.7 L 646.7,135.7 L 645.8,133.9 Z"/>
<path d="M 634.9,166.9 L 632.5,163.9 L 632.9,161.9 L 631.5,159.8 L 628.1,158.3 L 626.2,155.6 L 628.2,152.5 L 628.0,150.9 L 626.2,150.1 L 622.8,144.5 L 622.5,140.5 L 624.4,139.7 L 626.3,142.0 L 628.2,142.4 L 633.5,140.0 L 634.3,140.9 L 633.4,142.2 L 635.8,143.6 L 636.7,145.6 L 641.2,147.6 L 649.5,147.3 L 654.2,144.5 L 657.3,144.1 L 669.8,148.6 L 670.0,151.0 L 668.1,156.5 L 669.3,156.9 L 668.2,158.4 L 669.3,162.4 L 671.4,162.8 L 671.6,164.6 L 669.1,167.1 L 671.6,170.3 L 674.2,171.5 L 674.3,173.9 L 675.9,175.7 L 671.9,177.1 L 670.8,180.3 L 659.4,178.5 L 658.3,175.1 L 656.9,174.6 L 652.0,176.4 L 648.6,175.5 L 643.1,172.6 L 639.2,166.3 L 635.9,165.8 L 634.9,166.9 Z"/>
<path d="M 599.2,159.1 L 600.2,156.0 L 601.7,155.0 L 600.0,153.8 L 599.7,151.6 L 602.1,147.7 L 609.8,148.0 L 617.6,146.6 L 614.7,149.0 L 613.9,154.4 L 602.3,160.2 L 599.2,159.1 Z"/>
<path d="M 629.2,142.3 L 628.2,142.4 L 627.1,140.4 L 621.3,138.2 L 621.1,135.9 L 624.9,135.4 L 626.6,136.6 L 626.0,137.3 L 627.5,138.3 L 626.7,139.2 L 629.1,140.4 L 629.2,142.3 Z"/>
<path d="M 530.6,86.5 L 534.2,83.0 L 535.1,79.7 L 533.3,78.3 L 533.1,74.6 L 534.9,72.0 L 537.7,72.1 L 538.7,71.0 L 537.7,70.0 L 546.6,61.1 L 549.2,61.1 L 550.0,59.5 L 555.2,60.0 L 555.6,58.2 L 557.3,58.0 L 565.4,61.3 L 565.5,65.6 L 566.4,66.6 L 561.6,67.4 L 558.9,69.4 L 559.4,71.1 L 549.6,75.7 L 547.6,79.6 L 552.2,83.1 L 549.6,86.2 L 546.7,86.9 L 544.1,94.2 L 540.7,93.9 L 539.2,96.1 L 536.0,96.2 L 530.6,86.5 Z"/>
<path d="M 578.3,94.0 L 585.8,95.7 L 585.4,97.7 L 590.8,101.8 L 587.0,102.6 L 588.3,105.3 L 585.9,105.4 L 584.9,107.4 L 570.4,105.8 L 565.4,106.7 L 564.4,104.2 L 566.1,103.6 L 565.2,100.2 L 570.9,99.2 L 571.6,97.6 L 573.9,96.8 L 573.6,95.5 L 578.3,94.0 Z"/>
<path d="M 585.9,105.4 L 593.8,104.6 L 595.5,106.2 L 595.1,107.6 L 597.3,107.8 L 598.2,109.5 L 611.3,112.2 L 610.4,116.9 L 607.7,117.2 L 606.2,119.2 L 597.1,121.5 L 597.3,123.0 L 588.2,121.3 L 588.0,120.3 L 585.4,120.6 L 582.2,124.2 L 579.7,124.2 L 578.4,123.6 L 580.2,121.0 L 583.4,121.0 L 579.6,116.3 L 576.5,115.4 L 569.1,117.4 L 563.1,117.0 L 561.3,115.5 L 563.3,113.8 L 562.6,112.6 L 566.5,109.9 L 565.4,106.7 L 570.4,105.8 L 584.9,107.4 L 585.9,105.4 Z"/>
<path d="M 565.2,100.2 L 566.1,103.6 L 564.4,104.2 L 566.7,109.2 L 562.6,112.6 L 563.3,113.8 L 560.0,112.6 L 555.1,113.3 L 548.8,110.1 L 544.9,109.9 L 545.1,109.2 L 541.7,108.0 L 539.1,102.8 L 539.9,102.1 L 539.2,100.7 L 549.0,97.6 L 551.9,98.8 L 563.1,99.1 L 565.2,100.2 Z"/>
<path d="M 547.1,115.0 L 547.0,117.5 L 545.4,117.5 L 545.9,118.1 L 544.5,120.3 L 540.6,121.0 L 534.4,120.1 L 533.8,119.1 L 530.7,120.1 L 526.3,119.2 L 527.5,117.8 L 528.9,118.6 L 533.7,117.5 L 535.9,118.1 L 535.8,115.9 L 537.8,114.2 L 539.8,115.1 L 542.4,113.8 L 545.8,114.5 L 547.1,115.0 Z"/>
<path d="M 561.3,115.5 L 563.1,117.0 L 561.4,117.6 L 558.4,121.3 L 551.3,122.9 L 545.0,119.9 L 545.4,117.5 L 547.0,117.5 L 547.2,116.3 L 549.6,117.3 L 557.8,114.9 L 561.3,115.5 Z"/>
<path d="M 573.9,116.1 L 576.5,115.4 L 579.6,116.3 L 583.4,121.0 L 580.2,121.0 L 578.4,123.6 L 578.1,120.0 L 573.9,116.1 Z"/>
<path d="M 578.4,123.6 L 582.2,124.2 L 580.1,125.2 L 579.3,128.6 L 575.7,127.3 L 571.0,128.6 L 563.7,128.3 L 562.4,126.6 L 563.1,126.2 L 559.9,125.6 L 556.2,121.9 L 558.4,121.3 L 561.4,117.6 L 564.3,116.4 L 569.1,117.4 L 573.9,116.1 L 578.1,120.0 L 578.4,123.6 Z"/>
<path d="M 573.6,95.5 L 573.9,96.8 L 571.6,97.6 L 570.9,99.2 L 565.2,100.2 L 563.1,99.1 L 563.2,97.6 L 559.1,96.7 L 558.5,94.4 L 569.1,93.4 L 573.6,95.5 Z"/>
<path d="M 569.9,89.0 L 577.1,91.0 L 578.3,94.0 L 573.6,95.5 L 569.1,93.4 L 558.5,94.4 L 559.9,90.5 L 562.6,89.6 L 564.8,91.6 L 567.0,91.6 L 567.5,89.5 L 569.9,89.0 Z"/>
<path d="M 577.7,84.8 L 576.2,86.9 L 577.0,89.5 L 575.8,90.3 L 569.9,89.0 L 567.5,89.5 L 567.9,87.8 L 565.1,87.2 L 564.8,85.6 L 571.8,84.4 L 577.7,84.8 Z"/>
<path d="M 539.2,100.7 L 539.9,102.1 L 539.1,102.8 L 541.7,108.0 L 534.0,110.4 L 534.8,112.4 L 537.8,114.2 L 535.8,115.9 L 535.9,118.1 L 520.7,117.7 L 522.5,113.8 L 518.5,113.3 L 516.8,110.8 L 516.6,106.0 L 519.0,104.9 L 519.7,100.9 L 522.6,101.3 L 524.4,99.9 L 523.7,97.3 L 527.6,97.3 L 527.6,98.3 L 530.4,99.0 L 530.4,100.0 L 534.8,98.7 L 539.2,100.7 Z"/>
<path d="M 562.9,127.1 L 563.7,128.3 L 571.0,128.6 L 575.7,127.3 L 579.3,128.6 L 576.9,131.7 L 577.8,133.3 L 572.5,133.8 L 572.5,135.2 L 568.0,134.5 L 563.8,135.2 L 563.6,133.3 L 562.2,132.4 L 563.9,130.0 L 562.5,128.8 L 562.9,127.1 Z"/>
<path d="M 573.0,151.9 L 572.7,152.8 L 568.7,153.0 L 565.3,152.0 L 565.8,150.8 L 573.0,151.9 Z"/>
<path d="M 558.4,136.5 L 568.0,134.5 L 572.5,135.2 L 572.5,133.8 L 573.9,134.5 L 572.4,136.6 L 565.9,137.0 L 567.8,138.5 L 562.9,138.2 L 564.9,141.1 L 563.8,141.7 L 566.7,143.8 L 566.8,145.4 L 564.2,144.7 L 565.0,146.1 L 563.3,146.4 L 564.3,148.8 L 562.5,148.9 L 560.2,147.7 L 556.0,139.9 L 558.4,136.5 Z"/>
<path d="M 624.4,146.7 L 618.8,146.2 L 609.8,148.0 L 602.1,147.7 L 600.4,150.5 L 599.4,149.2 L 600.4,148.2 L 596.4,147.8 L 594.5,149.4 L 590.3,149.7 L 588.1,148.2 L 585.1,148.1 L 582.5,149.6 L 579.8,148.1 L 576.8,148.2 L 573.1,143.9 L 574.5,141.7 L 572.7,140.4 L 575.8,137.7 L 580.1,137.6 L 581.2,135.5 L 586.5,135.9 L 593.1,133.3 L 597.7,133.2 L 606.5,136.3 L 618.4,134.5 L 621.1,135.9 L 621.3,138.2 L 624.4,139.7 L 622.5,140.5 L 622.8,144.5 L 624.4,146.7 Z"/>
<path d="M 572.5,133.8 L 577.8,133.3 L 580.5,135.3 L 576.7,136.1 L 573.2,138.5 L 572.4,136.6 L 573.9,134.5 L 572.5,133.8 Z"/>
<path d="M 558.4,136.5 L 556.0,139.9 L 553.9,138.2 L 553.6,132.8 L 554.8,131.4 L 557.0,132.7 L 557.2,135.9 L 558.4,136.5 Z"/>
<path d="M 546.0,120.8 L 549.0,122.4 L 552.3,122.5 L 553.9,124.3 L 552.8,125.4 L 544.3,124.4 L 543.8,125.5 L 551.3,132.0 L 544.5,129.1 L 542.2,127.1 L 541.4,124.8 L 539.6,124.4 L 538.8,125.5 L 537.9,124.6 L 538.1,123.6 L 542.6,123.7 L 543.8,121.6 L 546.0,120.8 Z"/>
<path d="M 526.7,118.0 L 526.3,119.2 L 529.0,119.7 L 528.8,120.9 L 520.2,122.8 L 518.1,121.0 L 516.7,121.5 L 518.7,117.9 L 523.7,117.1 L 526.7,118.0 Z"/>
<path d="M 516.1,110.9 L 517.2,112.6 L 515.8,112.4 L 516.1,110.9 Z"/>
<path d="M 517.1,108.9 L 515.8,112.4 L 511.9,111.4 L 507.0,107.9 L 513.8,107.0 L 517.1,108.9 Z"/>
<path d="M 519.2,101.4 L 519.0,104.9 L 516.6,106.0 L 517.1,108.9 L 513.8,107.0 L 509.2,107.4 L 513.1,102.5 L 519.2,101.4 Z"/>
<path d="M 474.9,133.7 L 477.0,132.6 L 477.7,133.9 L 481.5,133.7 L 482.3,135.1 L 481.0,135.8 L 480.4,139.7 L 479.2,139.9 L 480.5,144.2 L 478.2,147.7 L 475.3,147.6 L 475.4,143.7 L 473.5,142.4 L 475.6,136.8 L 474.9,133.7 Z"/>
<path d="M 479.3,147.0 L 480.5,144.2 L 479.2,139.9 L 480.4,139.7 L 481.0,135.8 L 482.3,135.1 L 481.5,133.7 L 477.7,133.9 L 477.0,132.6 L 474.9,133.7 L 475.0,131.7 L 473.9,130.5 L 477.8,128.5 L 494.7,129.4 L 500.9,131.7 L 508.3,132.0 L 508.4,133.6 L 505.8,135.5 L 502.3,136.1 L 499.2,140.8 L 500.3,142.4 L 498.1,145.4 L 496.0,146.0 L 494.0,148.1 L 487.9,148.1 L 485.1,150.1 L 483.7,149.9 L 481.9,147.4 L 479.3,147.0 Z"/>
<path d="M 482.8,100.4 L 483.2,102.4 L 481.1,104.8 L 476.2,106.5 L 472.3,106.1 L 474.5,103.2 L 473.1,100.3 L 479.0,96.9 L 479.0,99.8 L 482.8,100.4 Z"/>
<path d="M 955.6,305.8 L 964.2,311.6 L 963.2,312.2 L 959.7,310.2 L 955.6,305.8 Z"/>
<path d="M 948.1,278.3 L 951.1,280.1 L 949.2,280.1 L 948.1,278.3 Z"/>
<path d="M 947.0,273.1 L 948.7,277.2 L 946.1,273.1 L 947.0,273.1 Z"/>
<path d="M 946.8,277.4 L 944.0,277.2 L 943.6,275.7 L 945.5,276.1 L 946.8,277.4 Z"/>
<path d="M 939.9,270.3 L 944.2,273.7 L 939.5,270.6 L 939.9,270.3 Z"/>
<path d="M 936.5,269.5 L 937.6,270.4 L 934.8,268.3 L 936.5,269.5 Z"/>
<path d="M 992.2,358.7 L 988.9,364.7 L 986.8,365.8 L 985.1,364.7 L 986.7,362.4 L 985.8,360.9 L 982.8,359.7 L 984.9,357.8 L 985.3,353.8 L 979.5,345.9 L 984.2,348.0 L 987.0,353.4 L 987.1,351.5 L 988.4,352.2 L 988.8,354.3 L 992.9,355.4 L 995.9,354.7 L 994.4,358.8 L 992.2,358.7 Z"/>
<path d="M 964.0,375.3 L 975.3,368.1 L 980.0,362.5 L 981.2,364.8 L 983.2,363.7 L 984.0,364.9 L 984.0,366.0 L 979.8,370.5 L 980.8,371.8 L 976.3,372.9 L 973.9,377.5 L 970.4,379.6 L 963.0,378.4 L 962.5,377.4 L 964.0,375.3 Z"/>
<path d="M 906.6,364.3 L 911.9,363.5 L 912.1,366.8 L 910.9,370.0 L 909.9,369.3 L 908.0,371.2 L 905.7,371.0 L 902.1,363.1 L 906.6,364.3 Z"/>
<path d="M 850.4,339.5 L 845.1,341.6 L 843.5,344.1 L 833.0,344.4 L 827.8,347.4 L 824.0,347.3 L 819.5,345.0 L 819.6,343.4 L 821.4,342.4 L 821.7,339.5 L 819.6,331.8 L 814.8,322.5 L 816.1,323.7 L 815.1,321.2 L 817.3,323.1 L 815.0,317.7 L 815.9,312.4 L 817.1,310.4 L 817.3,312.5 L 818.5,310.6 L 824.2,307.5 L 835.7,304.7 L 839.6,300.5 L 839.8,297.9 L 841.7,295.6 L 842.9,298.0 L 844.1,297.4 L 843.1,296.1 L 843.9,294.8 L 845.2,295.4 L 845.5,293.2 L 849.1,289.5 L 853.0,288.4 L 856.6,291.3 L 860.1,291.6 L 859.5,290.1 L 862.8,284.8 L 868.3,283.7 L 868.2,282.2 L 866.2,281.3 L 867.7,280.9 L 875.8,284.0 L 879.1,282.9 L 880.4,284.3 L 877.7,287.0 L 876.4,291.7 L 889.5,299.2 L 891.3,298.2 L 892.4,295.5 L 893.6,291.8 L 893.6,284.5 L 895.9,279.6 L 899.8,290.4 L 901.6,289.4 L 903.8,291.6 L 906.6,302.7 L 913.5,306.6 L 915.8,312.1 L 918.7,312.2 L 919.2,315.2 L 924.6,320.2 L 925.3,325.7 L 926.6,328.1 L 924.7,337.9 L 917.6,349.1 L 916.7,354.0 L 912.0,355.0 L 906.4,358.4 L 902.4,356.7 L 902.9,355.3 L 898.9,357.8 L 890.7,355.6 L 888.9,353.9 L 887.7,350.4 L 883.7,348.9 L 884.6,347.6 L 883.9,345.5 L 882.6,347.4 L 880.1,347.9 L 883.0,343.4 L 882.8,341.4 L 878.8,344.7 L 877.7,346.9 L 875.6,345.8 L 875.7,344.3 L 872.5,341.2 L 873.0,340.6 L 864.8,337.5 L 850.4,339.5 Z"/>
<path d="M 727.2,229.1 L 726.8,232.0 L 723.2,233.4 L 721.4,227.2 L 722.6,222.7 L 727.2,229.1 Z"/>
<path d="M 804.1,199.5 L 801.8,198.6 L 801.7,196.2 L 803.1,194.9 L 807.7,194.2 L 808.4,195.3 L 806.5,198.1 L 804.1,199.5 Z"/>
<path d="M 722.9,132.4 L 722.7,130.8 L 724.6,130.1 L 722.1,125.2 L 729.1,123.5 L 731.1,118.5 L 736.6,119.4 L 738.1,118.2 L 738.2,115.4 L 743.8,113.1 L 744.5,115.0 L 750.8,117.5 L 752.7,119.8 L 751.6,123.0 L 752.6,124.2 L 759.7,125.1 L 764.7,127.1 L 767.6,131.3 L 780.1,131.5 L 791.6,134.5 L 794.8,133.0 L 803.5,131.9 L 810.6,128.5 L 809.3,126.5 L 810.8,124.7 L 815.2,125.5 L 826.2,120.4 L 832.4,120.3 L 832.7,119.3 L 828.0,116.5 L 825.8,117.5 L 821.5,117.4 L 820.8,116.3 L 824.1,111.4 L 827.4,112.5 L 831.4,110.7 L 831.3,109.5 L 835.4,105.7 L 835.3,104.1 L 833.8,103.5 L 839.6,101.6 L 843.3,101.5 L 849.9,103.4 L 854.6,111.8 L 859.4,112.7 L 862.7,114.6 L 863.9,117.2 L 868.1,117.3 L 875.1,115.3 L 869.7,124.6 L 866.3,124.1 L 864.0,125.1 L 864.3,130.8 L 862.9,130.8 L 862.9,132.2 L 861.1,130.6 L 860.0,132.2 L 855.7,133.3 L 856.1,134.8 L 852.4,133.8 L 845.2,139.1 L 836.3,142.0 L 839.4,137.7 L 837.9,136.3 L 830.6,141.0 L 827.9,141.1 L 826.5,142.4 L 832.5,146.8 L 835.6,144.8 L 839.9,146.0 L 840.3,147.4 L 836.4,148.2 L 831.0,153.0 L 834.0,154.6 L 838.6,162.0 L 838.6,164.0 L 836.8,164.8 L 839.1,167.1 L 838.0,171.6 L 836.5,171.8 L 829.6,181.8 L 821.9,186.7 L 817.1,188.3 L 816.1,187.4 L 814.6,188.7 L 807.7,190.6 L 806.8,193.5 L 805.2,193.7 L 805.2,190.6 L 797.3,189.4 L 796.0,188.3 L 796.5,186.7 L 792.6,185.1 L 790.2,186.6 L 782.4,188.0 L 782.8,191.2 L 781.3,191.1 L 781.0,189.3 L 778.9,190.1 L 775.7,188.6 L 776.5,186.3 L 774.7,185.7 L 774.1,183.2 L 771.1,183.6 L 771.5,180.3 L 774.1,178.0 L 774.1,173.6 L 772.0,171.3 L 767.4,171.1 L 768.3,169.9 L 767.0,168.2 L 765.0,169.4 L 762.7,168.7 L 757.0,172.5 L 754.7,172.9 L 750.0,171.4 L 746.7,174.2 L 746.5,172.0 L 738.4,171.7 L 728.7,166.3 L 726.5,165.5 L 725.3,166.2 L 718.7,162.5 L 717.9,159.4 L 719.9,159.8 L 720.0,158.3 L 718.9,156.9 L 719.2,154.7 L 716.2,151.4 L 711.6,150.3 L 708.3,146.1 L 708.0,143.4 L 705.4,143.0 L 704.7,140.5 L 705.1,139.2 L 707.7,137.9 L 712.6,137.7 L 713.6,135.9 L 717.2,135.6 L 722.9,132.4 Z"/>
<path d="M 838.8,180.6 L 836.6,186.7 L 835.4,189.0 L 833.6,184.6 L 837.5,179.7 L 838.8,180.6 Z"/>
<path d="M 529.0,119.7 L 533.8,119.1 L 538.4,120.8 L 538.7,123.4 L 534.2,123.9 L 535.0,127.5 L 542.1,133.5 L 544.2,133.4 L 544.9,134.1 L 544.1,134.6 L 551.0,137.9 L 550.8,139.4 L 546.9,137.7 L 545.7,139.5 L 547.7,140.5 L 547.4,141.9 L 543.6,144.7 L 544.7,141.8 L 542.8,138.8 L 531.1,132.3 L 529.2,130.7 L 528.3,128.0 L 524.7,126.8 L 520.7,128.6 L 521.0,127.4 L 519.5,127.1 L 518.7,124.9 L 519.7,124.1 L 519.0,122.2 L 524.9,122.1 L 525.5,121.0 L 528.8,120.9 L 529.0,119.7 Z"/>
<path d="M 534.9,144.1 L 543.1,143.8 L 541.9,148.3 L 534.5,145.5 L 534.9,144.1 Z"/>
<path d="M 522.7,136.2 L 525.6,135.5 L 527.2,137.5 L 526.9,141.2 L 524.5,141.9 L 523.4,141.2 L 522.7,136.2 Z"/>
<path d="M 527.6,97.3 L 523.7,97.3 L 522.5,92.9 L 523.7,91.4 L 529.4,89.6 L 528.5,92.0 L 530.3,93.2 L 526.8,95.9 L 527.6,97.3 Z"/>
<path d="M 534.4,94.1 L 535.3,95.5 L 533.6,97.8 L 530.7,96.2 L 530.3,95.1 L 534.4,94.1 Z"/>
<path d="M 482.8,100.4 L 479.0,99.8 L 479.0,96.9 L 481.3,96.7 L 484.3,98.5 L 482.8,100.4 Z"/>
<path d="M 491.4,101.7 L 491.8,100.0 L 489.9,98.3 L 485.9,97.1 L 486.9,95.8 L 486.0,95.0 L 484.5,96.4 L 484.3,93.7 L 482.9,92.3 L 486.1,87.1 L 491.7,87.1 L 488.7,90.1 L 494.6,89.8 L 491.3,94.5 L 494.2,94.7 L 496.9,98.3 L 498.8,98.7 L 501.3,103.0 L 504.7,103.5 L 504.3,105.3 L 502.9,106.1 L 504.0,107.5 L 501.5,109.0 L 491.8,109.2 L 490.0,110.5 L 484.0,110.7 L 490.5,107.1 L 486.2,106.7 L 485.4,105.6 L 488.3,104.7 L 486.7,103.2 L 487.3,101.4 L 491.4,101.7 Z"/>
<path d="M 459.7,65.4 L 459.1,67.2 L 462.2,69.1 L 458.6,71.2 L 448.2,73.6 L 436.8,72.3 L 439.5,71.1 L 433.5,69.7 L 438.4,69.2 L 438.3,68.4 L 432.4,67.7 L 434.3,65.9 L 438.5,65.5 L 442.8,67.4 L 447.1,65.9 L 450.6,66.7 L 455.1,65.2 L 459.7,65.4 Z"/>
<path d="M 628.2,134.1 L 632.8,135.7 L 635.0,133.9 L 637.8,137.3 L 640.0,138.2 L 637.7,138.4 L 635.8,143.6 L 633.4,142.2 L 634.3,140.9 L 633.5,140.0 L 629.2,142.3 L 629.1,140.4 L 626.7,139.2 L 627.5,138.3 L 624.9,135.4 L 629.2,135.9 L 628.2,134.1 Z"/>
<path d="M 628.2,142.4 L 626.3,142.0 L 624.4,139.7 L 627.1,140.4 L 628.2,142.4 Z"/>
<path d="M 611.0,129.3 L 626.3,131.9 L 628.9,133.7 L 628.2,134.1 L 629.5,135.6 L 625.6,135.0 L 621.1,135.9 L 618.4,134.5 L 615.4,134.6 L 615.1,131.5 L 611.0,129.3 Z"/>
<path d="M 836.8,216.1 L 834.2,212.6 L 837.6,213.7 L 836.8,216.1 Z"/>
<path d="M 839.9,223.0 L 841.5,219.8 L 843.1,219.6 L 842.6,221.5 L 844.7,218.8 L 844.4,221.4 L 841.7,224.9 L 839.9,223.0 Z"/>
<path d="M 850.6,224.2 L 851.5,230.0 L 850.5,232.6 L 849.5,229.7 L 848.2,231.1 L 849.1,233.2 L 848.3,234.5 L 845.1,232.9 L 844.3,230.9 L 845.1,229.6 L 843.4,228.2 L 839.1,230.8 L 838.7,230.0 L 839.8,227.7 L 843.0,225.9 L 844.0,227.1 L 846.1,226.3 L 846.6,225.1 L 848.5,225.0 L 848.4,222.9 L 850.6,224.2 Z"/>
<path d="M 832.5,220.7 L 825.5,226.8 L 832.0,218.4 L 832.5,220.7 Z"/>
<path d="M 839.8,199.4 L 840.3,202.5 L 839.6,204.8 L 838.0,205.7 L 838.1,210.2 L 844.3,211.7 L 844.7,215.2 L 841.5,212.4 L 840.8,213.4 L 839.0,211.7 L 835.1,211.5 L 836.1,209.7 L 835.3,209.0 L 834.9,210.0 L 833.1,207.2 L 833.0,204.5 L 834.1,205.5 L 835.3,198.6 L 839.8,199.4 Z"/>
<path d="M 838.9,221.0 L 838.6,217.0 L 842.0,217.8 L 841.9,219.0 L 838.9,221.0 Z"/>
<path d="M 847.9,215.2 L 849.4,219.3 L 847.3,218.6 L 848.0,221.2 L 846.7,221.8 L 845.3,218.1 L 846.9,218.3 L 846.9,217.2 L 845.2,215.1 L 847.9,215.2 Z"/>
<path d="M 778.0,232.0 L 780.8,232.8 L 781.0,234.2 L 783.7,232.7 L 786.0,234.7 L 787.2,236.5 L 787.5,242.2 L 789.5,246.4 L 787.6,246.6 L 781.6,242.3 L 778.3,235.2 L 778.0,232.0 Z"/>
<path d="M 827.5,238.5 L 821.8,238.0 L 818.4,246.0 L 813.5,245.8 L 810.5,247.5 L 807.0,247.9 L 805.1,246.3 L 804.6,244.4 L 806.7,245.4 L 808.8,244.9 L 809.4,242.5 L 813.9,241.4 L 817.2,237.4 L 818.5,238.9 L 820.4,238.0 L 820.7,234.9 L 824.2,230.8 L 825.4,230.8 L 826.9,233.4 L 831.1,235.0 L 830.9,236.1 L 829.0,236.2 L 829.5,237.6 L 827.5,238.5 Z"/>
<path d="M 820.7,234.9 L 820.4,238.0 L 818.5,238.9 L 817.2,237.4 L 820.7,234.9 Z"/>
<path d="M 538.4,120.8 L 545.0,119.9 L 546.0,120.8 L 543.8,121.6 L 542.6,123.7 L 538.1,123.6 L 538.4,120.8 Z"/>
<path d="M 580.6,56.2 L 579.0,60.1 L 583.3,61.9 L 580.7,64.0 L 583.9,67.2 L 582.1,69.6 L 584.6,71.7 L 583.4,73.5 L 587.5,75.4 L 586.5,76.8 L 578.0,81.9 L 563.5,83.8 L 559.2,81.3 L 559.8,78.6 L 558.5,76.1 L 559.8,74.5 L 570.6,69.1 L 570.3,68.0 L 565.5,65.6 L 565.4,61.3 L 557.3,58.0 L 559.0,57.3 L 562.1,58.8 L 568.7,59.3 L 571.4,58.1 L 572.7,56.0 L 577.0,55.1 L 580.6,56.2 Z"/>
<path d="M 562.7,113.7 L 560.8,115.8 L 557.8,114.9 L 549.6,117.3 L 546.9,115.4 L 551.5,112.5 L 555.1,113.3 L 560.0,112.6 L 562.7,113.7 Z"/>
<path d="M 541.7,108.0 L 546.4,110.5 L 548.8,110.1 L 552.4,112.5 L 547.1,115.0 L 542.4,113.8 L 539.8,115.1 L 534.8,112.4 L 534.0,110.4 L 541.7,108.0 Z"/>
<path d="M 601.2,209.9 L 602.4,202.9 L 606.7,200.0 L 609.1,205.8 L 619.7,214.7 L 617.6,215.2 L 613.6,210.8 L 611.2,209.7 L 607.0,209.7 L 605.3,208.4 L 604.4,210.5 L 601.2,209.9 Z"/>
<path d="M 894.1,141.2 L 891.6,144.0 L 891.0,150.4 L 889.6,152.4 L 881.2,153.9 L 877.2,157.0 L 875.3,156.0 L 875.2,153.9 L 863.9,155.9 L 866.7,157.9 L 864.8,162.6 L 863.0,163.8 L 861.7,162.7 L 862.4,160.2 L 859.5,157.5 L 862.1,156.7 L 868.4,151.6 L 876.9,151.3 L 879.8,146.4 L 881.6,147.7 L 887.3,143.8 L 889.0,140.4 L 888.6,137.3 L 889.7,135.6 L 892.7,135.1 L 894.1,141.2 Z"/>
<path d="M 901.7,127.9 L 903.7,126.7 L 904.3,129.8 L 900.2,130.6 L 897.7,133.3 L 893.4,131.4 L 891.9,134.5 L 888.8,134.5 L 888.4,131.8 L 889.8,129.6 L 892.7,129.5 L 894.4,123.5 L 897.6,126.4 L 901.7,127.9 Z"/>
<path d="M 867.7,157.0 L 872.0,154.5 L 874.4,156.1 L 872.8,157.8 L 871.6,156.9 L 870.2,157.5 L 869.5,159.2 L 867.7,158.4 L 867.7,157.0 Z"/>
<path d="M 338.4,306.0 L 339.1,311.4 L 345.0,312.1 L 346.1,316.5 L 349.2,316.7 L 347.8,323.9 L 345.3,326.1 L 337.2,325.3 L 339.9,321.1 L 339.5,319.9 L 331.0,316.3 L 325.9,311.8 L 328.4,304.5 L 335.8,303.8 L 338.4,306.0 Z"/>
<path d="M 644.4,197.2 L 647.5,203.7 L 645.5,204.5 L 644.9,206.7 L 637.7,209.1 L 635.2,211.1 L 626.7,213.1 L 625.0,214.7 L 620.8,214.9 L 618.3,207.7 L 620.5,201.2 L 629.9,202.0 L 630.6,202.9 L 636.4,198.3 L 644.4,197.2 Z"/>
<path d="M 597.1,168.5 L 600.2,168.9 L 602.1,167.0 L 604.2,166.7 L 605.6,165.3 L 602.8,162.5 L 608.9,160.7 L 616.4,163.4 L 624.2,168.9 L 631.8,169.4 L 632.5,170.8 L 634.5,170.7 L 635.6,173.1 L 639.3,175.9 L 639.6,178.9 L 641.1,181.2 L 642.7,181.6 L 644.4,186.1 L 653.4,186.9 L 654.6,188.9 L 652.8,194.4 L 644.4,197.2 L 636.4,198.3 L 630.6,202.9 L 629.9,202.0 L 620.5,201.2 L 620.1,203.7 L 618.8,204.6 L 613.7,195.9 L 608.7,190.9 L 608.5,187.3 L 606.9,184.2 L 604.1,182.5 L 597.6,172.0 L 596.2,172.1 L 597.1,168.5 Z"/>
<path d="M 364.8,466.8 L 370.4,466.2 L 378.0,468.0 L 379.6,472.3 L 359.8,475.1 L 349.5,474.0 L 350.0,472.8 L 358.4,471.2 L 364.8,466.8 Z"/>
<path d="M 315.9,472.9 L 328.1,473.3 L 331.6,471.2 L 334.5,472.3 L 332.9,475.0 L 320.9,474.8 L 315.9,472.9 Z"/>
<path d="M 291.6,449.1 L 299.8,447.8 L 300.7,443.1 L 304.9,441.3 L 310.2,448.4 L 308.9,450.5 L 302.6,451.4 L 298.9,451.3 L 300.3,450.3 L 293.9,451.0 L 291.8,450.2 L 291.6,449.1 Z"/>
<path d="M 215.7,449.7 L 231.1,449.9 L 232.8,451.4 L 220.0,451.4 L 215.7,449.7 Z"/>
<path d="M 159.4,454.6 L 160.0,453.7 L 170.2,454.1 L 166.0,455.8 L 159.4,454.6 Z"/>
<path d="M 146.4,454.1 L 148.4,453.5 L 155.5,455.2 L 150.2,454.8 L 146.4,454.1 Z"/>
<path d="M 45.2,468.3 L 46.9,467.3 L 52.1,467.7 L 57.0,469.6 L 57.8,470.8 L 52.4,471.2 L 45.2,468.3 Z"/>
<path d="M 1000.0,485.3 L 1000.0,500.0 L 0.0,500.0 L 0.0,485.3 L 2.6,483.7 L 7.6,484.6 L 11.6,483.7 L 15.6,484.8 L 19.8,483.5 L 27.9,483.0 L 36.0,484.9 L 60.9,487.1 L 68.9,486.4 L 87.4,487.8 L 102.5,486.2 L 103.1,484.9 L 83.2,484.2 L 73.4,482.5 L 75.9,479.0 L 75.4,477.9 L 64.3,475.3 L 77.5,475.0 L 81.5,475.9 L 93.3,473.2 L 92.3,472.0 L 84.6,470.4 L 68.5,469.6 L 61.0,466.7 L 60.1,463.6 L 64.0,464.7 L 72.9,464.1 L 75.2,465.3 L 79.6,465.0 L 94.2,462.4 L 93.1,460.4 L 93.9,459.4 L 97.5,458.9 L 99.1,459.8 L 124.4,456.4 L 163.7,457.0 L 173.7,455.6 L 177.2,456.2 L 183.5,454.8 L 188.1,457.5 L 190.9,456.7 L 201.2,458.8 L 208.7,458.2 L 220.4,459.2 L 221.9,458.0 L 218.7,456.1 L 215.2,455.9 L 212.0,451.7 L 224.6,452.5 L 228.6,454.3 L 232.4,454.5 L 243.2,453.2 L 249.8,453.7 L 252.1,451.6 L 254.4,452.8 L 273.7,455.1 L 277.0,453.1 L 288.3,455.5 L 292.0,455.2 L 312.9,451.3 L 313.2,449.0 L 309.6,443.7 L 312.7,439.3 L 311.8,437.0 L 323.3,430.3 L 339.4,425.8 L 341.0,426.5 L 336.0,428.8 L 331.6,428.6 L 327.7,430.0 L 326.0,431.9 L 327.4,433.9 L 322.9,434.7 L 317.6,438.8 L 324.5,442.3 L 328.3,446.4 L 331.4,453.2 L 331.0,454.7 L 321.2,459.1 L 303.9,462.9 L 285.4,463.1 L 286.3,464.2 L 295.4,466.4 L 283.5,467.7 L 283.3,469.9 L 290.7,472.9 L 334.2,478.8 L 338.3,481.2 L 361.8,477.0 L 381.1,478.0 L 386.7,476.0 L 420.7,473.2 L 417.5,471.2 L 417.5,470.2 L 401.0,470.7 L 400.6,467.6 L 419.8,463.0 L 437.6,461.4 L 451.3,458.7 L 456.4,456.9 L 457.2,455.9 L 454.3,455.2 L 457.1,453.2 L 465.9,451.1 L 471.4,448.0 L 479.4,449.2 L 480.9,447.0 L 487.9,448.5 L 498.2,447.9 L 499.4,449.0 L 521.5,444.1 L 526.5,444.5 L 530.0,446.8 L 537.3,444.4 L 540.9,444.5 L 542.0,445.6 L 544.3,444.5 L 553.5,444.1 L 559.6,444.6 L 562.7,446.4 L 575.3,445.7 L 588.9,443.5 L 594.1,440.3 L 607.4,443.8 L 616.6,440.6 L 629.2,437.8 L 631.8,438.1 L 641.0,435.8 L 643.9,434.0 L 651.5,432.8 L 656.5,433.3 L 663.2,436.9 L 670.6,438.8 L 673.3,438.9 L 677.9,437.2 L 691.4,438.7 L 693.5,442.3 L 693.2,443.6 L 688.4,445.3 L 688.7,446.4 L 691.9,446.3 L 688.7,449.6 L 694.1,450.7 L 697.3,450.2 L 705.2,444.1 L 715.7,443.0 L 719.8,439.8 L 729.9,436.7 L 741.0,436.5 L 744.4,433.9 L 749.1,436.5 L 766.1,437.2 L 777.0,436.8 L 785.6,432.1 L 794.9,435.9 L 806.2,435.3 L 815.6,433.0 L 821.1,435.3 L 832.9,436.9 L 842.3,434.7 L 857.8,435.4 L 874.3,433.9 L 875.2,431.4 L 879.5,435.5 L 881.8,436.0 L 904.1,435.9 L 907.4,438.6 L 913.4,440.0 L 923.6,441.3 L 928.6,440.4 L 935.6,442.7 L 942.2,443.3 L 948.8,446.1 L 964.7,446.8 L 975.6,449.2 L 970.2,454.6 L 961.4,456.6 L 954.4,461.8 L 954.1,464.1 L 957.6,467.2 L 962.8,467.6 L 963.9,468.8 L 949.4,469.9 L 943.9,474.8 L 954.7,478.9 L 969.2,481.5 L 970.6,482.8 L 981.2,484.5 L 988.8,483.8 L 1000.0,485.3 Z"/>
<path d="M 590.9,152.4 L 591.5,151.7 L 596.0,150.9 L 594.4,152.6 L 590.9,152.4 Z"/>
<path d="M 589.6,152.5 L 592.7,152.3 L 594.5,152.8 L 591.6,154.0 L 589.6,152.5 Z"/>
<path d="M 494.0,152.3 L 496.9,159.3 L 496.4,160.4 L 489.9,162.1 L 489.7,164.2 L 485.4,166.7 L 475.9,169.9 L 475.6,174.7 L 468.4,175.3 L 465.3,181.2 L 461.4,184.2 L 459.0,190.3 L 452.7,190.5 L 459.9,177.1 L 464.9,172.1 L 467.5,171.8 L 473.4,166.9 L 472.7,163.4 L 476.0,157.7 L 480.8,155.2 L 483.5,150.7 L 494.0,152.3 Z"/>
<path d="M 602.4,188.9 L 569.4,188.9 L 569.4,168.8 L 568.6,166.5 L 569.9,162.3 L 573.6,162.3 L 580.3,164.2 L 586.0,162.3 L 588.0,162.7 L 588.8,164.1 L 589.4,163.2 L 593.8,164.0 L 595.2,163.3 L 597.0,168.1 L 594.9,172.7 L 594.2,173.2 L 592.0,171.1 L 589.8,167.3 L 594.7,177.4 L 599.1,183.5 L 598.7,185.8 L 602.4,188.9 Z"/>
<path d="M 569.2,161.4 L 569.4,194.4 L 566.3,194.4 L 566.2,195.6 L 544.1,185.0 L 539.3,187.5 L 537.7,186.0 L 533.3,184.8 L 529.9,181.8 L 528.6,182.3 L 525.9,177.5 L 527.0,176.4 L 527.4,169.6 L 526.3,165.8 L 527.7,165.2 L 527.6,162.8 L 531.8,160.1 L 531.9,158.0 L 542.3,160.4 L 543.6,162.8 L 553.0,165.9 L 555.7,163.9 L 555.1,161.8 L 557.9,159.1 L 563.6,159.3 L 564.5,160.6 L 569.2,161.4 Z"/>
<path d="M 632.7,227.8 L 624.9,236.1 L 621.3,236.2 L 616.3,239.1 L 613.2,238.2 L 609.9,240.5 L 600.4,237.6 L 596.4,231.7 L 593.2,228.6 L 591.5,228.4 L 592.5,226.8 L 594.0,226.7 L 595.2,220.5 L 599.6,215.1 L 601.2,209.9 L 604.4,210.5 L 605.3,208.4 L 607.0,209.7 L 611.2,209.7 L 615.6,212.6 L 617.6,215.2 L 615.7,217.7 L 616.0,219.3 L 618.8,219.6 L 618.2,220.6 L 621.3,224.5 L 632.7,227.8 Z"/>
<path d="M 617.6,215.2 L 619.7,214.7 L 620.3,215.6 L 620.2,216.7 L 618.7,217.4 L 619.8,218.2 L 618.8,219.6 L 616.0,219.3 L 615.7,217.7 L 617.6,215.2 Z"/>
<path d="M 636.0,218.3 L 635.9,223.7 L 632.7,227.8 L 621.3,224.5 L 618.2,220.6 L 619.8,218.2 L 622.5,221.0 L 636.0,218.3 Z"/>
<path d="M 594.2,252.6 L 582.2,253.7 L 583.0,248.3 L 586.6,243.9 L 585.5,243.5 L 585.6,240.3 L 586.8,239.5 L 592.8,239.5 L 594.5,238.2 L 595.8,240.1 L 597.3,244.7 L 594.1,249.7 L 594.2,252.6 Z"/>
<path d="M 584.5,253.2 L 585.4,256.4 L 583.2,256.5 L 582.3,258.1 L 580.6,257.9 L 581.4,254.5 L 584.5,253.2 Z"/>
<path d="M 551.6,131.5 L 545.7,127.7 L 543.8,125.5 L 544.3,124.4 L 553.8,125.4 L 553.1,126.6 L 554.4,127.7 L 554.0,129.0 L 552.0,130.0 L 551.6,131.5 Z"/>
<path d="M 562.2,132.4 L 563.6,133.3 L 563.8,135.2 L 558.4,136.5 L 557.2,135.9 L 557.7,133.2 L 562.2,132.4 Z"/>
<path d="M 552.3,122.5 L 556.2,121.9 L 559.9,125.6 L 563.1,126.2 L 562.3,127.8 L 563.9,130.0 L 562.6,132.1 L 559.9,132.7 L 560.5,131.4 L 557.8,129.8 L 556.3,131.1 L 553.4,129.1 L 554.4,127.7 L 553.1,126.6 L 553.9,124.3 L 552.3,122.5 Z"/>
<path d="M 556.5,130.8 L 554.8,131.4 L 553.8,133.7 L 551.3,132.0 L 553.4,129.1 L 556.5,130.8 Z"/>
<path d="M 557.2,133.7 L 555.8,131.7 L 557.3,130.0 L 560.5,131.4 L 557.2,133.7 Z"/>
<path d="M 328.7,220.1 L 330.8,219.8 L 330.7,221.9 L 327.9,222.0 L 328.7,220.1 Z"/>
<path d="M 585.6,240.3 L 582.5,237.2 L 577.7,237.8 L 569.8,228.3 L 566.4,226.1 L 568.2,225.2 L 569.6,221.5 L 571.6,221.1 L 574.3,223.7 L 580.5,223.9 L 583.3,221.4 L 585.7,223.0 L 587.1,222.7 L 590.0,219.2 L 589.1,216.7 L 592.2,216.2 L 592.2,220.2 L 593.7,221.3 L 594.4,225.9 L 591.5,228.4 L 594.7,229.9 L 598.1,234.7 L 592.8,239.5 L 585.6,240.3 Z"/>
</g>
<line x1="500" y1="0" x2="500" y2="500" stroke="#0ff" stroke-width="0.7" opacity="0.18"/><line x1="0" y1="250" x2="1000" y2="250" stroke="#0ff" stroke-width="0.7" opacity="0.18"/></svg>'''

DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BANKAI — VPNGuard SOC Console</title>
  <style>
    :root{
      --void:#04060a; --terminal:#090e17; --panel:#0d1527; --panel2:#0a101c;
      --text:#e2e8f0; --muted:#94a3b8; --line:rgba(148,163,184,.16);
      --green:#00ff66; --cyan:#00f0ff; --red:#ff2a55; --amber:#ffaa00; --blue:#60a5fa;
      --shadow:0 0 18px rgba(0,255,102,.05), inset 0 0 12px rgba(0,255,102,.02);
    }
    *{box-sizing:border-box}
    html,body{margin:0;min-height:100%;background:var(--void);color:var(--text);font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}
    body{overflow-x:hidden;background-image:radial-gradient(circle at 50% 0%,rgba(0,255,102,.05),transparent 58%),linear-gradient(rgba(0,255,102,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,102,.025) 1px,transparent 1px);background-size:100% 100%,32px 32px,32px 32px}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(rgba(18,16,16,0) 50%,rgba(0,0,0,.16) 50%);background-size:100% 4px;opacity:.45;z-index:99}
    header{position:sticky;top:0;z-index:20;border-bottom:1px solid rgba(0,255,102,.18);background:rgba(4,6,10,.92);backdrop-filter:blur(10px)}
    .topbar{max-width:1500px;margin:auto;padding:12px 18px;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
    .brand{display:flex;align-items:center;gap:12px}.brand-mark{color:var(--green);font-weight:900;font-size:18px;text-shadow:0 0 10px rgba(0,255,102,.65)}
    .title{font-size:18px;font-weight:900;letter-spacing:.08em;color:#fff}.title small{font-size:10px;font-weight:600;color:var(--muted);border:1px solid var(--line);padding:3px 6px;border-radius:3px;margin-left:6px;letter-spacing:.06em}
    .subtitle{font-size:9px;color:#64748b;margin-top:4px;letter-spacing:.08em}
    .badges{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.badge{font-size:10px;padding:6px 9px;border:1px solid var(--line);border-radius:4px;background:rgba(15,23,42,.75);color:var(--muted)}.badge.ok{color:#86efac;border-color:rgba(34,197,94,.35)}.badge.bad{color:#fca5a5;border-color:rgba(239,68,68,.35)}.badge.cyan{color:var(--cyan);border-color:rgba(0,240,255,.25)}
    main{max-width:1500px;margin:auto;padding:18px;display:grid;gap:14px}.hud{background:rgba(9,14,23,.9);border:1px solid rgba(0,255,102,.16);box-shadow:var(--shadow);position:relative}.hud:after{content:"";position:absolute;right:-1px;bottom:-1px;width:8px;height:8px;border-right:2px solid var(--green);border-bottom:2px solid var(--green)}
    .danger{border-color:rgba(255,42,85,.3);box-shadow:0 0 18px rgba(255,42,85,.07)}
    .grid5{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.metric{padding:14px;min-height:104px}.metric .kicker{font-size:10px;color:#64748b;border-bottom:1px solid var(--line);padding-bottom:7px;margin-bottom:9px;display:flex;justify-content:space-between;gap:8px}.metric .num{font-size:28px;font-weight:900;color:#fff}.metric .meta{font-size:10px;color:#64748b;margin-top:8px;display:flex;justify-content:space-between;gap:8px}.green{color:var(--green)}.red{color:var(--red)}.amber{color:var(--amber)}.cyan{color:var(--cyan)}
    .tabs{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;border-bottom:1px solid rgba(0,255,102,.15);padding-bottom:8px}.tabset{display:flex;gap:7px;flex-wrap:wrap}.tab{font:inherit;font-size:10px;font-weight:800;letter-spacing:.04em;color:#94a3b8;background:transparent;border:1px solid var(--line);padding:8px 11px;border-radius:3px;cursor:pointer}.tab.active{color:var(--green);border-color:rgba(0,255,102,.6);background:rgba(0,255,102,.06)}.live-note{font-size:10px;color:#64748b;padding:8px 0}.live-note b{color:var(--red)}
    .view.hidden{display:none}.cols2{display:grid;grid-template-columns:2fr 1fr;gap:14px}.cols3{display:grid;grid-template-columns:1.35fr 1fr 1fr;gap:14px}.panel{padding:14px}.panel-title{font-size:11px;font-weight:900;color:#fff;text-transform:uppercase;letter-spacing:.07em;border-bottom:1px solid var(--line);padding-bottom:9px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;gap:10px}.panel-title span{color:#64748b;font-size:9px;font-weight:600}.sub{font-size:10px;color:var(--muted)}
    canvas{width:100%;height:285px;display:block}.chart-wrap{height:285px}.empty{padding:16px;border:1px dashed var(--line);color:#64748b;font-size:11px}.scroll{max-height:310px;overflow:auto}
    .feed{display:grid;gap:8px}.feed-item{padding:9px;border:1px solid var(--line);background:rgba(2,6,23,.55);display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.feed-item.critical{border-color:rgba(255,42,85,.45);background:rgba(127,29,29,.10)}.feed-main{min-width:0}.feed-line{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.sev{font-size:9px;font-weight:900;padding:3px 5px;border:1px solid var(--line);border-radius:3px}.sev.CRITICAL{color:#fecdd3;border-color:rgba(255,42,85,.55);background:rgba(127,29,29,.24)}.sev.HIGH{color:#fde68a;border-color:rgba(245,158,11,.5);background:rgba(120,53,15,.18)}.sev.MEDIUM{color:#fef08a}.sev.LOW{color:#bfdbfe}.attack{font-size:10px;color:#fff;font-weight:800}.feed-time{font-size:9px;color:#64748b}.feed-story{font-size:9px;line-height:1.5;color:#94a3b8;margin-top:4px}.btn{font:inherit;font-size:9px;padding:6px 8px;background:#0b1220;color:#cbd5e1;border:1px solid var(--line);border-radius:3px;cursor:pointer}.btn:hover{border-color:rgba(0,255,102,.45);color:#fff}.btn-green{color:var(--green);border-color:rgba(0,255,102,.35)}.btn-danger{color:#fecaca;border-color:rgba(255,42,85,.45)}
    table{width:100%;border-collapse:collapse;font-size:10px}.table-wrap{overflow:auto}.table th,.table td{padding:8px 7px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.table th{color:#64748b;font-weight:700;font-size:9px}.table tr.clickable{cursor:pointer}.table tr.clickable:hover{background:rgba(15,23,42,.55)}
    select,input{font:inherit;background:#060b13;color:#e5e7eb;border:1px solid var(--line);border-radius:3px;padding:7px 8px;font-size:10px;outline:none}select:focus,input:focus{border-color:rgba(0,255,102,.45)}.filters{display:flex;gap:7px;flex-wrap:wrap}.filters .grow{flex:1;min-width:160px}
    .model-lines{display:grid;gap:7px;font-size:10px}.line{display:flex;justify-content:space-between;gap:10px;border-bottom:1px dashed rgba(148,163,184,.10);padding-bottom:6px}.line span:first-child{color:#64748b}.line span:last-child{text-align:right}
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.82);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:16px;z-index:80}.modal.show{display:flex}.modal-box{max-width:980px;width:100%;max-height:92vh;overflow:auto;background:rgba(4,8,15,.98);border:1px solid rgba(0,255,102,.28);box-shadow:0 0 40px rgba(0,255,102,.08);padding:16px}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:12px}.modal-title{font-size:11px;font-weight:900;color:var(--green);letter-spacing:.06em}.close{font:inherit;background:transparent;border:0;color:#94a3b8;font-size:18px;cursor:pointer}.detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.detail-card{padding:9px;border:1px solid var(--line);background:#020617}.detail-card .label{font-size:8px;color:#64748b}.detail-card .value{font-size:10px;font-weight:800;color:#fff;margin-top:4px}.pre{white-space:pre-wrap;max-height:300px;overflow:auto;background:#02050a;border:1px solid var(--line);padding:10px;color:#86efac;font-size:9px;line-height:1.55}
    .risk-grid{display:grid;grid-template-columns:1.4fr .8fr;gap:14px}.slider-row{padding:10px;border:1px solid var(--line);background:#030712;margin-bottom:9px}.slider-row .r1{display:flex;justify-content:space-between;font-size:10px;margin-bottom:6px}.slider-row input[type=range]{width:100%;padding:0;border:0}.gauge{display:flex;align-items:center;justify-content:center;min-height:290px}.circle{width:170px;height:170px;border-radius:50%;border:4px solid var(--green);display:flex;flex-direction:column;align-items:center;justify-content:center;box-shadow:0 0 28px rgba(0,255,102,.08)}.circle .pct{font-size:31px;font-weight:900;color:#fff}.circle .tier{font-size:9px;color:var(--green);margin-top:3px}
    footer{max-width:1500px;margin:auto;padding:0 18px 18px;color:#64748b;font-size:9px}.footer-row{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:9px}
    .mix-chart{height:220px;display:grid;align-content:center;gap:11px;padding:8px 2px}
    .overview-globe{margin-top:10px;border-top:1px solid var(--line);padding-top:10px}.globe-wrap{position:relative;height:190px;background:radial-gradient(circle at 50% 42%,rgba(0,240,255,.08),transparent 56%),#02060b;border:1px solid var(--line);overflow:hidden}.globe-canvas{width:100%;height:100%;display:block}.globe-overlay{position:absolute;left:8px;top:8px;font-size:8px;color:#64748b;letter-spacing:.08em}.globe-link{position:absolute;right:8px;bottom:8px}
    .quick-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
    .mix-row{display:grid;grid-template-columns:132px minmax(0,1fr) 58px;gap:10px;align-items:center}
    .mix-label{min-width:0}.mix-name{font-size:9px;font-weight:900;color:#e5e7eb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.mix-tech{font-size:8px;color:#64748b;margin-top:3px}
    .mix-track{height:16px;position:relative;background:rgba(15,23,42,.9);border:1px solid rgba(148,163,184,.12);overflow:hidden}
    .mix-track:after{content:"";position:absolute;inset:0;background:repeating-linear-gradient(90deg,transparent 0 32px,rgba(148,163,184,.08) 32px 33px);pointer-events:none}
    .mix-bar{position:absolute;left:0;top:0;bottom:0;min-width:0;width:0;border-right:2px solid currentColor;box-shadow:0 0 14px currentColor;transition:width .35s ease;z-index:1}
    .mix-bar.red{background:linear-gradient(90deg,rgba(255,42,85,.55),rgba(255,42,85,.95));color:var(--red)}
    .mix-bar.amber{background:linear-gradient(90deg,rgba(255,170,0,.45),rgba(255,170,0,.95));color:var(--amber)}
    .mix-bar.cyan{background:linear-gradient(90deg,rgba(0,240,255,.40),rgba(0,240,255,.95));color:var(--cyan)}
    .mix-bar.blue{background:linear-gradient(90deg,rgba(96,165,250,.35),rgba(96,165,250,.95));color:var(--blue)}
    .mix-value{text-align:right}.mix-count{font-size:14px;font-weight:900;color:#fff}.mix-share{font-size:8px;color:#64748b;margin-top:2px}
    .mix-legend{display:flex;gap:12px;flex-wrap:wrap;margin-top:1px;font-size:8px;color:#64748b}.mix-legend span{display:flex;gap:5px;align-items:center}.mix-legend i{width:7px;height:7px;border-radius:50%;display:inline-block;box-shadow:0 0 7px currentColor}.mix-legend .red{color:var(--red);background:var(--red)}.mix-legend .amber{color:var(--amber);background:var(--amber)}.mix-legend .cyan{color:var(--cyan);background:var(--cyan)}.mix-legend .blue{color:var(--blue);background:var(--blue)}
    .geo-map{position:relative;min-height:430px;background:#020a05;border:1px solid var(--line);overflow:hidden}
    .geo-map-img{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;opacity:.55;filter:brightness(.7) saturate(.8) hue-rotate(70deg)}
    .geo-route-layer{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;opacity:.6}
    .geo-route{fill:none;stroke:rgba(0,240,255,.48);stroke-width:1.4;stroke-linecap:round;stroke-dasharray:7 9;animation:geoDash 3.6s linear infinite;filter:drop-shadow(0 0 3px rgba(0,240,255,.35))}
    .geo-context-node{fill:rgba(0,240,255,.25);stroke:rgba(0,240,255,.65);stroke-width:1;filter:drop-shadow(0 0 5px rgba(0,240,255,.45))}
    @keyframes geoDash{to{stroke-dashoffset:-64}}
    .geo-points{position:absolute;inset:0}
    .geo-point{position:absolute;width:10px;height:10px;border-radius:50%;transform:translate(-50%,-50%);box-shadow:0 0 0 3px rgba(0,255,102,.12),0 0 12px currentColor;cursor:pointer}
    .geo-point:after{content:"";position:absolute;inset:-6px;border:1px solid currentColor;border-radius:50%;opacity:.35;animation:geoPulse 1.9s ease-out infinite}
    @keyframes geoPulse{0%{transform:scale(.55);opacity:.65}100%{transform:scale(1.9);opacity:0}}
    .geo-point.success{background:var(--green);color:var(--green)}
    .geo-point.danger{background:var(--red);color:var(--red)}
    .geo-point.amber{background:var(--amber);color:var(--amber)}
    .geo-legend{position:absolute;right:12px;bottom:12px;display:flex;gap:12px;flex-wrap:wrap;padding:7px 9px;border:1px solid var(--line);background:rgba(2,6,23,.82);font-size:9px;color:#94a3b8}
    .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}.dot.success{background:var(--green)}.dot.danger{background:var(--red)}.dot.context{background:var(--cyan);box-shadow:0 0 7px var(--cyan)}
    .dataset-kpi{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:10px}.dataset-kpi .detail-card{min-height:68px}
    @media(max-width:1150px){.grid5{grid-template-columns:repeat(3,1fr)}.cols2,.cols3,.risk-grid{grid-template-columns:1fr}.detail-grid{grid-template-columns:repeat(2,1fr)}}
    @media(max-width:720px){.grid5{grid-template-columns:1fr 1fr}.detail-grid{grid-template-columns:1fr}.title{font-size:15px}.metric .num{font-size:23px}.mix-row{grid-template-columns:105px minmax(0,1fr) 44px}.mix-name{font-size:8px}.mix-tech{font-size:7px}.geo-map{min-height:330px}.geo-legend{left:8px;right:8px;bottom:8px;gap:8px}}
  </style>
</head>
<body>
<div id="authGate" style="position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:rgba(4,6,10,.96);backdrop-filter:blur(12px)">
  <div style="width:min(460px,92vw);border:1px solid rgba(0,255,102,.28);background:#090e17;box-shadow:0 0 40px rgba(0,255,102,.08);padding:24px">
    <div style="font-weight:900;letter-spacing:.12em;color:#00ff66;font-size:17px">BANKAI // SOC API TOKEN REQUIRED</div>
    <div style="margin-top:10px;color:#94a3b8;font-size:12px;line-height:1.6">SOC API access is protected. Enter the local BANKAI_API_TOKEN configured on the Sentinel host.</div>
    <input id="apiTokenInput" type="password" autocomplete="current-password" placeholder="BANKAI_API_TOKEN" style="margin-top:16px;width:100%;padding:11px 12px;background:#04060a;color:#e2e8f0;border:1px solid rgba(148,163,184,.2);font:inherit">
    <div id="authError" style="min-height:18px;margin-top:8px;color:#ff2a55;font-size:11px"></div>
    <button id="authButton" class="btn" style="width:100%;margin-top:4px">AUTHENTICATE</button>
  </div>
</div>
<header>
  <div class="topbar">
    <div class="brand">
      <div class="brand-mark">&gt;_</div>
      <div><div class="title">BANKAI <small>VPNGuard v1.2</small></div><div class="subtitle">AUTHENTICATION ATTACK DETECTION • LIVE LOCAL SOC CONSOLE</div></div>
    </div>
    <div class="badges"><button class="btn" onclick="logout()">LOGOUT</button>
      <span class="badge cyan">LOCAL-FIRST</span>
      <span class="badge">MITRE T1110</span>
      <span class="badge" id="health">CHECKING…</span>
      <span class="badge" id="clock"></span>
    </div>
  </div>
</header>

<main>
  <section class="grid5">
    <div class="hud metric"><div class="kicker"><span>INGESTED_EVENTS</span><span class="green">● LIVE</span></div><div class="num" id="events">0</div><div class="meta"><span>Durable event store</span><span class="green">STREAMING</span></div></div>
    <div class="hud metric danger"><div class="kicker"><span>ACTIVE_ALERTS</span><span class="red">● SIGNAL</span></div><div class="num red" id="alerts">0</div><div class="meta"><span>Correlated detections</span><span id="critical" class="red">0 CRITICAL</span></div></div>
    <div class="hud metric"><div class="kicker"><span>INCIDENTS</span><span class="amber">● CASES</span></div><div class="num amber" id="incidents">0</div><div class="meta"><span>Investigation queue</span><span id="epm">0 EPM</span></div></div>
    <div class="hud metric"><div class="kicker"><span>MITRE_T1110</span><span class="cyan">● MAPPED</span></div><div class="num cyan" id="threats">0</div><div class="meta"><span>Brute + spray</span><span id="tracked">0 SRC</span></div></div>
    <div class="hud metric"><div class="kicker"><span>DETECTION_QUALITY</span><span class="cyan">● EVAL</span></div><div class="num" id="precision">—</div><div class="meta"><span id="recall">Recall —</span><span id="f1">F1 —</span></div></div>
  </section>

  <section class="tabs">
    <div class="tabset">
      <button class="tab active" data-tab="overview">[01] THREAT OVERVIEW & TIMELINE</button>
      <button class="tab" data-tab="incidents">[02] INCIDENTS & FORENSICS</button>
      <button class="tab" data-tab="risk">[03] BREACH RISK ENGINE</button>
      <button class="tab" data-tab="geo">[04] GEO ACTIVITY</button>
      <button class="tab" data-tab="dataset">[05] USER DATASET LAB</button>
    </div>
    <div class="live-note">Backend source: <b>real-time API</b> • no client-side incident injection</div>
  </section>

  <section id="view-overview" class="view">
    <div class="cols2">
      <div class="hud panel">
        <div class="panel-title"><span class="green">&gt;</span> Authentication Velocity & Anomaly Activity <span>60-MINUTE ROLLING WINDOW</span></div>
        <div class="chart-wrap"><canvas id="activity"></canvas></div>
      </div>
      <div class="hud panel">
        <div class="panel-title"><span class="amber">&gt;</span> ATTACK DISTRIBUTION <span>LIVE API</span></div>
        <div id="mix" class="mix-chart" aria-label="Live attack distribution"></div>
        <div class="overview-globe">
          <div class="panel-title" style="margin-bottom:7px"><span class="cyan">GLOBAL ACTIVITY GLOBE</span><span>GEO SIGNAL</span></div>
          <div class="globe-wrap">
            <canvas id="globeCanvas" class="globe-canvas" aria-label="Global authentication activity globe"></canvas>
            <div class="globe-overlay">AUTH EVENTS / SIGNAL ROUTES</div>
            <button class="btn globe-link" onclick="openTab('geo')">OPEN GEO MAP →</button>
          </div>
        </div>
      </div>
    </div>

    <div class="cols3" style="margin-top:14px">
      <div class="hud panel" style="grid-column:span 2">
        <div class="panel-title"><span class="red">&gt;</span> Real-Time Attack Campaign Feed <span>MITRE ATT&amp;CK</span></div>
        <div id="feed" class="feed scroll"></div>
      </div>
      <div class="hud panel">
        <div class="panel-title"><span class="green">&gt;</span> Engine Diagnostics <span>BACKEND STATE</span></div>
        <div id="evalLabel" style="font-size:9px;color:var(--amber);letter-spacing:.08em;margin-bottom:8px"></div><div id="modelBox" class="model-lines"></div>
        <div class="quick-actions"><button class="btn btn-green" onclick="openTab('dataset')">OPEN USER DATASET LAB →</button><button class="btn" onclick="openTab('geo')">OPEN GLOBAL MAP →</button><button class="btn btn-green" onclick="window.open('__TARGET_ROOT__','_blank')">OPEN TARGET AUTH →</button><button class="btn" onclick="window.open('__ATTACKER_ROOT__','_blank')">OPEN ATTACK LAB →</button></div>
      </div>
    </div>

    <div class="hud panel" style="margin-top:14px">
      <div class="panel-title"><span class="cyan">&gt;</span> Alert Investigation <span>SEARCH / TRIAGE / LIFECYCLE</span></div>
      <div class="filters">
        <select id="filterAttack"><option value="">All attack types</option><option value="password_spraying">VPN / Password spraying</option><option value="brute_force">Brute force</option><option value="impossible_travel">Impossible travel</option><option value="ml_anomaly">ML anomaly</option></select>
        <select id="filterSeverity"><option value="">All severities</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
        <select id="filterStatus"><option value="">All statuses</option><option>NEW</option><option>INVESTIGATING</option><option>CONFIRMED</option><option>RESOLVED</option><option>FALSE_POSITIVE</option></select>
        <input id="filterIp" class="grow" placeholder="source IP filter">
        <button class="btn btn-green" onclick="refresh()">APPLY</button>
      </div>
      <div class="cols3" style="margin-top:12px">
        <div><div class="sub" style="margin-bottom:7px">RECENT ALERTS</div><div id="alertTable" class="table-wrap"></div></div>
        <div><div class="sub" style="margin-bottom:7px">RECENT INCIDENTS</div><div id="incidentTable" class="table-wrap"></div></div>
        <div><div class="sub" style="margin-bottom:7px">INVESTIGATE</div><div class="filters"><input id="investigateInput" class="grow" placeholder="alert ID / IP / username"><button class="btn" onclick="investigate()">OPEN</button></div><div id="investigation" class="sub" style="margin-top:10px">Select an alert or enter an identifier.</div><div id="lifecycle" style="margin-top:10px"></div></div>
      </div>
    </div>
  </section>

  <section id="view-incidents" class="view hidden">
    <div class="hud panel">
      <div class="panel-title"><span class="cyan">&gt;</span> Correlated Incident Records <span>REAL BACKEND DATA</span></div>
      <div class="table-wrap"><div id="incidentDetailTable"></div></div>
    </div>
    <div class="hud panel" style="margin-top:14px">
      <div class="panel-title"><span class="green">&gt;</span> Evidence Dossier <span>SELECT AN INCIDENT ABOVE</span></div>
      <div id="incidentDossier" class="sub">No incident selected.</div>
    </div>
  </section>

  <section id="view-risk" class="view hidden">
    <div class="risk-grid">
      <div class="hud panel">
        <div class="panel-title"><span class="green">&gt;</span> Combinatorial Breach Risk Engine <span>MATHEMATICAL MODEL</span></div>
        <div class="slider-row"><div class="r1"><span>Directory accounts (N)</span><b id="valN">500</b></div><input id="sliderN" type="range" min="50" max="5000" step="50" value="500"></div>
        <div class="slider-row"><div class="r1"><span>Weak-password attempts per account (k)</span><b id="valK">3</b></div><input id="sliderK" type="range" min="1" max="25" step="1" value="3"></div>
        <div class="slider-row"><div class="r1"><span>Candidate password space (M)</span><b id="valM">1000</b></div><input id="sliderM" type="range" min="100" max="10000" step="100" value="1000"></div>
        <div class="pre">P(compromise) = 1 - (1 - k/M)^N

This calculator is an analytical risk model. It does not execute credential attacks and its probability is not a measured production breach probability.</div>
      </div>
      <div class="hud panel gauge">
        <div><div class="circle" id="gauge"><div class="pct" id="resProb">77.7%</div><div class="tier" id="resTier">ELEVATED RISK</div></div><div class="model-lines" style="margin-top:14px"><div class="line"><span>Tested pairs</span><span id="resComb">1500</span></div><div class="line"><span>Single-account p</span><span id="resSingle">0.30%</span></div><div class="line"><span>Action</span><span id="resAction" class="amber">Enforce MFA / FIDO2</span></div></div></div>
      </div>
    </div>
  </section>

  <section id="view-geo" class="view hidden">
    <div class="hud panel">
      <div class="panel-title"><span class="green">&gt;</span> GEO ACTIVITY MAP <span>LIVE SQLITE AUTH EVENTS</span></div>
      <div class="sub" style="margin-bottom:10px">Authentication coordinates are plotted from the persisted event stream; the animated network layer is visual context only and is excluded from event counts.</div>
      <div id="geoMap" class="geo-map">
        <img src="/dashboard/world_map.svg" alt="World map" class="geo-map-img">
        <svg id="geoRoutes" class="geo-route-layer" viewBox="0 0 1000 500" preserveAspectRatio="none" aria-hidden="true">
          <g id="geoContextRoutes"></g>
          <g id="geoContextNodes"></g>
        </svg>
        <div id="geoPoints" class="geo-points"></div>
        <div class="geo-legend"><span><i class="dot success"></i> SUCCESS</span><span><i class="dot danger"></i> FAILURE / ATTACK</span><span><i class="dot context"></i> GLOBAL SIGNAL</span></div>
      </div>
      <div id="geoSummary" class="model-lines" style="margin-top:10px"></div>
    </div>
  </section>

  <section id="view-dataset" class="view hidden">
    <div class="cols2">
      <div class="hud panel">
        <div class="panel-title"><span class="cyan">&gt;</span> USER-SUPPLIED AUTHENTICATION DATASET <span>CSV • MAX 50,000 ROWS</span></div>
        <div class="sub" style="margin-bottom:10px">Upload your own authentication dataset. The live SOC model/database are not overwritten by this upload.</div>
        <input id="datasetFile" type="file" accept=".csv,text/csv" style="width:100%;padding:10px">
        <div class="filters" style="margin-top:10px">
          <button class="btn btn-green" onclick="evaluateDataset()">EVALUATE DATASET</button>
          <button class="btn" onclick="trainDataset()">TRAIN DATASET MODEL</button>
          <button class="btn" onclick="analyzeDataset()">ANALYZE WITH TRAINED MODEL</button>
        </div>
        <div class="pre" style="margin-top:10px">Ground-truth labels are used only after detection for evaluation. Supported labels: NORMAL, ATTACK_BRUTE_FORCE, ATTACK_PASSWORD_SPRAY, ATTACK_IMPOSSIBLE_TRAVEL.</div>
      </div>
      <div class="hud panel">
        <div class="panel-title"><span class="green">&gt;</span> Dataset / Training Results <span>MEASURED OUTPUT</span></div>
        <div id="datasetStatus" class="model-lines"><div class="line"><span>Status</span><span class="amber">NO DATASET RUN</span></div></div>
        <div id="datasetResult" class="pre" style="margin-top:10px;max-height:420px">Upload a CSV and run an action.</div>
      </div>
    </div>
  </section>
</main>
<footer><div class="footer-row"><span>BANKAI (VPNGuard) • LIVE BACKEND SOC CONSOLE</span><span>LIVE telemetry is backend-sourced. Benchmark metrics are labelled separately when available.</span></div></footer>

<div id="modal" class="modal">
  <div class="modal-box">
    <div class="modal-head"><div class="modal-title">&gt;_ FORENSIC EVIDENCE DOSSIER <span id="modalId" style="color:#fff;margin-left:6px"></span></div><button class="close" onclick="closeModal()">×</button></div>
    <div id="modalBody"></div>
  </div>
</div>

<script>
let authBusy=false;
function showAuthGate(show=true){document.getElementById('authGate').style.display=show?'flex':'none';if(show)document.getElementById('apiTokenInput').focus();}
async function login(){if(authBusy)return;authBusy=true;const btn=document.getElementById('authButton');const token=document.getElementById('apiTokenInput').value.trim();document.getElementById('authError').textContent='';btn.disabled=true;btn.textContent='AUTHENTICATING…';try{if(!token){document.getElementById('authError').textContent='Enter BANKAI_API_TOKEN.';return;}const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});if(!r.ok){let msg='Authentication failed. Check BANKAI_API_TOKEN.';try{const d=await r.json();if(d.detail)msg=d.detail;}catch(_){}document.getElementById('authError').textContent=msg;return;}showAuthGate(false);await refresh();}catch(e){document.getElementById('authError').textContent='Sentinel API unavailable.';}finally{authBusy=false;btn.disabled=false;btn.textContent='AUTHENTICATE';}}
async function logout(){try{await fetch('/api/auth/logout',{method:'POST'});}finally{showAuthGate(true);}}
async function apiFetch(url, options={}){const r=await fetch(url,options);if(r.status===401){showAuthGate(true);throw new Error('SOC API authentication required');}return r;}
document.getElementById('authButton').addEventListener('click',login);document.getElementById('apiTokenInput').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct=v=>v==null?'—':`${(Number(v)*100).toFixed(1)}%`;
let cachedIncidents=[];

function tickClock(){ $('clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'; }
setInterval(tickClock,1000);tickClock();

document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>openTab(btn.dataset.tab)));

function drawLine(canvas,data){
  const dpr=devicePixelRatio||1,r=canvas.getBoundingClientRect(),w=Math.max(320,r.width),h=285;canvas.width=w*dpr;canvas.height=h*dpr;const c=canvas.getContext('2d');c.setTransform(dpr,0,0,dpr,0,0);c.clearRect(0,0,w,h);
  const vals=data.map(x=>Number(x.total||0)),fails=data.map(x=>Number(x.failures||0)),max=Math.max(1,...vals);const L=42,R=16,T=24,B=34,H=h-T-B;
  c.strokeStyle='rgba(148,163,184,.12)';c.lineWidth=1;for(let j=0;j<=4;j++){const y=T+H*j/4;c.beginPath();c.moveTo(L,y);c.lineTo(w-R,y);c.stroke();}
  const series=(arr,color)=>{c.strokeStyle=color;c.lineWidth=2;c.beginPath();arr.forEach((v,i)=>{const x=L+(w-L-R)*(i/Math.max(1,arr.length-1));const y=T+H-(v/max)*H;i?c.lineTo(x,y):c.moveTo(x,y)});c.stroke()};series(vals,'#60a5fa');series(fails,'#ffaa00');
  c.fillStyle='#64748b';c.font='10px ui-monospace';c.fillText(String(max),8,T+4);c.fillText('0',20,h-B);c.fillStyle='#94a3b8';c.fillText('events/min',8,13);
  const ticks=Math.min(6,data.length);for(let i=0;i<ticks;i++){const idx=Math.round(i*(data.length-1)/Math.max(1,ticks-1));const x=L+(w-L-R)*(idx/Math.max(1,data.length-1));c.fillStyle='#64748b';c.fillText((data[idx]?.timestamp||'').slice(11,16),x-12,h-10)}
}
const ATTACK_MIX = [
  {key:'brute_force', label:'BRUTE FORCE', tech:'T1110.001', tone:'red'},
  {key:'password_spraying', label:'VPN / PASSWORD SPRAY', tech:'T1110.003', tone:'amber'},
  {key:'impossible_travel', label:'IMPOSSIBLE TRAVEL', tech:'T1078', tone:'cyan'},
  {key:'anomaly', label:'ML ANOMALY', tech:'ISOLATION FOREST', tone:'blue'},
];
function attackCount(obj,key){
  const direct=Number(obj?.[key]||0);
  if(direct) return direct;
  if(key==='password_spraying') return Number(obj?.vpn_spray||obj?.password_spray||0);
  return 0;
}
function renderAttackDistribution(obj){
  const root=$('mix');
  const items=ATTACK_MIX.map(x=>({...x,count:attackCount(obj,x.key)}));
  const total=items.reduce((n,x)=>n+x.count,0);
  const max=Math.max(1,...items.map(x=>x.count));
  root.innerHTML = items.map(x=>{
    const pct=total ? (x.count/total)*100 : 0;
    const width=x.count ? Math.max(5,(x.count/max)*100) : 0;
    return `<div class="mix-row">
      <div class="mix-label"><div class="mix-name">${x.label}</div><div class="mix-tech">${x.tech}</div></div>
      <div class="mix-track"><div class="mix-bar ${x.tone}" style="width:${width.toFixed(1)}%"></div></div>
      <div class="mix-value"><div class="mix-count">${x.count}</div><div class="mix-share">${pct.toFixed(0)}%</div></div>
    </div>`;
  }).join('') + `<div class="mix-legend"><span><i class="red"></i> BRUTE</span><span><i class="amber"></i> VPN/SPRAY</span><span><i class="cyan"></i> TRAVEL</span><span><i class="blue"></i> ML</span></div>`;
}
function renderFeed(inc){
  const el=$('feed');if(!inc.length){el.innerHTML='<div class="empty">No incidents yet.</div>';return;}el.innerHTML=inc.slice(0,8).map(x=>{const critical=x.severity==='CRITICAL';return `<div class="feed-item ${critical?'critical':''}"><div class="feed-main"><div class="feed-line"><span class="sev ${esc(x.severity)}">${esc(x.severity)}</span><span class="attack">${esc((x.attack_types||[]).join(' + '))}</span><span class="feed-time">${esc(x.last_seen||x.created_at||'')}</span></div><div class="feed-story">${esc(`Source ${((x.source_ips||[]).join(', '))||'n/a'} • ${((x.affected_users||[]).length)} users • risk ${x.risk_score}`)}</div></div><button class="btn" onclick="showIncident('${esc(x.incident_id)}')">INVESTIGATE →</button></div>`}).join('');
}
function renderAlertTable(alerts){
  const el=$('alertTable');if(!alerts.length){el.innerHTML='<div class="empty">No alerts match the current filters.</div>';return;}el.innerHTML=`<table class="table"><tr><th>TYPE</th><th>SEV</th><th>RISK</th><th>STATUS</th></tr>${alerts.map(x=>`<tr class="clickable" onclick="showAlert('${esc(x.alert_id)}')"><td>${esc(x.attack_type)}</td><td>${esc(x.severity)}</td><td>${esc(x.risk_score)}</td><td>${esc(x.status||'NEW')}</td></tr>`).join('')}</table>`;
}
function renderIncidentTable(incidents){
  const el=$('incidentTable');if(!incidents.length){el.innerHTML='<div class="empty">No incidents yet.</div>';return;}el.innerHTML=`<table class="table"><tr><th>SEV</th><th>TYPE</th><th>USERS</th><th>STATUS</th></tr>${incidents.map(x=>`<tr class="clickable" onclick="showIncident('${esc(x.incident_id)}')"><td>${esc(x.severity)}</td><td>${esc((x.attack_types||[]).join(', '))}</td><td>${(x.affected_users||[]).length}</td><td>${esc(x.status||'NEW')}</td></tr>`).join('')}</table>`;
}
function renderIncidentDetailTable(){
  const el=$('incidentDetailTable');if(!cachedIncidents.length){el.innerHTML='<div class="empty">No incidents yet.</div>';return;}el.innerHTML=`<table class="table"><tr><th>ID</th><th>TIME</th><th>SOURCE(S)</th><th>TARGETS</th><th>MITRE/TYPE</th><th>SEV</th><th>RISK</th><th>STATUS</th></tr>${cachedIncidents.map(x=>`<tr class="clickable" onclick="showIncident('${esc(x.incident_id)}')"><td>${esc(x.incident_id)}</td><td>${esc(x.last_seen||x.created_at||'')}</td><td>${esc((x.source_ips||[]).join(', '))}</td><td>${(x.affected_users||[]).length}</td><td>${esc((x.attack_types||[]).join(', '))}</td><td>${esc(x.severity)}</td><td>${esc(x.risk_score)}</td><td>${esc(x.status||'NEW')}</td></tr>`).join('')}</table>`;
}
function renderModel(h,m,e){
  const quality=e?.available===false?'<span>NOT GENERATED</span>':`<span>${esc(e.evaluation_type||'labelled evaluation')}</span>`;
  $('modelBox').innerHTML=`<div class="line"><span>Telemetry</span><span class="green">LIVE BACKEND EVENTS</span></div><div class="line"><span>Engine</span><span>Rules + Isolation Forest</span></div><div class="line"><span>Model loaded</span><span class="${h.model_loaded?'green':'amber'}">${h.model_loaded}</span></div><div class="line"><span>Tracked sources</span><span>${m.tracked_sources}</span></div><div class="line"><span>Geo users</span><span>${m.tracked_geo_users}</span></div><div class="line"><span>Evaluation</span>${quality}</div><div class="line"><span>Evaluation type</span><span>${esc(e?.evaluation_type||'not available')}</span></div>`;
  $('precision').textContent=e?.available===false?'—':pct(e.macro_precision);$('recall').textContent=`Recall ${e?.available===false?'—':pct(e.macro_recall)}`;$('f1').textContent=`F1 ${e?.available===false?'—':pct(e.macro_f1)}`;if(e?.not_real_world_benchmark===true){$('evalLabel').textContent='CONTROLLED EVALUATION • NOT REAL-WORLD ACCURACY';}else{$('evalLabel').textContent='EVALUATION';}
}
function modal(title,body){$('modalId').textContent=title;$('modalBody').innerHTML=body;$('modal').classList.add('show')};function closeModal(){$('modal').classList.remove('show')}
async function showAlert(id){const r=await apiFetch('/api/alerts/'+encodeURIComponent(id));if(!r.ok)return;const x=await r.json();modal('ALERT '+esc(x.alert_id),`<div class="detail-grid"><div class="detail-card"><div class="label">TYPE</div><div class="value">${esc(x.attack_type)}</div></div><div class="detail-card"><div class="label">SEVERITY</div><div class="value">${esc(x.severity)}</div></div><div class="detail-card"><div class="label">RISK</div><div class="value">${esc(x.risk_score)}</div></div><div class="detail-card"><div class="label">MITRE</div><div class="value">${esc(x.mitre)}</div></div></div><div class="pre" style="margin-top:10px">${esc(JSON.stringify(x,null,2))}</div><div style="display:flex;gap:7px;flex-wrap:wrap;margin-top:10px">${['NEW','INVESTIGATING','CONFIRMED','RESOLVED','FALSE_POSITIVE'].map(s=>`<button class="btn" onclick="updateAlert('${esc(x.alert_id)}','${s}')">${s}</button>`).join('')}</div>`) }
async function showIncident(id){const r=await apiFetch('/api/incidents/'+encodeURIComponent(id));if(!r.ok)return;const x=await r.json();$('incidentDossier').innerHTML=`<div class="pre">${esc(JSON.stringify(x,null,2))}</div>`;modal('INCIDENT '+esc(x.incident_id),`<div class="detail-grid"><div class="detail-card"><div class="label">SEVERITY</div><div class="value">${esc(x.severity)}</div></div><div class="detail-card"><div class="label">RISK</div><div class="value">${esc(x.risk_score)}</div></div><div class="detail-card"><div class="label">TYPES</div><div class="value">${esc((x.attack_types||[]).join(', '))}</div></div><div class="detail-card"><div class="label">USERS</div><div class="value">${(x.affected_users||[]).length}</div></div></div><div class="pre" style="margin-top:10px">${esc(JSON.stringify(x,null,2))}</div><div style="display:flex;gap:7px;flex-wrap:wrap;margin-top:10px">${['NEW','INVESTIGATING','CONFIRMED','RESOLVED','FALSE_POSITIVE'].map(s=>`<button class="btn" onclick="updateIncident('${esc(x.incident_id)}','${s}')">${s}</button>`).join('')}</div>`) }
async function updateAlert(id,status){const body={status};if(status==='FALSE_POSITIVE')body.false_positive_reason=prompt('Reason for false positive:','')||'';const r=await apiFetch('/api/alerts/'+encodeURIComponent(id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(r.ok){closeModal();refresh();}}
async function updateIncident(id,status){const body={status};if(status==='FALSE_POSITIVE')body.false_positive_reason=prompt('Reason for false positive:','')||'';const r=await apiFetch('/api/incidents/'+encodeURIComponent(id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(r.ok){closeModal();refresh();}}
async function investigate(){const q=$('investigateInput').value.trim();if(!q)return;try{const a=await apiFetch('/api/alerts/'+encodeURIComponent(q));if(a.ok)return showAlert(q);const ip=await apiFetch('/api/investigate/ip/'+encodeURIComponent(q));if(ip.ok){const x=await ip.json();if(x.source_ip===q){return modal('IP INVESTIGATION',`<div class="pre">${esc(JSON.stringify(x,null,2))}</div>`);}}const u=await apiFetch('/api/investigate/user/'+encodeURIComponent(q));if(u.ok){const x=await u.json();return modal('USER INVESTIGATION',`<div class="pre">${esc(JSON.stringify(x,null,2))}</div>`);}modal('NOT FOUND','<div class="empty">No alert, source IP, or user matched that identifier.</div>')}catch(e){modal('INVESTIGATION ERROR','<div class="empty">'+esc(e.message)+'</div>')}}


function geoXY(lat,lon){return {x:((lon+180)/360)*1000,y:((90-lat)/180)*500};}
function renderGeoContext(){
  const routes=$('geoContextRoutes'),nodes=$('geoContextNodes');
  if(!routes||!nodes)return;
  const hubs=[[-77.49,39.04],[8.68,50.11],[37.62,55.75],[77.21,28.61],[103.82,1.35],[-0.12,51.50]];
  const links=[[0,1],[0,3],[1,3],[1,5],[2,1],[2,3],[3,4],[5,4]];
  nodes.innerHTML=hubs.map(([lon,lat])=>{const p=geoXY(lat,lon);return `<circle class="geo-context-node" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3.1"/>`;}).join('');
  routes.innerHTML=links.map(([a,b])=>{
    const p1=geoXY(hubs[a][1],hubs[a][0]),p2=geoXY(hubs[b][1],hubs[b][0]);
    const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2-42;
    return `<path class="geo-route" d="M ${p1.x.toFixed(1)} ${p1.y.toFixed(1)} Q ${mx.toFixed(1)} ${my.toFixed(1)} ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}"/>`;
  }).join('');
}
async function renderGeo(){
  const r=await apiFetch('/api/geo?minutes=1440&limit=500');
  if(!r.ok)return;
  const data=await r.json();
  renderGeoContext();
  const layer=$('geoPoints'); layer.innerHTML='';
  const pts=data.points||[];
  const grouped=new Map();
  pts.slice(-150).forEach(p=>{
    const lat=Number(p.latitude), lon=Number(p.longitude);
    if(!Number.isFinite(lat)||!Number.isFinite(lon))return;
    const status=String(p.status||'').toLowerCase();
    const attack=String(p.attack_type||'').toLowerCase();
    const key=`${lat.toFixed(2)}|${lon.toFixed(2)}|${status}|${attack}`;
    const prior=grouped.get(key)||{...p,count:0}; prior.count += 1; grouped.set(key,prior);
  });
  grouped.forEach(p=>{
    const {x,y}=geoXY(Number(p.latitude),Number(p.longitude));
    const status=String(p.status||'').toLowerCase();
    const kind=status==='failure'?'danger':(String(p.attack_type||'').includes('impossible')?'amber':'success');
    const dot=document.createElement('div'); dot.className=`geo-point ${kind}`; dot.style.left=Math.max(1,Math.min(99,(x/1000)*100))+'%'; dot.style.top=Math.max(2,Math.min(98,(y/500)*100))+'%';
    dot.style.transform=`translate(-50%,-50%) scale(${Math.min(1.8,1+Math.log2(Math.max(1,p.count))*.14)})`;
    dot.title=`${p.city||'Unknown'}, ${p.country||''} • ${p.source_ip||''} • ${status||'event'} • ${p.count} event${p.count===1?'':'s'} • ${p.timestamp||''}`;
    layer.appendChild(dot);
  });
  $('geoSummary').innerHTML=`<div class="line"><span>Geo events</span><span class="green">${data.count||0}</span></div><div class="line"><span>Event source</span><span>${esc(data.source||'sqlite_events')}</span></div><div class="line"><span>Global signal layer</span><span class="cyan">ACTIVE</span></div>`;
}
function openTab(name){document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!==`view-${name}`));if(name==='incidents')renderIncidentDetailTable();if(name==='geo')renderGeo().catch(console.error);if(name==='dataset')document.getElementById('datasetFile')?.focus();}
let globePoints=[];let globePhase=0;let globeAnimFrame=null;
function drawGlobalGlobe(points=[]){
  const canvas=$('globeCanvas');if(!canvas)return;
  globePoints=points.filter(p=>Number.isFinite(Number(p.latitude))&&Number.isFinite(Number(p.longitude))).slice(-120);
  const rect=canvas.getBoundingClientRect();const dpr=devicePixelRatio||1;const w=Math.max(300,rect.width),h=Math.max(160,rect.height);canvas.width=w*dpr;canvas.height=h*dpr;
  const c=canvas.getContext('2d');c.setTransform(dpr,0,0,dpr,0,0);
  const draw=()=>{
    c.clearRect(0,0,w,h); const cx=w/2,cy=h/2+4,R=Math.min(h*.40,w*.28);
    c.beginPath();c.arc(cx,cy,R,0,Math.PI*2);c.fillStyle='rgba(0,10,18,.88)';c.fill();c.strokeStyle='rgba(0,240,255,.45)';c.lineWidth=1.2;c.stroke();
    c.save();c.beginPath();c.arc(cx,cy,R,0,Math.PI*2);c.clip();
    c.strokeStyle='rgba(0,240,255,.14)';c.lineWidth=.8;
    for(let lon=-60;lon<=60;lon+=30){const x=cx+(lon/90)*R*Math.cos((globePhase*.002)%6.28);c.beginPath();c.ellipse(x,cy,R*Math.max(.08,Math.sqrt(Math.max(0,1-Math.pow(Math.abs(lon)/90,2)))),R,.1,0,Math.PI*2);c.stroke();}
    for(let lat=-60;lat<=60;lat+=30){const y=cy-(lat/90)*R;c.beginPath();c.ellipse(cx,y,R,R*.18,0,0,Math.PI*2);c.stroke();}
    // context signal hubs (presentation layer, not included in event counts)
    const hubs=[[-77.49,39.04],[8.68,50.11],[37.62,55.75],[77.21,28.61],[-0.12,51.50]];
    const project=(lat,lon)=>{const lambda=(lon*Math.PI/180)+(globePhase*.0007);const phi=lat*Math.PI/180;const x=cx+R*Math.sin(lambda)*Math.cos(phi);const y=cy-R*Math.sin(phi);const visible=Math.cos(lambda)*Math.cos(phi)>-0.15;return {x,y,visible};};
    hubs.forEach(([lon,lat],i)=>{const a=project(lat,lon);const b=project(lat+((i%2)?2:-2),lon+18);if(a.visible&&b.visible){c.strokeStyle='rgba(0,240,255,.16)';c.setLineDash([4,5]);c.beginPath();c.moveTo(a.x,a.y);c.quadraticCurveTo((a.x+b.x)/2,(a.y+b.y)/2-14,b.x,b.y);c.stroke();c.setLineDash([]);}if(a.visible){c.fillStyle='#00f0ff';c.shadowBlur=8;c.shadowColor='#00f0ff';c.beginPath();c.arc(a.x,a.y,2.2,0,Math.PI*2);c.fill();c.shadowBlur=0;}});
    globePoints.forEach(p=>{const a=project(Number(p.latitude),Number(p.longitude));if(!a.visible)return;const fail=String(p.status||'').toLowerCase()==='failure';c.fillStyle=fail?'#ff2a55':'#00ff66';c.shadowBlur=8;c.shadowColor=c.fillStyle;c.beginPath();c.arc(a.x,a.y,2.6,0,Math.PI*2);c.fill();c.shadowBlur=0;});
    c.restore();
    c.fillStyle='#64748b';c.font='8px ui-monospace';c.fillText(`${globePoints.length} GEO EVENTS`,10,h-10);
    globePhase=(globePhase+1)%100000;globeAnimFrame=requestAnimationFrame(draw);
  };
  if(globeAnimFrame)cancelAnimationFrame(globeAnimFrame);draw();
}
async function refreshGlobe(){try{const r=await apiFetch('/api/geo?minutes=1440&limit=500');if(!r.ok)return;const d=await r.json();drawGlobalGlobe(d.points||[]);}catch(e){console.debug('globe refresh',e.message)}}
function selectedDataset(){const f=$('datasetFile').files[0]; if(!f) throw new Error('Choose a CSV dataset first.'); return f;}
async function datasetPost(endpoint){
  const f=selectedDataset();
  if(f.size>12*1024*1024) throw new Error('CSV exceeds 12 MB upload limit.');
  const content=await f.text();
  const r=await apiFetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:f.name,content})});
  const data=await r.json().catch(()=>({detail:'Invalid server response'}));
  if(!r.ok) throw new Error(data.detail||`Dataset request failed (${r.status})`);
  $('datasetResult').textContent=JSON.stringify(data,null,2);
  const ev=data.held_out_test||data.validation||{};
  const iev=data.held_out_test||{}; const metric=data.event_level||iev; const inc=data.incident_level||iev.incident_level||{};
  $('datasetStatus').innerHTML=`<div class="dataset-kpi"><div class="detail-card"><div class="label">ROWS</div><div class="value">${esc(data.rows??'—')}</div></div><div class="detail-card"><div class="label">PRECISION</div><div class="value">${pct(metric.precision)}</div></div><div class="detail-card"><div class="label">RECALL</div><div class="value">${pct(metric.recall)}</div></div><div class="detail-card"><div class="label">F1</div><div class="value">${pct(metric.f1)}</div></div><div class="detail-card"><div class="label">FPR</div><div class="value">${pct(metric.fpr)}</div></div><div class="detail-card"><div class="label">ALERT/TP</div><div class="value">${inc.alert_to_true_positive_ratio==null?'—':Number(inc.alert_to_true_positive_ratio).toFixed(2)}</div></div><div class="detail-card"><div class="label">MTTD</div><div class="value">${inc.mttd_seconds==null?'—':Number(inc.mttd_seconds).toFixed(2)+'s'}</div></div><div class="detail-card"><div class="label">COMPRESSION</div><div class="value">${inc.incident_compression==null?'—':Number(inc.incident_compression).toFixed(1)+'×'}</div></div></div>`;
  await refresh();
}
async function evaluateDataset(){try{await datasetPost('/api/dataset/evaluate')}catch(e){modal('DATASET EVALUATION ERROR',`<div class="empty">${esc(e.message)}</div>`)}}
async function trainDataset(){try{await datasetPost('/api/dataset/train')}catch(e){modal('DATASET TRAINING ERROR',`<div class="empty">${esc(e.message)}</div>`)}}
async function analyzeDataset(){try{await datasetPost('/api/dataset/analyze')}catch(e){modal('DATASET ANALYSIS ERROR',`<div class="empty">${esc(e.message)}</div>`)}}

function calculateRisk(){const N=Number($('sliderN').value),k=Number($('sliderK').value),M=Number($('sliderM').value);const combinations=N*k,pSingle=k/M,pComp=1-Math.pow(1-pSingle,N);$('valN').textContent=N.toLocaleString();$('valK').textContent=k;$('valM').textContent=M.toLocaleString();$('resProb').textContent=(pComp*100).toFixed(1)+'%';$('resComb').textContent=combinations.toLocaleString();$('resSingle').textContent=(pSingle*100).toFixed(2)+'%';const tier=$('resTier'),g=$('gauge'),a=$('resAction');if(pComp>.70){tier.textContent='CRITICAL BREACH RISK';tier.style.color='var(--red)';g.style.borderColor='var(--red)';a.textContent='Enforce phishing-resistant MFA / FIDO2';a.style.color='var(--red)'}else if(pComp>.35){tier.textContent='ELEVATED VULNERABILITY';tier.style.color='var(--amber)';g.style.borderColor='var(--amber)';a.textContent='Strengthen MFA + lockout';a.style.color='var(--amber)'}else{tier.textContent='LOW ATTACK EXPOSURE';tier.style.color='var(--green)';g.style.borderColor='var(--green)';a.textContent='Routine baseline monitoring';a.style.color='var(--green)'}}
['sliderN','sliderK','sliderM'].forEach(id=>$(id).addEventListener('input',calculateRisk));calculateRisk();

async function refresh(){
 try{
  const [h,m,a,i,act,e]=await Promise.all([
    fetch('/health').then(r=>r.json()),apiFetch('/api/metrics').then(r=>r.json()),apiFetch('/api/alerts?limit=12'+($('filterAttack').value?'&attack_type='+encodeURIComponent($('filterAttack').value):'')+($('filterSeverity').value?'&severity='+encodeURIComponent($('filterSeverity').value):'')+($('filterStatus').value?'&status='+encodeURIComponent($('filterStatus').value):'')+($('filterIp').value?'&source_ip='+encodeURIComponent($('filterIp').value):'')).then(r=>r.json()),apiFetch('/api/incidents?limit=12').then(r=>r.json()),apiFetch('/api/activity?minutes=60').then(r=>r.json()),apiFetch('/api/evaluation').then(r=>r.ok?r.json():{available:false}).catch(()=>({available:false}))
  ]);
  cachedIncidents=i;
  $('health').textContent=h.model_loaded?'API HEALTHY • ML LOADED':'API HEALTHY • RULE-ONLY';$('health').className='badge '+(h.model_loaded?'ok':'');
  $('events').textContent=m.total_events.toLocaleString();$('alerts').textContent=m.total_alerts.toLocaleString();$('incidents').textContent=m.incidents.toLocaleString();$('critical').textContent=`${m.critical_alerts} CRITICAL`;$('epm').textContent=`${m.events_per_minute} EPM`;$('threats').textContent=(Number(m.alerts_by_type?.brute_force||0)+Number(m.alerts_by_type?.password_spraying||0)).toLocaleString();$('tracked').textContent=`${m.tracked_sources} SRC`;
  drawLine($('activity'),act);renderAttackDistribution(m.alerts_by_type||{});refreshGlobe();renderFeed(i);renderAlertTable(a);renderIncidentTable(i);renderModel(h,m,e);renderIncidentDetailTable();
  if(document.getElementById('view-geo') && !document.getElementById('view-geo').classList.contains('hidden')) { renderGeo().catch(console.error); }
 }catch(err){$('health').textContent='API OFFLINE';$('health').className='badge bad';console.error(err)}}
refresh();setInterval(refresh,2500);window.addEventListener('resize',refresh);window.addEventListener('click',e=>{if(e.target===$('modal'))closeModal()});
</script>
</body>
</html>
'''

ALL_IN_ONE_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BANKAI — ALL-IN-ONE LAB</title>
<style>
:root{--bg:#04060a;--panel:#090e17;--line:rgba(0,255,102,.16);--green:#00ff66;--cyan:#00f0ff;--red:#ff2a55;--amber:#ffaa00;--blue:#60a5fa;--text:#e2e8f0;--muted:#64748b}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:ui-monospace,Consolas,monospace}
body{background-image:radial-gradient(circle at 50% 0%,rgba(0,255,102,.05),transparent 60%),linear-gradient(rgba(0,255,102,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,102,.02) 1px,transparent 1px);background-size:100% 100%,32px 32px,32px 32px}
header{position:sticky;top:0;z-index:10;border-bottom:1px solid var(--line);background:rgba(4,6,10,.96);padding:12px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px}.brand{display:flex;align-items:center;gap:10px}.mark{color:var(--green);font-weight:900;font-size:18px}.title{font-size:16px;font-weight:900}.sub{font-size:9px;color:var(--muted);margin-top:3px}.topbadges{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}.badge{font-size:9px;padding:5px 8px;border:1px solid rgba(148,163,184,.18);color:var(--muted)}.ok{color:var(--green);border-color:rgba(0,255,102,.3)}.warn{color:var(--amber);border-color:rgba(255,170,0,.3)}.bad{color:var(--red);border-color:rgba(255,42,85,.35)}
main{max-width:1600px;margin:auto;padding:12px;display:grid;grid-template-columns:1.03fr 1.25fr 1.03fr;gap:12px;align-items:stretch}.col{min-width:0}.section{background:rgba(9,14,23,.95);border:1px solid var(--line);position:relative;overflow:hidden}.section:after{content:"";position:absolute;right:-1px;bottom:-1px;width:8px;height:8px;border-right:2px solid var(--green);border-bottom:2px solid var(--green)}.head{padding:10px 12px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:8px}.head b{font-size:10px;letter-spacing:.06em}.head span{font-size:8px;color:var(--muted)}.body{padding:11px}.body.scroll{max-height:calc(100vh - 88px);overflow:auto}
.targetbar{border:1px solid rgba(0,255,102,.18);background:#020617;padding:8px;font-size:9px;color:#94a3b8;margin-bottom:9px}.targetbar b{color:var(--green)}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:8px}.card{padding:10px;background:#020617;border:1px solid var(--line)}.label{font-size:8px;color:var(--muted)}.num{font-size:20px;font-weight:900;margin-top:5px;color:#fff}.green{color:var(--green)}.cyan{color:var(--cyan)}.red{color:var(--red)}.amber{color:var(--amber)}.blue{color:var(--blue)}
.threat{margin-top:8px;padding:9px;border:1px solid rgba(0,255,102,.22);background:rgba(0,255,102,.03);font-size:9px}.threat.warn{border-color:rgba(255,170,0,.45);background:rgba(120,53,15,.12)}.threat.bad{border-color:rgba(255,42,85,.65);background:rgba(127,29,29,.18);animation:pulse 1.5s infinite}@keyframes pulse{50%{box-shadow:0 0 18px rgba(255,42,85,.13)}}
button{font:inherit;cursor:pointer}.attack-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.attack{padding:11px;background:#020617;border:1px solid rgba(148,163,184,.14);text-align:left;color:#fff}.attack b{display:block;font-size:9px}.attack span{display:block;font-size:8px;color:var(--muted);margin-top:4px}.attack:hover{border-color:rgba(0,255,102,.4)}.normal{color:var(--green)}.brute{color:var(--red)}.spray{color:var(--amber)}.travel{color:var(--cyan)}
.run{margin-top:8px;padding:9px;border:1px dashed rgba(148,163,184,.18);font-size:8px;line-height:1.5}.flow{display:grid;grid-template-columns:1fr 20px 1fr 20px 1fr;gap:6px;align-items:center}.node{background:#020617;border:1px solid var(--line);padding:10px 5px;text-align:center}.node b{display:block;font-size:8px}.node span{display:block;font-size:7px;color:var(--muted);margin-top:4px}.arrow{color:var(--green);text-align:center}.log{height:170px;overflow:auto;background:#02050a;border:1px solid rgba(148,163,184,.12);padding:8px;font-size:8px}.entry{padding:5px 0;border-bottom:1px dashed rgba(148,163,184,.08)}.time{color:var(--muted)}
.mix{display:grid;gap:8px}.mixrow{display:grid;grid-template-columns:110px 1fr 26px;gap:7px;align-items:center;font-size:8px}.track{height:13px;background:#020617;border:1px solid rgba(148,163,184,.1)}.fill{height:100%;min-width:0}.inc{padding:7px;border:1px solid rgba(148,163,184,.12);background:#020617;margin-bottom:6px;font-size:8px;line-height:1.45}.inc.crit{border-color:rgba(255,42,85,.38)}
.chart{height:95px;border:1px solid rgba(148,163,184,.12);background:#02050a}.geo{height:170px;position:relative;border:1px solid rgba(148,163,184,.12);background:#02060b;overflow:hidden}.geo-map-img{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;opacity:.95}.geo-canvas{position:absolute;inset:0;width:100%;height:100%;display:block}.geo-note{position:absolute;left:7px;top:7px;font-size:7px;color:var(--muted);z-index:2}.geo-legend{position:absolute;right:7px;bottom:7px;display:flex;gap:8px;padding:5px 7px;border:1px solid rgba(148,163,184,.15);background:rgba(2,6,23,.82);font-size:7px;color:#94a3b8;z-index:2}.dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:3px}.dot.danger{background:var(--red);box-shadow:0 0 7px var(--red)}.dot.context{background:var(--cyan);box-shadow:0 0 7px var(--cyan)}
.field{margin-bottom:7px}.field label{display:block;font-size:8px;color:var(--muted);margin-bottom:4px}.field input{width:100%;padding:8px;background:#02060b;color:#fff;border:1px solid rgba(148,163,184,.15);font:inherit;font-size:9px}.primary{width:100%;padding:9px;background:#07131b;border:1px solid rgba(0,255,102,.4);color:var(--green);font-weight:900}.result{margin-top:7px;padding:8px;background:#020617;border:1px solid rgba(148,163,184,.12);font-size:8px;min-height:33px}.small{font-size:8px;color:var(--muted)}
.footer{max-width:1600px;margin:auto;padding:0 12px 12px;color:#64748b;font-size:8px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:8px}
@media(max-width:1200px){main{grid-template-columns:1fr}.body.scroll{max-height:none}.section{min-height:auto}}
</style></head>
<body>
<header><div class="brand"><span class="mark">&gt;_</span><div><div class="title">BANKAI // ALL-IN-ONE LAB</div><div class="sub">ONE BROWSER TAB • ATTACKER / OBSERVER / TARGET SERVER</div></div></div><div class="topbadges"><span id="obsBadge" class="badge ok">● OBSERVER LIVE</span><span id="targetBadge" class="badge ok">● TARGET LIVE</span><span id="gatewayBadge" class="badge ok">● GATEWAY LIVE</span><span id="riskBadge" class="badge ok">RISK 0</span></div></header>
<main>
<section class="col section"><div class="head"><b><span class="green">01</span> / ATTACKER</b><span>REAL HTTP CLIENT</span></div><div class="body scroll">
<div class="targetbar">TARGET AUTH SERVICE<br><b id="targetUrl">__TARGET_URL__</b></div>
<div class="attack-grid">
<button class="attack normal" onclick="scenario('normal')"><b>NORMAL LOGIN</b><span>1 × HTTP 200</span></button>
<button class="attack brute" onclick="scenario('brute_force')"><b>BRUTE FORCE LAB</b><span>12 failures / 1 user</span></button>
<button class="attack spray" onclick="scenario('vpn_spray')"><b>VPN / PASSWORD SPRAY</b><span>15 failures / 15 users</span></button>
<button class="attack travel" onclick="scenario('impossible_travel')"><b>IMPOSSIBLE TRAVEL</b><span>Delhi → Ashburn</span></button>
</div>
<div id="attackRun" class="run">READY — choose a controlled scenario.</div>
<div class="cards" style="margin-top:8px"><div class="card"><div class="label">REQUESTS</div><div id="aReq" class="num">0</div></div><div class="card"><div class="label">HTTP 200</div><div id="aOk" class="num green">0</div></div><div class="card"><div class="label">HTTP 401</div><div id="aFail" class="num red">0</div></div><div class="card"><div class="label">LAST HTTP</div><div id="aLast" class="num cyan">—</div></div></div>
<div class="head" style="margin:12px -11px 8px"><b>LIVE HTTP RUN LOG</b><span>REAL 200 / 401</span></div><div id="attackLog" class="log"></div>
<div class="head" style="margin:12px -11px 8px"><b>CLIENT → AUTH → GATEWAY → SOC</b><span>BACKEND FLOW</span></div><div class="flow"><div class="node"><b>CLIENT</b><span>real request</span></div><div class="arrow">→</div><div class="node"><b>AUTH</b><span>:8200</span></div><div class="arrow">→</div><div class="node"><b>GATEWAY</b><span>:8100</span></div></div>
</div></section>
<section class="col section"><div class="head"><b><span class="cyan">02</span> / OBSERVER</b><span>LIVE SOC</span></div><div class="body scroll">
<div class="cards"><div class="card"><div class="label">EVENTS</div><div id="oEvents" class="num">0</div></div><div class="card"><div class="label">ALERTS</div><div id="oAlerts" class="num">0</div></div><div class="card"><div class="label">INCIDENTS</div><div id="oIncidents" class="num">0</div></div><div class="card"><div class="label">CRITICAL</div><div id="oCritical" class="num red">0</div></div></div>
<div class="threat" id="obsThreat"><b>● DETECTION ENGINE: READY</b><div id="obsThreatText" class="small">Rules + Isolation Forest</div></div>
<div class="head" style="margin:12px -11px 8px"><b>ATTACK DISTRIBUTION</b><span>LIVE API</span></div><div id="mix" class="mix"></div>
<div class="head" style="margin:12px -11px 8px"><b>AUTHENTICATION ACTIVITY</b><span>30-MIN WINDOW</span></div><canvas id="activity" class="chart"></canvas>
<div class="head" style="margin:12px -11px 8px"><b>GLOBAL GEO ACTIVITY</b><span>SQLITE COORDINATES</span></div><div class="geo"><img src="/dashboard/world_map.svg" alt="World map" class="geo-map-img"><canvas id="geo" class="geo-canvas"></canvas><div class="geo-note">AUTH EVENTS / SIGNAL ROUTES</div><div class="geo-legend"><span><i class="dot danger"></i>ATTACK</span><span><i class="dot context"></i>GLOBAL SIGNAL</span></div></div>
<div class="head" style="margin:12px -11px 8px"><b>LATEST DETECTION STORIES</b><span>BACKEND</span></div><div id="incidents"></div>
</div></section>
<section class="col section"><div class="head"><b><span class="red">03</span> / TARGET SERVER</b><span>AUTH + PROTECTION</span></div><div class="body scroll">
<div class="cards"><div class="card"><div class="label">AUTH</div><div id="tAuth" class="num green">UP</div></div><div class="card"><div class="label">GATEWAY</div><div id="tGateway" class="num green">UP</div></div><div class="card"><div class="label">SENTINEL</div><div id="tSentinel" class="num green">UP</div></div><div class="card"><div class="label">RISK</div><div id="tRisk" class="num">0</div></div></div>
<div id="protection" class="threat"><b id="protectTitle">● TARGET PROTECTION: NORMAL</b><div id="protectText" class="small">Monitoring Sentinel risk.</div></div>
<div class="head" style="margin:12px -11px 8px"><b>DIRECT REAL LOGIN</b><span>HTTP 200 / 401</span></div>
<div class="field"><label>USERNAME</label><input id="username" value="alice@company.local"></div><div class="field"><label>PASSWORD</label><input id="password" type="password" placeholder="Enter lab password"></div><div class="field"><label>SOURCE IP</label><input id="sourceIp" value="127.0.0.1" inputmode="numeric" autocomplete="off"></div><button class="primary" onclick="directLogin()">SEND REAL AUTH REQUEST →</button><div id="loginResult" class="result">Waiting for authentication…</div>
<div class="head" style="margin:12px -11px 8px"><b>REAL REQUEST PIPELINE</b><span>BACKEND STATE</span></div><div class="flow"><div class="node"><b>AUTH :8200</b><span>200 / 401</span></div><div class="arrow">→</div><div class="node"><b>GATEWAY :8100</b><span>forward</span></div><div class="arrow">→</div><div class="node"><b>SENTINEL :8000</b><span>detect</span></div></div>
<div class="head" style="margin:12px -11px 8px"><b>RECENT TARGET EVENTS</b><span>LIVE</span></div><div id="targetLog" class="log"></div>
</div></section>
</main>
<div class="footer"><span>CONTROLLED PRIVATE/LOOPBACK LAB • REAL HTTP • NO PUBLIC TARGETS</span><span>Single-Laptop mode: one browser tab, three live sections.</span></div>
<script>
const TARGET='__TARGET_URL__';
const $=id=>document.getElementById(id);
function logAttack(s){const d=document.createElement('div');d.className='entry';d.innerHTML=s;$('attackLog').prepend(d);while($('attackLog').children.length>80)$('attackLog').lastChild.remove()}
async function postTarget(payload){const r=await fetch(TARGET,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let j={};try{j=await r.json()}catch{};return {status:r.status,body:j}}
function setRun(text){$('attackRun').textContent=text}
async function scenario(kind){
 const specs={
  normal:[{u:'alice@company.local',p:'Alice123!',ip:'127.0.0.1',type:'client'}],
  brute_force:Array.from({length:12},(_,i)=>({u:'alice@company.local',p:'bad-'+i,ip:'10.0.0.81',type:'client',city:'Moscow',country:'Russia',lat:55.7558,lon:37.6176})),
  vpn_spray:['alice','bob','charlie','david','eve','frank','grace','heidi','ivan','judy','alice2','bob2','charlie2','david2','eve2'].map((u,i)=>({u:u+'@company.local',p:'wrong-'+i,ip:'10.8.0.5',type:'vpn',city:'Berlin VPN',country:'Germany',lat:52.52,lon:13.405})),
  impossible_travel:[{u:'alice@company.local',p:'Alice123!',ip:'10.0.0.24',type:'client',city:'Delhi',country:'India',lat:28.6139,lon:77.2090},{u:'alice@company.local',p:'Alice123!',ip:'10.0.0.42',type:'client',city:'Ashburn',country:'USA',lat:38.9072,lon:-77.0369}]
 }[kind];
 let ok=0,fail=0;setRun(kind.toUpperCase()+' RUNNING');$('aReq').textContent='0';$('aOk').textContent='0';$('aFail').textContent='0';
 for(let i=0;i<specs.length;i++){
  const x=specs[i];const r=await postTarget({username:x.u,password:x.p,source_ip:x.ip,source_type:x.type,city:x.city,country:x.country,latitude:x.lat,longitude:x.lon});
  if(r.status===200)ok++;if(r.status===401)fail++;$('aReq').textContent=String(i+1);$('aOk').textContent=String(ok);$('aFail').textContent=String(fail);$('aLast').textContent=String(r.status);logAttack(`<span class="time">${new Date().toISOString()}</span> • ${kind.toUpperCase()} • ${x.u} • HTTP <span class="${r.status===200?'green':'red'}">${r.status}</span>`);await new Promise(z=>setTimeout(z,110));
 }
 setRun('DONE — '+specs.length+' requests • '+ok+' successes • '+fail+' failures');await refreshAll();
}
async function directLogin(){const u=$('username').value,p=$('password').value,ip=$('sourceIp').value.trim()||'127.0.0.1';const r=await postTarget({username:u,password:p,source_ip:ip,source_type:'client'});$('loginResult').innerHTML=`HTTP <b class="${r.status===200?'green':'red'}">${r.status}</b> • ${r.body.forwarded?'forwarded to Gateway':'not forwarded'}`;await refreshAll()}
function renderMix(a){const rows=[['brute_force','BRUTE FORCE','red'],['password_spraying','PASSWORD SPRAY','amber'],['vpn_spray','VPN SPRAY','amber'],['impossible_travel','IMPOSSIBLE TRAVEL','cyan'],['ml_anomaly','ML ANOMALY','blue']];const max=Math.max(1,...rows.map(x=>Number(a[x[0]]||0)));$('mix').innerHTML=rows.map(([k,n,c])=>`<div class="mixrow"><span>${n}</span><div class="track"><div class="fill" style="width:${Math.round(Number(a[k]||0)/max*100)}%;background:${c==='red'?'var(--red)':c==='amber'?'var(--amber)':c==='cyan'?'var(--cyan)':'var(--blue)'}"></div></div><b>${Number(a[k]||0)}</b></div>`).join('')}
function drawActivity(points){const c=$('activity'),ctx=c.getContext('2d'),w=c.clientWidth||500,h=c.clientHeight||95,dpr=window.devicePixelRatio||1;c.width=w*dpr;c.height=h*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);ctx.strokeStyle='rgba(0,255,102,.09)';for(let y=15;y<h;y+=20){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}const mx=Math.max(1,...points.map(p=>Number(p.total||0)));ctx.strokeStyle='#00f0ff';ctx.lineWidth=2;ctx.beginPath();points.forEach((p,i)=>{const x=points.length<=1?0:(i/(points.length-1))*w;const y=h-12-(Number(p.total||0)/mx)*(h-24);if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y)});ctx.stroke()}
function drawGeo(points){const c=$('geo'),ctx=c.getContext('2d'),w=c.clientWidth||500,h=c.clientHeight||150,dpr=window.devicePixelRatio||1;c.width=w*dpr;c.height=h*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);ctx.strokeStyle='rgba(0,240,255,.08)';for(let i=1;i<8;i++){ctx.beginPath();ctx.moveTo((i/8)*w,0);ctx.lineTo((i/8)*w,h);ctx.stroke()}for(let j=1;j<4;j++){ctx.beginPath();ctx.moveTo(0,(j/4)*h);ctx.lineTo(w,(j/4)*h);ctx.stroke()}const pts=points.slice(0,50).map(p=>({x:((Number(p.longitude)+180)/360)*w,y:((90-Number(p.latitude))/180)*h}));ctx.strokeStyle='rgba(0,240,255,.45)';ctx.setLineDash([5,6]);for(let i=1;i<pts.length;i++){ctx.beginPath();ctx.moveTo(pts[i-1].x,pts[i-1].y);ctx.quadraticCurveTo((pts[i-1].x+pts[i].x)/2,Math.min(pts[i-1].y,pts[i].y)-10,pts[i].x,pts[i].y);ctx.stroke()}ctx.setLineDash([]);for(const [i,p] of pts.entries()){ctx.fillStyle=i<8?'#ff2a55':'#00f0ff';ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=10;ctx.beginPath();ctx.arc(p.x,p.y,i<8?4:2.5,0,Math.PI*2);ctx.fill()}ctx.shadowBlur=0}
function renderIncidents(items){$('incidents').innerHTML=items.length?items.map(x=>`<div class="inc ${x.severity==='CRITICAL'?'crit':''}"><b class="${x.severity==='CRITICAL'?'red':x.severity==='HIGH'?'amber':'cyan'}">${x.severity}</b> • ${x.attack_types[0].toUpperCase()} • risk ${x.risk_score} • ${x.mitre}<br><span class="small">${x.evidence||''}</span></div>`).join(''):'<div class="small">No incidents yet.</div>'}
function renderTargetLog(items){$('targetLog').innerHTML=items.length?items.map(x=>`<div class="entry"><span class="time">${x.time}</span> • ${x.username} • ${x.source_ip} • HTTP <b class="${x.status===200?'green':'red'}">${x.status}</b> • ${x.forwarded?'FORWARDED':'PENDING'}</div>`).join(''):'<div class="small">Waiting for target events…</div>'}
async function refreshAll(){
 try{
  const [all,th,logs]=await Promise.all([fetch('/public/allinone').then(r=>r.json()),fetch('__TARGET_HEALTH__').then(r=>r.json()),fetch('__TARGET_LOGS__').then(r=>r.json())]);
  const m=all.metrics||{};const p=all.protection||{};
  $('oEvents').textContent=String(m.total_events||0);$('oAlerts').textContent=String(m.total_alerts||0);$('oIncidents').textContent=String(m.incidents||0);$('oCritical').textContent=String(m.critical_alerts||0);
  $('tRisk').textContent=Number(p.risk||0).toFixed(1);$('riskBadge').textContent='RISK '+Number(p.risk||0).toFixed(1);$('riskBadge').className='badge '+(p.shutdown_alert?'bad':Number(p.risk||0)>=50?'warn':'ok');
  $('targetBadge').textContent=p.shutdown_alert?'⚠ TARGET SHUTDOWN ALERT':'● TARGET LIVE';$('targetBadge').className='badge '+(p.shutdown_alert?'bad':Number(p.risk||0)>=50?'warn':'ok');
  $('gatewayBadge').textContent=th.gateway?'● GATEWAY LIVE':'● GATEWAY OFFLINE';$('gatewayBadge').className='badge '+(th.gateway?'ok':'bad');
  $('tGateway').textContent=th.gateway?'UP':'DOWN';$('tGateway').className='num '+(th.gateway?'green':'red');$('tSentinel').textContent=th.sentinel?'UP':'DOWN';$('tSentinel').className='num '+(th.sentinel?'green':'red');
  if(p.shutdown_alert){$('protection').className='threat bad';$('protectTitle').textContent='⚠ TARGET SHUTDOWN ALERT';$('protectText').textContent=`CRITICAL RISK ${Number(p.risk||0).toFixed(1)}/100 • ${p.action||'CONTAINMENT REQUIRED'}`;}
  else if(Number(p.risk||0)>=50){$('protection').className='threat warn';$('protectTitle').textContent='▲ ELEVATED THREAT';$('protectText').textContent=`RISK ${Number(p.risk||0).toFixed(1)}/100 • ${p.action||'MONITOR'}`;}
  else{$('protection').className='threat';$('protectTitle').textContent='● TARGET PROTECTION: NORMAL';$('protectText').textContent='Monitoring Sentinel risk.';}
  $('obsThreatText').textContent=`Rules + Isolation Forest • ${Number(m.total_alerts||0)} alerts / ${Number(m.incidents||0)} incidents`;
  drawActivity(all.activity||[]);drawGeo(all.geo||[]);renderMix(m.alerts_by_type||{});renderIncidents(all.incidents||[]);renderTargetLog(logs.items||[]);
 }catch(e){console.error(e)}
}
setInterval(refreshAll,1800);refreshAll();
</script></body></html>'''

TARGET_HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BANKAI // TARGET SERVER</title><style>
:root{--bg:#04060a;--panel:#090e17;--line:rgba(0,255,102,.16);--green:#00ff66;--cyan:#00f0ff;--red:#ff2a55;--amber:#ffaa00;--text:#e2e8f0;--muted:#64748b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,Consolas,monospace;background-image:radial-gradient(circle at 50% 0%,rgba(0,255,102,.05),transparent 60%),linear-gradient(rgba(0,255,102,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,102,.02) 1px,transparent 1px);background-size:100% 100%,32px 32px,32px 32px}header{border-bottom:1px solid var(--line);padding:12px 18px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:rgba(4,6,10,.96);z-index:5}.brand{display:flex;gap:10px;align-items:center}.mark{color:var(--green);font-weight:900}.title{font-size:16px;font-weight:900}.sub{font-size:9px;color:var(--muted);margin-top:3px}.badges{display:flex;gap:7px;flex-wrap:wrap}.badge{padding:5px 8px;border:1px solid rgba(148,163,184,.18);font-size:9px;color:var(--muted)}.ok{color:var(--green);border-color:rgba(0,255,102,.3)}.bad{color:var(--red);border-color:rgba(255,42,85,.35)}.warn{color:var(--amber);border-color:rgba(255,170,0,.3)}main{max-width:1450px;margin:auto;padding:16px}.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:12px}.panel{background:rgba(9,14,23,.94);border:1px solid var(--line);padding:14px;position:relative}.panel:after{content:"";position:absolute;right:-1px;bottom:-1px;width:8px;height:8px;border-right:2px solid var(--green);border-bottom:2px solid var(--green)}.eyebrow{color:var(--green);font-size:9px;letter-spacing:.08em}.hero h1{font-size:46px;line-height:.9;margin:16px 0 12px;color:#fff}.hero h1 span{color:var(--green)}.hero p{font-size:10px;line-height:1.75;color:#94a3b8}.chips{display:flex;gap:7px;flex-wrap:wrap}.chip{font-size:8px;border:1px solid var(--line);padding:5px 7px;color:#94a3b8}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}.card{background:#020617;border:1px solid var(--line);padding:11px}.card .label{font-size:8px;color:var(--muted)}.card b{display:block;font-size:22px;margin-top:6px}.green{color:var(--green)}.cyan{color:var(--cyan)}.red{color:var(--red)}.amber{color:var(--amber)}.threat{margin-top:12px;padding:10px;border:1px solid rgba(0,255,102,.2);background:rgba(0,255,102,.03);font-size:10px}.threat.elevated{border-color:rgba(255,170,0,.45);background:rgba(120,53,15,.12);color:#fde68a}.threat.shutdown{border-color:rgba(255,42,85,.65);background:rgba(127,29,29,.18);color:#fecdd3;animation:pulse 1.7s infinite}@keyframes pulse{50%{box-shadow:0 0 18px rgba(255,42,85,.12)}}.panel-title{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid rgba(148,163,184,.12);padding-bottom:9px;margin-bottom:10px;font-size:10px;font-weight:900}.panel-title span{color:var(--muted);font-size:8px;font-weight:600}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.field label{display:block;color:var(--muted);font-size:8px;margin-bottom:5px}.field input{width:100%;padding:9px;background:#02060b;color:#fff;border:1px solid rgba(148,163,184,.15)}button{font:inherit;cursor:pointer}.primary{width:100%;padding:10px;margin-top:9px;background:#07131b;border:1px solid rgba(0,255,102,.4);color:var(--green);font-weight:900}.result{margin-top:9px;padding:9px;background:#02060b;border:1px solid rgba(148,163,184,.12);font-size:10px;min-height:38px}.flow{display:grid;grid-template-columns:1fr 25px 1fr 25px 1fr;gap:7px;align-items:center}.node{border:1px solid var(--line);padding:13px 7px;text-align:center;background:#020617}.node b{display:block;font-size:10px}.node span{font-size:8px;color:var(--muted)}.arrow{color:var(--green);text-align:center}.log{height:285px;overflow:auto;background:#02050a;border:1px solid rgba(148,163,184,.12);padding:10px}.row{display:grid;grid-template-columns:70px 80px 1fr 90px;padding:7px 0;border-bottom:1px dashed rgba(148,163,184,.08);font-size:9px}.small{font-size:8px;color:var(--muted)}.links{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.link{padding:7px 9px;background:#08111a;border:1px solid rgba(148,163,184,.15);color:#cbd5e1;font-size:9px;text-decoration:none}@media(max-width:1000px){.grid{grid-template-columns:1fr}.cards{grid-template-columns:1fr 1fr}}
</style></head><body><header><div class="brand"><span class="mark">&gt;_</span><div><div class="title">BANKAI // TARGET AUTHENTICATION SERVER</div><div class="sub">LAPTOP 1 • AUTH EDGE • REAL HTTP</div></div></div><div class="badges"><span class="badge ok">● AUTH UP</span><span id="gBadge" class="badge ok">● GATEWAY UP</span><span id="sBadge" class="badge ok">● SENTINEL UP</span><span id="clock" class="badge">—</span></div></header><main><div class="grid"><section class="panel hero"><div class="eyebrow">01 / TARGET SERVER</div><h1>AUTHENTICATE.<br><span>VERIFY.</span></h1><p>Real client HTTP requests arrive here. The target returns real 200/401 responses, then forwards the resulting authentication event through Gateway to Sentinel for detection.</p><div class="chips"><span class="chip">HTTP 200 / 401</span><span class="chip">REAL EVENT FLOW</span><span class="chip">PRIVATE LAB</span><span class="chip">NO PASSWORDS IN SOC</span></div><div id="threat" class="threat"><b>● TARGET PROTECTION: NORMAL</b><div id="threatText" class="small">Monitoring Sentinel risk.</div></div></section><section class="panel"><div class="panel-title"><span>LIVE SERVICE STATE</span><span>ROLE</span></div><div class="cards" style="grid-template-columns:1fr 1fr;margin-top:0"><div class="card"><div class="label">AUTH</div><b class="green">UP</b></div><div class="card"><div class="label">GATEWAY</div><b id="gUp" class="green">UP</b></div><div class="card"><div class="label">SENTINEL</div><b id="sUp" class="green">UP</b></div><div class="card"><div class="label">RISK</div><b id="risk">0</b></div></div><div class="links"><a class="link" href="__OBSERVER_URL__/" target="_blank">OPEN SOC →</a><a class="link" href="__ATTACKER_URL__/" target="_blank">OPEN ATTACKER →</a></div></section></div><div class="cards"><div class="card"><div class="label">REQUESTS</div><b id="req">0</b></div><div class="card"><div class="label">HTTP 200</div><b id="ok" class="green">0</b></div><div class="card"><div class="label">HTTP 401</div><b id="fail" class="red">0</b></div><div class="card"><div class="label">DETECTIONS</div><b id="det" class="cyan">0</b></div></div><div class="grid" style="margin-top:12px"><section class="panel"><div class="panel-title"><span>02 / DIRECT REAL LOGIN</span><span>TARGET SERVER</span></div><div class="formgrid"><div class="field"><label>USERNAME</label><input id="username" value="alice@company.local"></div><div class="field"><label>PASSWORD</label><input id="password" type="password" placeholder="Enter lab password"></div></div><button id="login" class="primary">SEND REAL LOGIN →</button><div id="result" class="result">Waiting for authentication…</div></section><section class="panel"><div class="panel-title"><span>03 / REAL REQUEST PIPELINE</span><span>BACKEND</span></div><div class="flow"><div class="node"><b>AUTH</b><span>:8200</span></div><div class="arrow">→</div><div class="node"><b>GATEWAY</b><span>:8100</span></div><div class="arrow">→</div><div class="node"><b>SENTINEL</b><span>:8000</span></div></div><div class="small" style="margin-top:8px">The observer creates the actual alert/incident. This server displays the resulting protection state.</div></section></div><section class="panel" style="margin-top:12px"><div class="panel-title"><span>04 / RECENT TARGET REQUESTS</span><span>LIVE</span></div><div id="events" class="log"></div></section></main><script>
const $=id=>document.getElementById(id);let req=0,ok=0,fail=0;function tick(){$('clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'}setInterval(tick,1000);tick();function addLog(x){const e=document.createElement('div');e.className='row';e.innerHTML=`<span>${x.code}</span><span>${x.status}</span><span>${x.user}</span><span>${x.time}</span>`;$('events').prepend(e)}
$('login').onclick=async()=>{const u=$('username').value.trim(),p=$('password').value;try{const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,source_ip:'127.0.0.1'})});const d=await r.json();req++;if(r.status===200)ok++;else fail++;$('req').textContent=req;$('ok').textContent=ok;$('fail').textContent=fail;$('result').textContent=`HTTP ${r.status} • ${d.forwarded?'FORWARDED TO GATEWAY':'FORWARD FAILED'}`;addLog({code:r.status,status:r.status===200?'SUCCESS':'FAILURE',user:u,time:new Date().toLocaleTimeString()})}catch(e){$('result').textContent='AUTH ERROR • '+e.message}};
async function refresh(){try{const [p,h,l]=await Promise.all([fetch('/api/protection').then(r=>r.json()),fetch('/health').then(r=>r.json()),fetch('/api/logs').then(r=>r.json())]);$('risk').textContent=p.risk.toFixed(1);$('det').textContent=p.recent_alerts+' / '+p.recent_incidents;$('gUp').textContent=h.gateway?'UP':'DOWN';$('sUp').textContent=h.sentinel?'UP':'DOWN';$('gBadge').textContent=h.gateway?'● GATEWAY UP':'● GATEWAY DOWN';$('sBadge').textContent=h.sentinel?'● SENTINEL UP':'● SENTINEL DOWN';$('gBadge').className='badge '+(h.gateway?'ok':'bad');$('sBadge').className='badge '+(h.sentinel?'ok':'bad');const t=$('threat');if(p.shutdown_alert){t.className='threat shutdown';t.innerHTML='<b class="red">⚠ TARGET SHUTDOWN ALERT • CRITICAL</b><div class="small">Risk '+p.risk+'/100 • '+p.recent_alerts+' alerts • '+p.recent_incidents+' incidents</div>'}else if(p.risk>=50){t.className='threat elevated';t.innerHTML='<b class="amber">▲ ELEVATED THREAT</b><div class="small">Risk '+p.risk+'/100 • protection heightened</div>'}else{t.className='threat';t.innerHTML='<b class="green">● TARGET PROTECTION: NORMAL</b><div class="small">Monitoring Sentinel risk.</div>'} $('events').innerHTML='';(l.items||[]).slice(0,30).forEach(x=>addLog({code:x.status,status:x.status===200?'SUCCESS':'FAILURE',user:x.username,time:(x.time||'').slice(11,19)}))}catch(e){}}
setInterval(refresh,1500);refresh();</script></body></html>'''

ATTACKER_HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BANKAI // LAB CLIENT</title><style>
:root{--bg:#04060a;--panel:#090e17;--line:rgba(0,255,102,.16);--green:#00ff66;--cyan:#00f0ff;--red:#ff2a55;--amber:#ffaa00;--blue:#60a5fa;--text:#e2e8f0;--muted:#64748b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,Consolas,monospace;background-image:radial-gradient(circle at 50% 0%,rgba(0,255,102,.05),transparent 60%),linear-gradient(rgba(0,255,102,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,102,.02) 1px,transparent 1px);background-size:100% 100%,32px 32px,32px 32px}header{border-bottom:1px solid var(--line);padding:12px 18px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:rgba(4,6,10,.96);z-index:5}.brand{display:flex;gap:10px;align-items:center}.mark{width:30px;height:30px;border:1px solid rgba(0,255,102,.4);display:grid;place-items:center;color:var(--green)}.title{font-size:16px;font-weight:900}.sub{font-size:9px;color:var(--muted);margin-top:3px}.badges{display:flex;gap:7px;flex-wrap:wrap}.badge{padding:5px 8px;border:1px solid rgba(148,163,184,.18);font-size:9px;color:var(--muted)}.ok{color:var(--green);border-color:rgba(0,255,102,.3)}.bad{color:var(--red);border-color:rgba(255,42,85,.35)}.warn{color:var(--amber);border-color:rgba(255,170,0,.3)}main{max-width:1450px;margin:auto;padding:16px}.grid{display:grid;grid-template-columns:1.15fr 1fr;gap:12px}.panel{background:rgba(9,14,23,.94);border:1px solid var(--line);padding:14px;position:relative}.panel:after{content:"";position:absolute;right:-1px;bottom:-1px;width:8px;height:8px;border-right:2px solid var(--green);border-bottom:2px solid var(--green)}.hero h1{font-size:48px;line-height:.9;margin:14px 0;color:#fff}.hero h1 span{color:var(--green)}.hero p{font-size:10px;color:#94a3b8;line-height:1.7}.eyebrow{color:var(--green);font-size:9px;letter-spacing:.08em}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.card{background:#020617;border:1px solid var(--line);padding:11px}.card .label{font-size:8px;color:var(--muted)}.card b{display:block;font-size:22px;margin-top:6px}.green{color:var(--green)}.cyan{color:var(--cyan)}.red{color:var(--red)}.amber{color:var(--amber)}.blue{color:var(--blue)}.target{padding:10px;border:1px solid rgba(0,255,102,.2);background:#020617;font-size:10px}.panel-title{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid rgba(148,163,184,.12);padding-bottom:9px;margin-bottom:10px;font-size:10px;font-weight:900}.panel-title span{color:var(--muted);font-size:8px}.scenarios{display:grid;grid-template-columns:1fr 1fr;gap:8px}.attack{padding:16px;background:#020617;border:1px solid rgba(148,163,184,.12);color:#fff;text-align:left}.attack b{display:block;font-size:10px}.attack span{display:block;font-size:8px;color:var(--muted);margin-top:5px}.attack:hover{border-color:rgba(0,255,102,.35)}.normal{color:var(--green)}.brute{color:var(--red)}.spray{color:var(--amber)}.travel{color:var(--cyan)}.runbar{margin-top:8px;padding:10px;border:1px dashed rgba(148,163,184,.18);font-size:9px}.two{display:grid;grid-template-columns:1.2fr .8fr;gap:12px}.flow{display:grid;grid-template-columns:1fr 26px 1fr 26px 1fr;gap:7px;align-items:center}.node{border:1px solid var(--line);padding:13px 7px;text-align:center;background:#020617}.node b{display:block;font-size:10px}.node span{font-size:8px;color:var(--muted)}.arrow{color:var(--green);text-align:center}.log{height:320px;overflow:auto;background:#02050a;border:1px solid rgba(148,163,184,.12);padding:9px}.entry{padding:7px 0;border-bottom:1px dashed rgba(148,163,184,.08);font-size:9px}.time{color:var(--muted)}.mix{display:grid;gap:8px}.mixrow{display:grid;grid-template-columns:120px 1fr 28px;gap:8px;align-items:center;font-size:8px}.track{height:14px;background:#020617;border:1px solid rgba(148,163,184,.12)}.fill{height:100%}.incident{padding:8px;border:1px solid rgba(148,163,184,.12);background:#020617;font-size:9px;margin-bottom:7px}.incident.critical{border-color:rgba(255,42,85,.4)}.links{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.link{padding:7px 9px;background:#08111a;border:1px solid rgba(148,163,184,.15);color:#cbd5e1;font-size:9px;text-decoration:none}.small{font-size:8px;color:var(--muted)}@media(max-width:1050px){.grid,.two{grid-template-columns:1fr}.cards{grid-template-columns:1fr 1fr}}
</style></head><body><header><div class="brand"><span class="mark">B</span><div><div class="title">BANKAI // LAB CLIENT</div><div class="sub">LAPTOP 3 • REAL HTTP CLIENT</div></div></div><div class="badges"><span id="targetBadge" class="badge ok">● TARGET CHECKING</span><a class="badge" href="__OBSERVER_URL__/" target="_blank" style="text-decoration:none">OPEN SOC</a><span id="clock" class="badge">—</span></div></header><main><div class="grid"><section class="panel hero"><div class="eyebrow">CONTROLLED LAB / REAL HTTP CLIENT</div><h1>REQUEST.<br><span>VERIFY.</span></h1><p>This client sends real HTTP requests to the configured authentication target. Detection is pulled from the live observer backend, so the page shows actual alerts and incidents instead of fabricating a state.</p><div class="target">TARGET AUTH SERVICE • <span id="targetUrl">__TARGET_URL__</span></div></section><section class="panel"><div class="panel-title"><span>LIVE CLIENT STATE</span><span>BACKEND-CONNECTED</span></div><div class="cards" style="grid-template-columns:1fr 1fr;margin-top:0"><div class="card"><div class="label">REQUESTS</div><b id="req">0</b></div><div class="card"><div class="label">HTTP 200</div><b id="ok" class="green">0</b></div><div class="card"><div class="label">HTTP 401</div><b id="fail" class="red">0</b></div><div class="card"><div class="label">DETECTIONS</div><b id="det" class="cyan">0</b></div></div><div id="targetInfo" class="runbar">TARGET • checking…</div></section></div><div class="cards" style="margin-top:12px"><div class="card"><div class="label">OBSERVED EVENTS</div><b id="obsEvents">0</b></div><div class="card"><div class="label">ACTIVE ALERTS</div><b id="obsAlerts" class="amber">0</b></div><div class="card"><div class="label">INCIDENTS</div><b id="obsIncidents" class="red">0</b></div><div class="card"><div class="label">RISK</div><b id="obsRisk">0</b></div><div class="card"><div class="label">PROTECTION</div><b id="obsProtect" class="green">NORMAL</b></div></div><div class="two" style="margin-top:12px"><section class="panel"><div class="panel-title"><span>01 / ATTACK EXECUTION</span><span>REAL HTTP → TARGET</span></div><div class="flow"><div class="node"><b>ATTACKER</b><span>Laptop 3</span></div><div class="arrow">→</div><div class="node"><b>TARGET</b><span>Auth :8200</span></div><div class="arrow">→</div><div class="node"><b>OBSERVER</b><span>alert / incident</span></div></div><div class="scenarios" style="margin-top:10px"><button class="attack normal" onclick="scenario('normal')"><b>NORMAL LOGIN</b><span>1 × HTTP 200</span></button><button class="attack brute" onclick="scenario('brute_force')"><b>BRUTE FORCE LAB</b><span>12 failures / 1 user</span></button><button class="attack spray" onclick="scenario('vpn_spray')"><b>VPN / PASSWORD SPRAY</b><span>15 failures / 15 users</span></button><button class="attack travel" onclick="scenario('impossible_travel')"><b>IMPOSSIBLE TRAVEL</b><span>Delhi → Ashburn</span></button></div><div id="state" class="runbar">READY — choose a controlled scenario.</div></section><section class="panel"><div class="panel-title"><span>02 / ATTACK DISTRIBUTION</span><span>LIVE OBSERVER</span></div><div id="mix" class="mix"></div><div class="panel-title" style="margin-top:14px"><span>LATEST DETECTION STORIES</span><span>LIVE</span></div><div id="incidents"></div></section></div><div class="two" style="margin-top:12px"><section class="panel"><div class="panel-title"><span>03 / LIVE HTTP RUN LOG</span><span>200 / 401</span></div><div id="log" class="log"></div></section><section class="panel"><div class="panel-title"><span>04 / CLIENT → AUTH → GATEWAY → SOC</span><span>BACKEND</span></div><div class="flow" style="margin-top:28px"><div class="node"><b>CLIENT</b><span>real request</span></div><div class="arrow">→</div><div class="node"><b>AUTH</b><span>real 200/401</span></div><div class="arrow">→</div><div class="node"><b>GATEWAY</b><span>forward</span></div></div><div class="links"><a class="link" href="__TARGET_URL__/" target="_blank">OPEN TARGET →</a><a class="link" href="__OBSERVER_URL__/" target="_blank">OPEN FULL SOC →</a></div></section></div></main><script>
const TARGET='__TARGET_URL__',OBSERVER='__OBSERVER_URL__',$=id=>document.getElementById(id);let req=0,ok=0,fail=0;function tick(){$('clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'}setInterval(tick,1000);tick();function log(s){const d=document.createElement('div');d.className='entry';d.innerHTML=`<span class="time">${new Date().toLocaleTimeString()}</span> • ${s}`;$('log').prepend(d)}
async function hit(payload,label){const r=await fetch(TARGET+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();req++;if(r.status===200)ok++;else fail++;$('req').textContent=req;$('ok').textContent=ok;$('fail').textContent=fail;log(`${label} → HTTP ${r.status} • ${payload.username}`);return {r,d}}
const users=['alice','bob','charlie','david','eve','frank','grace','heidi','ivan','judy','alice2','bob2','charlie2','david2','eve2'];
async function scenario(kind){$('state').textContent=kind.toUpperCase()+' RUNNING';try{if(kind==='normal')await hit({username:'alice@company.local',password:'Alice123!',source_ip:'10.0.0.24',city:'Delhi',country:'India',latitude:28.6139,longitude:77.2090},'NORMAL');if(kind==='brute_force'){for(let i=0;i<12;i++){await hit({username:'alice@company.local',password:'bad-'+i,source_ip:'10.0.0.81',city:'Moscow',country:'Russia',latitude:55.7558,longitude:37.6176},'BRUTE');await new Promise(x=>setTimeout(x,100))}}if(kind==='vpn_spray'){for(let i=0;i<users.length;i++){await hit({username:users[i]+'@company.local',password:'wrong-'+i,source_ip:'10.8.0.5',source_type:'vpn',city:'Berlin VPN',country:'Germany',latitude:52.52,longitude:13.405},'VPN SPRAY');await new Promise(x=>setTimeout(x,100))}}if(kind==='impossible_travel'){await hit({username:'alice@company.local',password:'Alice123!',source_ip:'10.0.0.24',city:'Delhi',country:'India',latitude:28.6139,longitude:77.2090},'TRAVEL-1');await new Promise(x=>setTimeout(x,250));await hit({username:'alice@company.local',password:'Alice123!',source_ip:'10.0.0.42',city:'Ashburn',country:'USA',latitude:38.9072,longitude:-77.0369},'TRAVEL-2')} $('state').textContent=kind.toUpperCase()+' COMPLETE';setTimeout(refresh,250)}catch(e){$('state').textContent='ATTACK ERROR • '+e.message;log('ERROR • '+e.message)}}
async function refresh(){try{const [t,o]=await Promise.all([fetch(TARGET+'/api/protection').then(r=>r.json()),fetch(OBSERVER+'/public/status').then(r=>r.json())]);$('targetInfo').textContent=`TARGET • ${t.action} • risk ${t.risk}/100`;$('targetBadge').textContent=t.shutdown_alert?'⚠ TARGET SHUTDOWN ALERT':'● TARGET ONLINE';$('targetBadge').className='badge '+(t.shutdown_alert?'bad':(t.risk>=50?'warn':'ok'));$('obsEvents').textContent=o.events;$('obsAlerts').textContent=o.alerts;$('obsIncidents').textContent=o.incidents;$('obsRisk').textContent=o.risk.toFixed(1);$('obsProtect').textContent=t.shutdown_alert?'SHUTDOWN ALERT':(t.risk>=50?'ELEVATED':'NORMAL');$('obsProtect').className=t.shutdown_alert?'red':(t.risk>=50?'amber':'green');$('det').textContent=o.alerts;renderMix(o.attack_distribution||{});renderIncidents(o.latest_incidents||[])}catch(e){$('targetBadge').textContent='● TARGET CHECK FAILED';$('targetBadge').className='badge bad'}}
function renderMix(a){const items=[['brute_force','BRUTE FORCE','#ff2a55'],['password_spraying','VPN / PASSWORD SPRAY','#ffaa00'],['impossible_travel','IMPOSSIBLE TRAVEL','#00f0ff'],['ml_anomaly','ML ANOMALY','#60a5fa']];const max=Math.max(1,...items.map(x=>Number(a[x[0]]||0)));$('mix').innerHTML=items.map(x=>`<div class="mixrow"><div>${x[1]}</div><div class="track"><div class="fill" style="width:${(Number(a[x[0]]||0)/max*100).toFixed(1)}%;background:${x[2]}"></div></div><div>${Number(a[x[0]]||0)}</div></div>`).join('')}
function renderIncidents(items){$('incidents').innerHTML=items.length?items.map(x=>`<div class="incident ${x.severity==='CRITICAL'?'critical':''}"><b>${x.severity}</b> • ${x.attack_types.join(' + ')} • risk ${x.risk_score}<div class="small">${x.evidence}</div></div>`).join(''):'<div class="small">No incidents yet.</div>'}refresh();setInterval(refresh,1500);
</script></body></html>'''

GATEWAY_HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BANKAI // GATEWAY</title><style>body{margin:0;background:#04060a;color:#e2e8f0;font-family:ui-monospace,Consolas,monospace}.wrap{max-width:1000px;margin:auto;padding:18px}.panel{background:#090e17;border:1px solid rgba(0,255,102,.16);padding:15px;margin-bottom:12px}.green{color:#00ff66}.muted{color:#64748b;font-size:9px}.log{background:#02050a;border:1px solid rgba(148,163,184,.12);padding:10px;height:500px;overflow:auto;font-size:10px}.flow{display:grid;grid-template-columns:1fr 30px 1fr 30px 1fr;gap:7px;align-items:center}.node{padding:14px;border:1px solid rgba(0,255,102,.16);background:#020617;text-align:center}.arrow{color:#00ff66;text-align:center}</style></head><body><div class="wrap"><div class="panel"><div style="font-size:18px;font-weight:900"><span class="green">&gt;_ BANKAI</span> // GATEWAY</div><div class="muted">LAPTOP 1 • EVENT FORWARDING • REAL HTTP</div></div><div class="panel"><div class="flow"><div class="node"><b>AUTH :8200</b><div class="muted">target</div></div><div class="arrow">→</div><div class="node"><b>GATEWAY :8100</b><div class="muted">forward</div></div><div class="arrow">→</div><div class="node"><b>SENTINEL :8000</b><div class="muted">detect</div></div></div></div><div class="panel"><div style="font-size:11px;font-weight:900;margin-bottom:9px">LIVE FORWARDING LOG</div><div id="log" class="log">Gateway console ready…</div></div></div><script>async function refresh(){try{const r=await fetch('/api/gateway/log');const d=await r.json();document.getElementById('log').textContent=d.items.map(x=>`${x.time} • ${x.status} • ${x.message}`).join('\n')||'Gateway idle…'}catch(e){}}setInterval(refresh,1000);refresh();</script></body></html>'''


def json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode('utf-8')



def run_controlled_attack(scenario: str, target_url: str | None = None) -> dict:
    specs={
        "normal":[("alice@company.local","Alice123!","127.0.0.1","client",None,None,None,None)],
        "brute_force":[("alice@company.local",f"bad-{i}","10.0.0.81","client","Moscow","Russia",55.7558,37.6176) for i in range(12)],
        "vpn_spray":[(u+"@company.local",f"wrong-{i}","10.8.0.5","vpn","Berlin VPN","Germany",52.52,13.405) for i,u in enumerate(["alice","bob","charlie","david","eve","frank","grace","heidi","ivan","judy","alice2","bob2","charlie2","david2","eve2"])],
        "impossible_travel":[("alice@company.local","Alice123!","10.0.0.24","client","Delhi","India",28.6139,77.2090),("alice@company.local","Alice123!","10.0.0.42","client","Ashburn","USA",38.9072,-77.0369)]
    }
    if scenario not in specs: raise ValueError("unsupported scenario")
    target_url=target_url or service_url("target","/login"); counts={}; results=[]
    for u,pwd,ip,stype,city,country,lat,lon in specs[scenario]:
        code,body=http_json(target_url,{"username":u,"password":pwd,"source_ip":ip,"source_type":stype,"city":city,"country":country,"latitude":lat,"longitude":lon},timeout=5)
        counts[str(code)]=counts.get(str(code),0)+1; results.append({"username":u,"status_code":code,"body":body,"target":target_url,"timestamp":now_iso()})
    return {"scenario":scenario,"requested":len(specs[scenario]),"completed":len(results),"status_counts":counts,"last_status":results[-1]["status_code"],"target":target_url,"results":results}



def public_allinone() -> dict:
    """Single-Laptop-only local summary for the unified browser page."""
    m=metrics()
    with DB_LOCK, db() as c:
        alert_rows=c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 8").fetchall()
        incident_rows=c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 8").fetchall()
        geo_rows=c.execute("SELECT latitude,longitude,city,country,source_ip,username,status,ts FROM events WHERE latitude IS NOT NULL AND longitude IS NOT NULL ORDER BY id DESC LIMIT 80").fetchall()
    return {"metrics":m,"alerts":[_map_alert(r) for r in alert_rows],"incidents":[_map_incident(r) for r in incident_rows],"activity":activity_series(30),"geo":[dict(r) for r in geo_rows],"protection":protective_status()}


def make_handler(role):
    class RoleHandler(BaseHTTPRequestHandler):
        server_version=f"BANKAI-{role}/2.0"
        def _send(self,body,ctype="text/html; charset=utf-8",code=200,cookies=None,cors=False):
            self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(body)))
            if cors:
                self.send_header("Access-Control-Allow-Origin","*"); self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS"); self.send_header("Access-Control-Allow-Headers","Content-Type,X-Gateway-Token,X-Ingest-Token")
            if cookies:
                for c in cookies:self.send_header("Set-Cookie",c)
            self.end_headers(); self.wfile.write(body)
        def _auth(self): return "bankai_session=1" in self.headers.get("Cookie","")
        def _json(self): return json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))).decode() or "{}")
        def do_OPTIONS(self): self._send(b"{}","application/json",204,cors=True)
        def do_GET(self):
            path,q=_parse_query(self.path)
            if role=="observer":
                if path=="/dashboard/world_map.svg": self._send(WORLD_MAP_SVG.encode(), "image/svg+xml", cors=True); return
                if path=="/":
                    page=DASHBOARD_HTML.replace("__TARGET_ROOT__",service_url("target")).replace("__ATTACKER_ROOT__",service_url("attacker"))
                    self._send(page.encode()); return
                if path=="/all-in-one":
                    if not CONFIG.get("mode","").startswith("Single"):
                        self._send(json_bytes({"detail":"all-in-one page is local single-laptop mode only"}),"application/json",403,cors=True); return
                    page=ALL_IN_ONE_HTML.replace("__TARGET_URL__",service_url("target","/login")).replace("__TARGET_HEALTH__",service_url("target","/health")).replace("__TARGET_LOGS__",service_url("target","/api/logs"))
                    self._send(page.encode(),cors=True); return
                if path=="/health": self._send(json_bytes({"status":"ok","model_loaded":IsolationForest is not None and ensure_if_model() is not None}),"application/json",cors=True); return
                if path=="/public/status": self._send(json_bytes(public_status()),"application/json",cors=True); return
                if path=="/public/allinone":
                    if not CONFIG.get("mode","").startswith("Single"):
                        self._send(json_bytes({"detail":"all-in-one endpoint is local single-laptop mode only"}),"application/json",403,cors=True); return
                    self._send(json_bytes(public_allinone()),"application/json",cors=True); return
                if path.startswith("/api/"):
                    if path not in ("/api/auth/login","/api/auth/health","/api/events/ingest") and not self._auth(): self._send(json_bytes({"detail":"authentication required"}),"application/json",401,cors=True); return
                    self._send(json_bytes(api_payload(path,q)),"application/json",cors=True); return
            elif role=="target":
                if path=="/": self._send(TARGET_HTML.replace("__OBSERVER_URL__",service_url("observer")).replace("__ATTACKER_URL__",service_url("attacker")).encode(),cors=True); return
                if path=="/health":
                    try:g=http_json(service_url("gateway","/health"),timeout=2)[0]==200
                    except Exception:g=False
                    try:o=http_json(service_url("observer","/health"),timeout=2)[0]==200
                    except Exception:o=False
                    self._send(json_bytes({"status":"ok","gateway":g,"sentinel":o}),"application/json",cors=True); return
                if path=="/api/protection":
                    try:self._send(json_bytes(http_json(service_url("observer","/public/status"),timeout=2)[1]),"application/json",cors=True)
                    except Exception:self._send(json_bytes({"risk":0,"shutdown_alert":False,"action":"SENTINEL OFFLINE"}),"application/json",cors=True)
                    return
                if path=="/api/logs":
                    with TARGET_LOG_LOCK: items=list(TARGET_LOG)[-40:][::-1]
                    self._send(json_bytes({"items":items}),"application/json",cors=True); return
            elif role=="attacker":
                if path=="/": self._send(ATTACKER_HTML.replace("__TARGET_URL__",service_url("target")).replace("__OBSERVER_URL__",service_url("observer")).encode(),cors=True); return
                if path=="/health": self._send(json_bytes({"status":"ok","target":http_json(service_url("target","/health"),timeout=2)[0]==200}),"application/json",cors=True); return
            elif role=="gateway":
                if path=="/": self._send(GATEWAY_HTML.encode(),cors=True); return
                if path=="/health": self._send(json_bytes({"status":"ok"}),"application/json",cors=True); return
                if path=="/api/gateway/log":
                    with GATEWAY_LOG_LOCK: items=list(GATEWAY_LOG)[-100:][::-1]
                    self._send(json_bytes({"items":items}),"application/json",cors=True); return
            self._send(b"Not found",code=404)
        def do_POST(self):
            path,q=_parse_query(self.path)
            if role=="observer":
                if path=="/api/auth/login":
                    try:
                        d=self._json(); ok=str(d.get("token",""))==DASHBOARD_TOKEN; self._send(json_bytes({"ok":ok}),"application/json",200 if ok else 401,["bankai_session=1; Path=/; HttpOnly; SameSite=Lax"] if ok else None,cors=True)
                    except Exception as e:self._send(json_bytes({"detail":str(e)}),"application/json",400,cors=True)
                    return
                if path=="/api/auth/logout": self._send(json_bytes({"ok":True}),"application/json",200,["bankai_session=; Path=/; Max-Age=0; HttpOnly"],cors=True); return
                if path=="/api/events/ingest":
                    if self.headers.get("X-Ingest-Token")!="BANKAI-INGEST-2026": self._send(json_bytes({"detail":"ingest auth required"}),"application/json",401,cors=True); return
                    d=self._json(); result=insert_event(str(d.get("username","unknown")),str(d.get("source_ip","127.0.0.1")),int(d.get("status",401)),source_type=str(d.get("source_type","client")),city=d.get("city"),country=d.get("country"),lat=d.get("latitude"),lon=d.get("longitude"),target=str(d.get("target","bankai-lab-auth")))
                    self._send(json_bytes(result),"application/json",200,cors=True); return
                if path.startswith("/api/dataset/"):
                    if not self._auth(): self._send(json_bytes({"detail":"authentication required"}),"application/json",401,cors=True); return
                    try:
                        d=self._json(); content=str(d.get("content","")); filename=str(d.get("filename","dataset.csv"))
                        if not content.strip(): raise ValueError("Dataset content is empty.")
                        if len(content.encode("utf-8")) > 12*1024*1024: raise ValueError("CSV exceeds 12 MB upload limit.")
                        if path=="/api/dataset/evaluate": result=evaluate_csv(content)
                        elif path=="/api/dataset/train": result=train_dataset_model(content)
                        elif path=="/api/dataset/analyze": result=analyze_dataset_model(content)
                        else: self._send(json_bytes({"detail":"unknown dataset action"}),"application/json",404,cors=True); return
                        result["filename"]=filename
                        self._send(json_bytes(result),"application/json",200,cors=True); return
                    except Exception as e:
                        self._send(json_bytes({"detail":str(e)}),"application/json",400,cors=True); return
                if path=="/api/auth":
                    d=self._json(); u=str(d.get("username","")); status=200 if VALID_USERS.get(u)==str(d.get("password","")) else 401; r=insert_event(u or "unknown",str(d.get("source_ip","127.0.0.1")),status,source_type=str(d.get("source_type","client")),city=d.get("city"),country=d.get("country"),lat=d.get("latitude"),lon=d.get("longitude")); r["status"]=status; self._send(json_bytes(r),"application/json",status,cors=True); return
            elif role=="target":
                if path=="/login":
                    try:
                        d=self._json(); u=str(d.get("username","")); pwd=str(d.get("password","")); ip=str(d.get("source_ip","127.0.0.1"))
                        if not is_private_lab_host(ip): self._send(json_bytes({"status":400,"error":"private/test lab only"}),"application/json",400,cors=True); return
                        st=200 if VALID_USERS.get(u)==pwd else 401; event={"username":u or "unknown","source_ip":ip,"status":st,"source_type":str(d.get("source_type","client")),"city":d.get("city"),"country":d.get("country"),"latitude":d.get("latitude"),"longitude":d.get("longitude"),"target":"bankai-lab-auth"}
                        with TARGET_LOG_LOCK: TARGET_LOG.append({"time":now_iso(),"username":u or "unknown","status":st,"source_ip":ip,"forwarded":False});
                        code,body=http_json(service_url("gateway","/ingest"),event,headers={"X-Gateway-Token":"BANKAI-GATEWAY-2026"},timeout=5); forwarded=code==200
                        with TARGET_LOG_LOCK: TARGET_LOG[-1]["forwarded"]=forwarded
                        self._send(json_bytes({"status":st,"forwarded":forwarded,"gateway":body}),"application/json",st,cors=True); return
                    except Exception as e:self._send(json_bytes({"detail":str(e)}),"application/json",400,cors=True); return
            elif role=="gateway":
                if path=="/ingest":
                    if self.headers.get("X-Gateway-Token")!="BANKAI-GATEWAY-2026": self._send(json_bytes({"detail":"gateway auth required"}),"application/json",401,cors=True); return
                    d=self._json(); code,body=http_json(service_url("observer","/api/events/ingest"),d,headers={"X-Ingest-Token":"BANKAI-INGEST-2026"},timeout=5); with_lock=GATEWAY_LOG_LOCK
                    with with_lock:GATEWAY_LOG.append({"time":now_iso(),"status":str(code),"message":f"forwarded {d.get('source_ip')} {d.get('status')} -> Sentinel"})
                    self._send(json_bytes({"forwarded":code==200,"sentinel_status":code,"sentinel":body}),"application/json",200,cors=True); return
            self._send(b"Not found",code=404)
        def log_message(self,fmt,*args): pass
    return RoleHandler

def start_service(role):
    if role in SERVERS:return
    server=ThreadingHTTPServer((CONFIG.get("bind_host","127.0.0.1"),ROLE_PORTS[role]),make_handler(role)); t=threading.Thread(target=server.serve_forever,daemon=True);t.start();SERVERS[role]=server;SERVER_THREADS[role]=t

def stop_service(role):
    s=SERVERS.pop(role,None)
    if s:s.shutdown();s.server_close()
    SERVER_THREADS.pop(role,None)

def stop_all_services():
    for role in list(SERVERS):stop_service(role)


class ControlCenter:
    def __init__(self,root):
        self.root=root;self.root.title("BANKAI — SOC Control Center");self.root.geometry("980x700");self.root.configure(bg="#04060a");self.build()
    def build(self):
        st=ttk.Style();st.theme_use("clam");st.configure("TFrame",background="#04060a");st.configure("TLabel",background="#04060a",foreground="#d7e9e0");st.configure("TButton",background="#07131b",foreground="#d7e9e0")
        ttk.Label(self.root,text="BANKAI",foreground="#00ff66",font=("Consolas",24,"bold")).pack(anchor="w",padx=18,pady=(15,0));ttk.Label(self.root,text="SOC CONTROL CENTER • BROWSER-FIRST LAB",font=("Consolas",10)).pack(anchor="w",padx=20)
        self.mode=ttk.Combobox(self.root,values=["Single Laptop — All-in-One","Laptop 1 — Auth + Gateway","Laptop 2 — Sentinel + Dashboard","Laptop 3 — Client"],state="readonly",width=34);self.mode.set(CONFIG["mode"]);self.mode.pack(anchor="w",padx=20,pady=8)
        body=ttk.Frame(self.root);body.pack(fill="both",expand=True,padx=18,pady=8);left=ttk.Frame(body);left.pack(side="left",fill="y",padx=(0,12));right=ttk.Frame(body);right.pack(side="right",fill="both",expand=True)
        def fld(label,key):
            ttk.Label(left,text=label).pack(anchor="w",pady=(7,2));e=ttk.Entry(left,width=32);e.insert(0,CONFIG[key]);e.pack(fill="x");return e
        self.s=fld("Laptop 2 Sentinel IP", "sentinel_ip");self.a=fld("Laptop 1 Auth/Gateway IP", "auth_gateway_ip");self.c=fld("Laptop 3 Client IP", "client_ip");self.t=fld("Dashboard API Token","dashboard_token")
        for txt,fn in [("Save Configuration",self.save),("Setup / Repair Environment",self.setup),("Self-Test / Diagnose",self.test),("Start Selected Role",self.start),("Stop BANKAI",self.stop),("Open Observer / SOC",self.open_observer),("Open Target Server",self.open_target),("Open Attacker / Client",self.open_attacker),("Open Gateway Console",self.open_gateway),("Test Wi-Fi / LAN Connectivity",self.connectivity)]:ttk.Button(left,text=txt,command=fn).pack(fill="x",pady=3)
        self.log=tk.Text(right,bg="#02050a",fg="#8ed9c0",font=("Consolas",10));self.log.pack(fill="both",expand=True);self.msg("Single Laptop opens ONE browser tab with three live sections: Attacker / Observer / Target Server. Gateway runs in the background.")
    def msg(self,m):self.log.insert("end",f"[{datetime.now().strftime('%H:%M:%S')}] {m}\n");self.log.see("end")
    def save(self):
        bind="127.0.0.1" if self.mode.get().startswith("Single") else "0.0.0.0";save_config({"mode":self.mode.get(),"bind_host":bind,"sentinel_ip":self.s.get().strip() or "127.0.0.1","auth_gateway_ip":self.a.get().strip() or "127.0.0.1","client_ip":self.c.get().strip() or "127.0.0.1","dashboard_token":self.t.get().strip() or DASHBOARD_TOKEN});self.msg(f"Saved configuration • bind={bind}")
    def setup(self):self.save();init_db();self.msg("Environment ready.")
    def test(self):self.msg("SELF-TEST PASS" if run_self_test()==0 else "SELF-TEST FAIL")
    def start(self):
        self.save();stop_all_services();m=self.mode.get();roles=["observer","gateway","target","attacker"] if m.startswith("Single") else (["gateway","target"] if m.startswith("Laptop 1") else (["observer"] if m.startswith("Laptop 2") else ["attacker"]))
        for r in roles:
            try:start_service(r);self.msg(f"Started {r} :{ROLE_PORTS[r]}")
            except Exception as e:self.msg(f"FAILED {r}: {e}")
        self.root.after(900,self.open_tabs)
    def open_tabs(self):
        m=self.mode.get()
        if m.startswith("Single"):
            urls=[service_url("observer","/all-in-one")]
        else:
            urls=([service_url("target"),service_url("gateway")] if m.startswith("Laptop 1") else ([service_url("observer")] if m.startswith("Laptop 2") else [service_url("attacker")]))
        for u in urls:webbrowser.open_new_tab(u)
        self.msg("Opened: "+" | ".join(urls))
    def open_observer(self):webbrowser.open_new_tab(service_url("observer"))
    def open_target(self):webbrowser.open_new_tab(service_url("target"))
    def open_attacker(self):webbrowser.open_new_tab(service_url("attacker"))
    def open_gateway(self):webbrowser.open_new_tab(service_url("gateway"))
    def connectivity(self):
        for n,u in [("Observer",service_url("observer","/health")),("Gateway",service_url("gateway","/health")),("Target",service_url("target","/health"))]:
            try:self.msg(f"{n}: HTTP {http_json(u,timeout=2)[0]}")
            except Exception as e:self.msg(f"{n}: OFFLINE • {e}")
    def stop(self):stop_all_services();self.msg("BANKAI stopped")
    def close(self):self.stop();self.root.destroy()


def run_self_test() -> int:
    import tempfile
    global DB_PATH
    old=DB_PATH;DB_PATH=Path(tempfile.mkdtemp(prefix="bankai_rt_"))/"test.db";oldcfg=dict(CONFIG)
    try:
        CONFIG.update({"bind_host":"127.0.0.1","sentinel_ip":"127.0.0.1","auth_gateway_ip":"127.0.0.1","client_ip":"127.0.0.1","dashboard_token":DASHBOARD_TOKEN});init_db();assert ensure_if_model() is not None;stop_all_services()
        for r in ("observer","gateway","target","attacker"):start_service(r)
        for r in ("observer","target","attacker"):
            with urlopen(service_url(r),timeout=5) as rr:
                assert rr.status==200 and rr.read(32)
        assert http_json(service_url("gateway","/health"))[0]==200
        allinone_code,allinone_body=http_json(service_url("observer","/public/allinone")); assert allinone_code==200 and allinone_body["metrics"] is not None
        with urlopen(service_url("observer","/all-in-one"),timeout=5) as rr:
            page=rr.read().decode("utf-8")
            assert rr.status==200 and "/ ATTACKER" in page and "/ OBSERVER" in page and "/ TARGET SERVER" in page
        target=service_url("target","/login")
        for i in range(7):assert http_json(target,{"username":"alice@company.local","password":"bad","source_ip":"10.0.0.81"})[0]==401
        for u in ["bob","charlie","david","eve","frank","grace"]:assert http_json(target,{"username":u+"@company.local","password":"wrong","source_ip":"10.8.0.5","source_type":"vpn"})[0]==401
        assert http_json(target,{"username":"alice@company.local","password":"Alice123!","source_ip":"10.0.0.24","latitude":28.6139,"longitude":77.2090,"city":"Delhi"})[0]==200
        assert http_json(target,{"username":"alice@company.local","password":"Alice123!","source_ip":"10.0.0.42","latitude":38.9072,"longitude":-77.0369,"city":"Ashburn"})[0]==200
        st=http_json(service_url("observer","/public/status"))[1];assert st["alerts"]>=3 and st["incidents"]>=3
        assert protective_status()["shutdown_alert"]
        headers={"Cookie":"bankai_session=1"}
        csv_rows=[]
        csv_rows += [f"401,alice@company.local,10.0.0.81,ATTACK_BRUTE_FORCE" for _ in range(6)]
        csv_rows += [f"401,bob@company.local,10.0.0.42,ATTACK_BRUTE_FORCE" for _ in range(6)]
        csv_rows += [f"200,charlie@company.local,10.0.0.24,NORMAL" for _ in range(3)]
        csv_text="status,username,source_ip,ground_truth_label\n" + "\n".join(csv_rows)
        code_eval,eval_body=http_json(service_url("observer","/api/dataset/evaluate"),{"filename":"selftest.csv","content":csv_text},headers=headers); assert code_eval==200 and eval_body["rows"]==15 and eval_body["labels_used_post_detection"] is True
        code_train,train_body=http_json(service_url("observer","/api/dataset/train"),{"filename":"selftest.csv","content":csv_text},headers=headers); assert code_train==200 and train_body["behavioral_groups"]==3
        code_analyze,analyze_body=http_json(service_url("observer","/api/dataset/analyze"),{"filename":"selftest.csv","content":csv_text},headers=headers); assert code_analyze==200 and "anomalies" in analyze_body
        print("BANKAI SELF-TEST: PASS");print("Real HTTP client -> target -> gateway -> sentinel -> detection: OK");print("Brute force + VPN spray + impossible travel: OK");print("Isolation Forest: OK");print("All-in-One route + 3-section page structure: OK");print("User dataset evaluation endpoint: OK");print("Target protective shutdown alert: OK");return 0
    except Exception as e:
        print(f"BANKAI SELF-TEST: FAIL — {type(e).__name__}: {e}");return 1
    finally:
        stop_all_services();DB_PATH=old;CONFIG.clear();CONFIG.update(oldcfg)



def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--self-test",action="store_true");a=p.parse_args()
    if a.self_test:raise SystemExit(run_self_test())
    init_db();root=tk.Tk();app=ControlCenter(root);root.protocol("WM_DELETE_WINDOW",app.close);root.mainloop()


if __name__ == "__main__":
    main()

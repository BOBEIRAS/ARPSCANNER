#!/usr/bin/env python3
import hmac
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request

DATABASE = os.environ.get("DASHBOARD_DB", "/var/lib/netmap-alerts/dashboard.db")
API_TOKEN = os.environ.get("ALERT_API_TOKEN", "")
app = Flask(__name__)


def database():
    Path(DATABASE).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, received_at INTEGER NOT NULL, "
        "payload TEXT NOT NULL)"
    )
    db.commit()
    return db


def authorized():
    value = request.headers.get("Authorization", "")
    return bool(API_TOKEN) and hmac.compare_digest(
        value, "Bearer " + API_TOKEN
    )


def api_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not authorized():
            return jsonify({"error": "não autorizado"}), 401
        return handler(*args, **kwargs)

    return wrapped


@app.post("/api/alerts")
@api_auth
def receive_alert():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get("type") != "alert":
        return jsonify({"error": "payload de alerta inválido"}), 400
    with database() as db:
        cursor = db.execute(
            "INSERT INTO alerts(received_at, payload) VALUES (strftime('%s','now'), ?)",
            (request.get_data(as_text=True),),
        )
        db.commit()
    return jsonify({"ok": True, "id": cursor.lastrowid}), 201


@app.get("/api/alerts")
def list_alerts():
    limit = min(request.args.get("limit", 100, type=int), 500)
    with database() as db:
        rows = db.execute(
            "SELECT id, received_at, payload FROM alerts "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return jsonify(
        [{"id": row["id"], "received_at": row["received_at"],
          "alert": row["payload"]} for row in rows]
    )


@app.get("/")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    if not API_TOKEN:
        raise SystemExit("Define ALERT_API_TOKEN antes de iniciar a API")
    database().close()
    app.run(host="0.0.0.0", port=5000, debug=False)

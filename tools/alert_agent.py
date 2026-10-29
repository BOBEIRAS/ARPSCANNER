#!/usr/bin/env python3
"""Runs netmap and forwards security alerts to an HTTPS API with local retry."""

import json
import os
import queue
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request

DB_PATH = os.environ.get("ALERT_QUEUE_DB", "/var/lib/netmap-alerts/queue.db")
API_URL = os.environ.get("ALERT_API_URL", "").strip()
API_TOKEN = os.environ.get("ALERT_API_TOKEN", "").strip()
NETMAP = os.environ.get("NETMAP_BIN", "/usr/local/bin/netmap")
TARGET = os.environ.get("NETMAP_TARGET", "")
INTERFACE = os.environ.get("NETMAP_INTERFACE", "")
SURICATA_LOG = os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS pending ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, "
            "created_at INTEGER NOT NULL)"
        )
        db.commit()


def enqueue(payload):
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "INSERT INTO pending(payload, created_at) VALUES (?, ?)",
            (json.dumps(payload, separators=(",", ":")), int(time.time())),
        )
        db.commit()


def send_pending():
    if not API_URL:
        raise RuntimeError("ALERT_API_URL não está configurada")
    while True:
        with sqlite3.connect(DB_PATH) as db:
            row = db.execute(
                "SELECT id, payload FROM pending ORDER BY id LIMIT 1"
            ).fetchone()
        if row is None:
            return
        try:
            queued = json.loads(row[1])
        except json.JSONDecodeError:
            queued = None
        if not isinstance(queued, dict) or queued.get("type") != "alert":
            print("A remover payload incompatível da fila de alertas",
                  flush=True)
            with sqlite3.connect(DB_PATH) as db:
                db.execute("DELETE FROM pending WHERE id = ?", (row[0],))
                db.commit()
            continue
        request = urllib.request.Request(
            API_URL,
            data=row[1].encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + API_TOKEN,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError("API devolveu HTTP %s" % response.status)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            print("API rejeitou o alerta (HTTP %s): %s" %
                  (error.code, body), flush=True)
            return
        except (urllib.error.URLError, OSError, RuntimeError) as error:
            print("API indisponível; alerta mantido na fila: %s" % error, flush=True)
            return
        with sqlite3.connect(DB_PATH) as db:
            db.execute("DELETE FROM pending WHERE id = ?", (row[0],))
            db.commit()


def forward(payload):
    if payload.get("type") != "alert":
        return
    enqueue(payload)
    send_pending()


def scanner():
    command = [NETMAP, "-j", "-w", "-p"]
    if INTERFACE:
        command[1:1] = ["-i", INTERFACE]
    if TARGET:
        command.append(TARGET)
    while True:
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in process.stdout:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    print("Saída inválida do netmap: %s" % line.rstrip(), flush=True)
                    continue
                forward(payload)
        except OSError as error:
            print("Não foi possível iniciar o netmap: %s" % error, flush=True)
        time.sleep(5)


def suricata():
    position = 0
    while True:
        try:
            with open(SURICATA_LOG, encoding="utf-8") as log:
                log.seek(position)
                for line in log:
                    position = log.tell()
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if payload.get("event_type") == "alert":
                        forward({"type": "alert", "alert": "suricata",
                                 "timestamp": int(time.time()),
                                 "data": payload})
        except (FileNotFoundError, OSError):
            time.sleep(10)


def main():
    init_db()
    if not API_URL:
        raise SystemExit("Configura ALERT_API_URL antes de iniciar o agente")
    if not (API_URL.startswith("https://") or
            API_URL.startswith("http://127.0.0.1:") or
            API_URL.startswith("http://localhost:")):
        raise SystemExit("ALERT_API_URL tem de usar HTTPS, exceto localhost")
    if not API_TOKEN:
        raise SystemExit("Configura ALERT_API_TOKEN antes de iniciar o agente")
    threading.Thread(target=suricata, daemon=True).start()
    scanner()


if __name__ == "__main__":
    main()

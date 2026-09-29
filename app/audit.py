import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "promptgate.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            request_id TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_types TEXT NOT NULL,
            model_used TEXT,
            prompt_length INTEGER NOT NULL
        )
    """)
    con.commit()
    con.close()

def log_event(request_id: str, risk_score: float, risk_level: str,
              action: str, entity_types: list[str], model_used: str | None,
              prompt_length: int):
    con = sqlite3.connect(DB)
    con.execute("""
        INSERT INTO audit_logs
        (timestamp, request_id, risk_score, risk_level, action, entity_types, model_used, prompt_length)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(), request_id,
        risk_score, risk_level, action, json.dumps(entity_types), model_used, prompt_length
    ))
    con.commit()
    con.close()


def get_logs(limit: int = 100):
    limit = max(1, min(int(limit), 500))
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows = con.execute("""
        SELECT timestamp, request_id, risk_score, risk_level, action,
               entity_types, model_used, prompt_length
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    con.close()

    result = []
    for row in rows:
        item = dict(row)
        try:
            item["entity_types"] = ", ".join(json.loads(item["entity_types"]))
        except Exception:
            pass
        result.append(item)
    return result

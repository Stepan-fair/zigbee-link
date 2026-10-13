"""Durable command receipts; diagnostic rotation cannot reset action budgets."""
from contextlib import contextmanager
from dataclasses import asdict, fields, replace
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from .model import Action, RecoveryState


class StoreError(Exception):
    pass


class RecoveryStore:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise ValueError("symlink")
            self.db = sqlite3.connect(path, timeout=5, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            os.chmod(path, 0o600)
            with self.transaction():
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise StoreError("Неподдерживаемая версия состояния восстановления")
                self.db.execute("CREATE TABLE IF NOT EXISTS states (key TEXT PRIMARY KEY, payload TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS commands (receipt TEXT PRIMARY KEY, key TEXT NOT NULL, kind TEXT NOT NULL, generation TEXT NOT NULL, created REAL NOT NULL, revision TEXT NOT NULL, run_id TEXT, outcome TEXT NOT NULL)")
                self.db.execute("CREATE INDEX IF NOT EXISTS command_budget ON commands(key,created)")
                self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY,key TEXT NOT NULL,opened REAL NOT NULL,closed REAL,outcome TEXT NOT NULL)")
                self.db.execute("PRAGMA user_version=1")
        except (sqlite3.Error, OSError, ValueError) as exc:
            if hasattr(self, "db"):
                self.db.close()
            raise StoreError("Состояние восстановления недоступно; команды запрещены") from None

    @contextmanager
    def transaction(self):
        with self.lock:
            try:
                with self.db:
                    yield
            except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
                raise StoreError("Состояние восстановления недоступно; команды запрещены") from None

    def _load(self, key):
        row = self.db.execute("SELECT payload FROM states WHERE key=?", (key,)).fetchone()
        if row is None:
            return RecoveryState()
        raw = json.loads(row[0])
        if not isinstance(raw, dict) or set(raw) != {f.name for f in fields(RecoveryState)}:
            raise ValueError("invalid stored state")
        state = RecoveryState(**raw)
        defaults = asdict(RecoveryState())
        for name, value in raw.items():
            default = defaults[name]
            if default is None:
                if value is not None and (name == "pending_action" and not isinstance(value, str) or name != "pending_action" and type(value) not in (int, float)):
                    raise ValueError("invalid stored value")
            elif isinstance(default, str):
                if not isinstance(value, str):
                    raise ValueError("invalid stored string")
            elif type(value) not in (int, float):
                raise ValueError("invalid stored number")
        counters = ("misses", "successes", "attempt_stage", "health_misses", "last_health_sequence")
        for name in counters:
            if type(raw[name]) is not int or not (-1 if name == "last_health_sequence" else 0) <= raw[name] <= 2**31 - 1:
                raise ValueError("invalid stored counter")
        if state.attempt_stage > 3:
            raise ValueError("invalid backoff")
        for name, value in raw.items():
            if type(value) in (int, float) and not math.isfinite(value):
                raise ValueError("non-finite state")
        return state

    def load(self, key: str) -> RecoveryState:
        with self.transaction():
            return self._load(key)

    def _save(self, key, state):
        self.db.execute("INSERT INTO states VALUES (?,?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload", (key, json.dumps(asdict(state), allow_nan=False)))
        if state.incident_id:
            self.db.execute("INSERT OR IGNORE INTO incidents VALUES (?,?,?,NULL,'active')", (state.incident_id, key, self._logical_now()))

    def _logical_now(self):
        row = self.db.execute("SELECT value FROM meta WHERE key='logical_utc'").fetchone()
        value = float(row[0]) if row else time.time()
        if not math.isfinite(value):
            raise ValueError("invalid logical time")
        return value

    def save(self, key: str, state: RecoveryState):
        with self.transaction():
            # Only receipt resolution may clear a pending command.
            pending = self.db.execute("SELECT receipt FROM commands WHERE key=? AND outcome='pending'", (key,)).fetchone()
            self._save(key, replace(state, pending_action=pending[0] if pending else None))

    def reserve(self, action: Action, now_utc: float, controls_revision: str, run_id: str | None = None) -> str:
        with self.transaction():
            if action.kind not in ("start", "restart") or self.db.execute("SELECT 1 FROM commands WHERE key=? AND outcome='pending'", (action.binding_key,)).fetchone():
                raise StoreError("Команда уже ожидает сверки или запрещена")
            receipt = str(uuid.uuid4())
            state = self._load(action.binding_key)
            self.db.execute("INSERT INTO commands VALUES (?,?,?,?,?,?,?,?)", (receipt, action.binding_key, action.kind, action.generation, now_utc, controls_revision, run_id, "pending"))
            self._save(action.binding_key, replace(state, pending_action=receipt))
            return receipt

    def pending(self, key: str) -> dict | None:
        with self.transaction():
            row = self.db.execute("SELECT * FROM commands WHERE key=? AND outcome='pending'", (key,)).fetchone()
            return dict(row) if row else None

    def resolve(self, receipt: str, outcome: str, run_id: str | None):
        if outcome not in ("confirmed", "cancelled", "failed"):
            raise StoreError("Неизвестный исход команды")
        with self.transaction():
            row = self.db.execute("SELECT key FROM commands WHERE receipt=? AND outcome='pending'", (receipt,)).fetchone()
            if not row:
                raise StoreError("Квитанция команды не найдена")
            self.db.execute("UPDATE commands SET outcome=? WHERE receipt=?", (outcome, receipt))
            state = self._load(row[0])
            self._save(row[0], replace(state, pending_action=None))

    def command_count(self, key: str, since_utc: float) -> int:
        with self.transaction():
            return self.db.execute("SELECT count(*) FROM commands WHERE key=? AND created>=?", (key, since_utc)).fetchone()[0]

    def meta(self, key: str, value: str | None = None) -> str | None:
        with self.transaction():
            if value is not None:
                self.db.execute("INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row[0] if row else None

    def prune(self, now_utc: float):
        with self.transaction():
            self.db.execute("DELETE FROM commands WHERE created<? AND outcome!='pending'", (now_utc - 86400 * 31,))
            self.db.execute("DELETE FROM incidents WHERE closed IS NOT NULL AND id NOT IN (SELECT id FROM incidents WHERE closed IS NOT NULL ORDER BY closed DESC LIMIT 100)")

    def finish_incident(self, key, outcome):
        if outcome not in ("radio_confirmed", "application_only", "binding_removed"):
            raise StoreError("Неизвестный исход инцидента")
        with self.transaction():
            state = self._load(key)
            if state.incident_id:
                self.db.execute("UPDATE incidents SET closed=?,outcome=? WHERE id=? AND key=?", (self._logical_now(), outcome, state.incident_id, key))
                self._save(key, replace(state, incident_id=""))

    def incident_summary(self, key: str) -> dict:
        with self.transaction():
            state = self._load(key)
            recent = [{"id": row["id"], "outcome": row["outcome"], "duration": max(0, (row["closed"] if row["closed"] is not None else self._logical_now()) - row["opened"])}
                      for row in self.db.execute("SELECT * FROM incidents WHERE key=? ORDER BY opened DESC LIMIT 100", (key,))]
            return {"phase": state.phase, "incident_id": state.incident_id, "pending": bool(state.pending_action), "recent": recent}

    def close(self):
        with self.lock:
            self.db.close()

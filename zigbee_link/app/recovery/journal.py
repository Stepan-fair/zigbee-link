"""Local bounded incident details. Only explicit safe fields are serialized."""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import threading
import time


@dataclass(frozen=True)
class SafeEvent:
    code: str
    network: str
    phase: str = ""
    previous: str = ""
    incident: str = ""
    action: str = ""
    outcome: str = ""
    facts: dict = field(default_factory=dict)


FACTS = {"misses", "successes", "hour_count", "day_count", "seconds", "health_failures", "next_seconds", "present", "conflict"}
FACTS.update({"revision", "candidate_count", "network_count"})
WAITING = {"coordinator_absent", "network_unavailable", "mqtt_unavailable", "supervisor_unavailable", "permission_unknown", "action_budget", "action_backoff", "measurement_unknown", "radio_not_confirmed"}
WAITING.update({"radio_confirmed", "scheduler_busy", "disabled", "maintenance", "configuration_error", "address_conflict",
                "identity_mismatch", "binding_invalid", "command_pending", "app_busy", "return_grace",
                "app_state_unknown", "clock_untrusted", "startup_or_health_grace"})


class EventJournal:
    def __init__(self, directory: Path, max_bytes=50 * 1024 * 1024, clock=time.time):
        self.directory, self.max_bytes, self.clock = directory, max_bytes, clock
        self.max_files = min(32, max(2, max_bytes // 1024))
        self.chunk = max_bytes // self.max_files
        self.lock = threading.RLock()
        self.last = {}
        self.sequence = 0
        self.debug_until = 0

    @property
    def debug_enabled(self):
        return self.clock() < self.debug_until

    def enable_debug(self):
        self.debug_until = self.clock() + 900

    def _path(self, number):
        p = self.directory / f"events.{number}.jsonl"
        if p.is_symlink():
            raise OSError("unsafe diagnostic path")
        return p

    def _rotate(self):
        oldest = self._path(self.max_files - 1)
        oldest.unlink(missing_ok=True)
        for n in range(self.max_files - 2, -1, -1):
            old = self._path(n)
            if old.exists():
                os.replace(old, self._path(n + 1))

    def emit(self, event: SafeEvent):
        if not isinstance(event, SafeEvent):
            raise ValueError("Требуется безопасное событие")
        for value in (event.code, event.network, event.phase, event.previous, event.incident, event.action, event.outcome):
            if not isinstance(value, str) or len(value) > 100 or not re.fullmatch(r"[a-zA-Z0-9_.:/-]*", value):
                raise ValueError("Некорректное поле события")
        now = self.clock()
        with self.lock:
            key = (event.network, event.code, event.phase)
            if event.code in WAITING and (not event.previous or event.previous == event.phase) and 0 <= now - self.last.get(key, float("-inf")) < 300 and not self.debug_enabled:
                return True
            facts = {k: v for k, v in event.facts.items() if k in FACTS and type(v) in (int, bool) and abs(int(v)) <= 10**12}
            self.sequence += 1
            raw = {"utc": now, "sequence": self.sequence, "network": event.network, "incident": event.incident,
                   "code": event.code, "phase": event.phase, "previous": event.previous,
                   "action": event.action, "outcome": event.outcome, "facts": facts}
            line = (json.dumps(raw, ensure_ascii=True, allow_nan=False) + "\n").encode()
            if len(line) > self.chunk:
                return False
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
                if self.directory.is_symlink():
                    return False
                os.chmod(self.directory, 0o700)
                for n in range(self.max_files):
                    p = self._path(n)
                    if p.exists() and p.stat().st_mtime < now - 30 * 86400:
                        p.unlink()
                p = self._path(0)
                if p.exists() and (p.stat().st_size + len(line) > self.chunk or int(p.stat().st_mtime // 86400) != int(now // 86400)):
                    self._rotate()
                with p.open("ab") as f:
                    f.write(line)
                os.chmod(p, 0o600)
                os.utime(p, (now, now))
                self.last[key] = now
                return True
            except OSError:
                return False

    def summary(self, key, now):
        return {"network": key, "detail_limit_bytes": self.max_bytes, "debug": self.debug_enabled}

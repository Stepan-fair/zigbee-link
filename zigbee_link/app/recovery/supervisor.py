"""Fixed-origin Supervisor access. No arbitrary endpoint forwarding."""
from dataclasses import dataclass, replace
import json
import math
import re
import time
from urllib import request, error

from .model import AppObservation
from .settings import parse_recovery


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: bytes


@dataclass(frozen=True)
class CommandOutcome:
    accepted: bool
    reason: str


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HttpTransport:
    def __init__(self, token):
        self._token = token
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, body=None, timeout=5):
        if method not in ("GET", "POST") or not path.startswith("/") or "//" in path or ".." in path:
            raise ValueError("Запрещённый запрос Supervisor")
        req = request.Request("http://supervisor" + path, data=b"{}" if method == "POST" else None,
                              method=method, headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as response:
                data = response.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    return HttpResult(502, b"")
                return HttpResult(response.status, data)
        except (OSError, error.URLError, ValueError):
            return HttpResult(503, b"")


class SupervisorClient:
    def __init__(self, token, transport=None, bindings=(), network_settings=None, clock=time.monotonic):
        self.transport = transport if transport is not None else HttpTransport(token)
        self.bindings = tuple(bindings)
        self.network_settings = network_settings
        self.clock = clock
        self.watchdogs = {}

    def _check(self, binding):
        if binding not in self.bindings:
            raise ValueError("Приложение отсутствует в разрешённой привязке")

    def _data(self, method, path):
        try:
            response = self.transport.request(method, path, timeout=5)
            if response.status != 200 or len(response.body) > 1024 * 1024:
                return None
            raw = json.loads(response.body)
            if not isinstance(raw, dict) or raw.get("result") != "ok" or not isinstance(raw.get("data", {}), dict):
                return None
            return raw.get("data", {})
        except (OSError, ValueError, TypeError, TimeoutError):
            return None

    def self_controls(self):
        data = self._data("GET", "/addons/self/info")
        if data is None or self.network_settings is None:
            return {}
        options = data.get("options")
        if not isinstance(options, dict):
            return {}
        config = parse_recovery(options.get("recovery", {}), self.network_settings)
        now = self.clock()
        return {b.key: replace(config.controls[b.key], observed_at=now) for b in self.bindings if b in config.bindings}

    def _busy(self, slug):
        data = self._data("GET", "/jobs/info")
        if data is None or not isinstance(data.get("jobs"), list):
            return True
        pending = list(data["jobs"])
        checked = 0
        while pending:
            checked += 1
            if checked > 256:
                return True
            job = pending.pop()
            if not isinstance(job, dict) or type(job.get("done")) is not bool or not isinstance(job.get("child_jobs"), list) or not isinstance(job.get("name"), str):
                return True
            if not job["done"] and (job.get("reference") == slug or job["name"].startswith("backup_")):
                return True
            pending.extend(job["child_jobs"])
        return False

    def _watchdog_busy(self, binding, data, state):
        slug = binding.addon_slug
        options = data.get("options", {})
        if state != "started" or (isinstance(options, dict) and not options.get("watchdog")):
            self.watchdogs.pop(slug, None)
            return False
        # Z2M's own retry timer runs inside a started container. Supervisor jobs
        # alone cannot identify it. Ambiguous logs defer our restart, never race it.
        try:
            response = self.transport.request("GET", f"/addons/{slug}/logs/latest?lines=200", timeout=5)
            if response.status != 200 or len(response.body) > 1024 * 1024:
                return True
            text = re.sub(r"\x1b\[[0-9;]*m", "", response.body.decode("utf-8", errors="replace"))
            markers = [line for line in text.splitlines() if
                       "WATCHDOG: Waiting " in line or "Starting Zigbee2MQTT " in line or "Zigbee2MQTT started!" in line]
            if not markers:
                return True
            last = markers[-1]
            if "Zigbee2MQTT started!" in last:
                self.watchdogs.pop(slug, None)
                return False
            token = tuple(markers[-8:])
            if slug not in self.watchdogs or self.watchdogs[slug][0] != token:
                wait = re.search(r"WATCHDOG: Waiting ([0-9]+(?:\.[0-9]+)?)min before next start try\.\s*$", last)
                if wait:
                    delay = float(wait[1]) * 60
                    if not math.isfinite(delay) or delay > 31 * 86400:
                        return True
                elif "Starting Zigbee2MQTT " in last:
                    delay = 0
                else:
                    return True
                self.watchdogs[slug] = (token, self.clock() + delay + 180)
            return self.clock() < self.watchdogs[slug][1]
        except (OSError, ValueError, TimeoutError):
            return True

    def observe(self, binding):
        self._check(binding)
        data = self._data("GET", f"/addons/{binding.addon_slug}/info")
        if data is None:
            return AppObservation()
        valid = data.get("slug") == binding.addon_slug and isinstance(data.get("name"), str) and "zigbee2mqtt" in data["name"].lower().replace(" ", "")
        version = data.get("version", "")
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?", version) if isinstance(version, str) else None
        valid = valid and bool(match) and tuple(int(v) for v in match.groups()) >= (2, 14, 2) and int(match[1]) == 2
        state = data.get("state")
        state = state if state in ("started", "stopped", "error") else "unknown"
        run_id = data.get("run_id")
        busy = self._busy(binding.addon_slug) or self._watchdog_busy(binding, data, state)
        return AppObservation(True, state, run_id if isinstance(run_id, str) else None, busy, valid)

    def command(self, binding, kind):
        self._check(binding)
        if kind not in ("start", "restart"):
            raise ValueError("Команда Supervisor запрещена")
        data = self._data("POST", f"/addons/{binding.addon_slug}/{kind}")
        # HTTP acceptance is not proof that the app has started.
        return CommandOutcome(data is not None, "accepted" if data is not None else "outcome_unknown")

    def diagnose(self, binding, limit=200):
        self._check(binding)
        try:
            response = self.transport.request("GET", f"/addons/{binding.addon_slug}/logs/latest?lines={min(max(limit, 1), 200)}", timeout=5)
            if response.status != 200 or len(response.body) > 1024 * 1024:
                return []
            text = response.body.decode("utf-8", errors="replace")
            signatures = {"ASH_NCP_FATAL_ERROR": "adapter_fatal", "HOST_FATAL_ERROR": "adapter_fatal",
                          "Adapter disconnected": "adapter_disconnected", "ECONNRESET": "connection_reset",
                          "ECONNREFUSED": "connection_refused"}
            return sorted({code for marker, code in signatures.items() if marker in text})
        except (OSError, ValueError, TimeoutError):
            return []

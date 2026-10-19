"""Supervisor metadata, optional MQTT service and own configuration transitions."""
from copy import deepcopy
from hashlib import sha256
from ipaddress import IPv4Address
import json
import re
import threading
import time
from urllib.parse import urlsplit
from ..recovery.settings import MqttSettings, SLUG, _mqtt
from .model import AppMetadata, BrokerRecord, BrokerConnection, SupervisorCapabilities
from .validation import decode_metadata, valid_topic


class DiscoverySourceError(RuntimeError):
    pass


def options_digest(options):
    return sha256(json.dumps(options, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def supports_admin_ingress(version):
    match = re.fullmatch(r"(\d{4})\.(\d{1,2})\.(\d+)", version) if isinstance(version, str) else None
    return bool(match and tuple(map(int, match.groups())) >= (2026, 10, 2))


def serial_endpoint(value):
    if not isinstance(value, str) or len(value) > 300:
        return None, None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("tcp", "socket") or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None, None
        return str(IPv4Address(parsed.hostname)), parsed.port
    except (ValueError, TypeError):
        return None, None


class SupervisorCatalogReader:
    def __init__(self, transport):
        self.transport = transport
        self.issues = ()
        self.slots = threading.BoundedSemaphore(2)
        self.scan_cancelled = threading.Event()
        self.scan_deadline = None

    def begin_scan(self, deadline):
        self.scan_deadline = deadline
        self.scan_cancelled.clear()

    def cancel_scan(self):
        self.scan_cancelled.set()

    def _get(self, path, *, optional=False, method="GET", body=None, scan=False):
        if method not in ("GET", "POST") or method == "POST" and path != "/addons/self/options":
            raise ValueError("setup_endpoint_forbidden")
        timeout = 5
        if scan:
            if self.scan_cancelled.is_set():
                raise DiscoverySourceError("scan_cancelled")
            if self.scan_deadline is not None:
                timeout = min(5, self.scan_deadline - time.monotonic())
                if timeout <= 0:
                    raise DiscoverySourceError("scan_timeout")
        started = time.monotonic()
        if not self.slots.acquire(timeout=timeout):
            raise DiscoverySourceError("supervisor_busy")
        try:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0 or scan and self.scan_cancelled.is_set():
                raise DiscoverySourceError("scan_timeout")
            response = self.transport.request(method, path, body=body, timeout=remaining)
        except (OSError, TimeoutError, ValueError):
            raise DiscoverySourceError("supervisor_unavailable") from None
        finally:
            self.slots.release()
        if optional and response.status in (400, 404):
            return None
        if response.status != 200:
            raise DiscoverySourceError("supervisor_unavailable")
        try:
            raw = decode_metadata(response.body)
            if not isinstance(raw, dict) or raw.get("result") != "ok" or not isinstance(raw.get("data", {}), dict):
                raise ValueError("response_invalid")
            return raw.get("data", {})
        except (ValueError, TypeError):
            raise DiscoverySourceError("supervisor_response_invalid") from None

    def apps(self):
        raw = self._get("/addons", scan=True)
        if not isinstance(raw.get("addons"), list):
            raise DiscoverySourceError("supervisor_response_invalid")
        result, issues = [], []
        for item in raw["addons"][:1024]:
            if self.scan_cancelled.is_set() or self.scan_deadline is not None and time.monotonic() >= self.scan_deadline:
                issues.append("scan_timeout")
                break
            slug = item.get("slug") if isinstance(item, dict) else None
            if not isinstance(slug, str) or not SLUG.fullmatch(slug) or "zigbee2mqtt" not in slug or item.get("installed") is False:
                continue
            try:
                info = self._get(f"/addons/{slug}/info", scan=True)
            except DiscoverySourceError:
                issues.append("addon_info_unavailable")
                continue
            name, version = info.get("name"), info.get("version")
            match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?", version) if isinstance(version, str) else None
            if (info.get("slug") != slug or not isinstance(name, str) or "zigbee2mqtt" not in name.lower().replace(" ", "")
                    or not match or int(match[1]) != 2 or tuple(map(int, match.groups())) < (2, 14, 2)
                    or item.get("repository") and info.get("repository") and item["repository"] != info["repository"]):
                issues.append("addon_unsupported")
                continue
            options = info.get("options", {})
            if not isinstance(options, dict):
                issues.append("addon_options_invalid")
                continue
            serial, mqtt = options.get("serial", {}), options.get("mqtt", {})
            serial = serial if isinstance(serial, dict) else {}
            mqtt = mqtt if isinstance(mqtt, dict) else {}
            ip, port = serial_endpoint(serial.get("port"))
            adapter = serial.get("adapter")
            adapter = adapter if isinstance(adapter, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", adapter) else None
            server = None
            if mqtt.get("server"):
                try:
                    server = _mqtt({"server": mqtt["server"]}).server
                except ValueError:
                    issues.append("addon_broker_invalid")
            result.append(AppMetadata(slug, "".join(c for c in name if ord(c) >= 32)[:100], version,
                          info.get("state", "unknown"), ip, port, adapter,
                          mqtt.get("base_topic") if valid_topic(mqtt.get("base_topic")) else None, server))
            if len(result) >= 253:
                issues.append("scan_limit")
                break
        self.issues = tuple(dict.fromkeys(issues))
        return tuple(result)

    def mqtt_service(self, *, scan=False):
        raw = self._get("/services/mqtt", optional=True, scan=scan)
        if raw is None:
            return None
        try:
            host, provider = raw["host"], raw["addon"]
            if not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,253}", host) or not isinstance(provider, str) or not SLUG.fullmatch(provider) or type(raw.get("ssl", False)) is not bool or isinstance(raw["port"], bool):
                raise ValueError("invalid_service")
            port = int(raw["port"])
            scheme = "mqtts" if raw.get("ssl") else "mqtt"
            server = f"{scheme}://{host}:{port}"
            settings = _mqtt({"server": server, "username": raw.get("username", ""), "password": raw.get("password", "")})
            aliases = {host}
            info = self._get(f"/addons/{provider}/info", scan=scan)
            if info.get("slug") != provider:
                raise ValueError("invalid_provider")
            for key in ("hostname", "ip_address"):
                alias = info.get(key)
                if isinstance(alias, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,253}", alias):
                    aliases.add(alias)
            identity = "service:" + sha256((provider + ":" + server).encode()).hexdigest()
            return BrokerConnection(BrokerRecord(identity, "auto", server, provider, tuple(sorted(aliases))), settings)
        except (ValueError, TypeError, KeyError):
            raise DiscoverySourceError("mqtt_service_invalid") from None

    def self_options(self):
        data = self._get("/addons/self/info")
        if not isinstance(data.get("options"), dict):
            raise DiscoverySourceError("self_options_unavailable")
        return deepcopy(data["options"])

    def capabilities(self):
        version = self._get("/supervisor/info").get("version", "unknown")
        port = self._get("/addons/self/info").get("ingress_port")
        port = port if type(port) is int and 62000 <= port <= 65500 else None
        return SupervisorCapabilities(version if isinstance(version, str) else "unknown", port,
                                      bool(port and supports_admin_ingress(version)))

    def set_mode(self, target_mode, *, expected_digest, legacy_options=None):
        if target_mode not in ("legacy", "guided") or legacy_options is not None and (not isinstance(legacy_options, dict) or set(legacy_options) - {"recovery"}):
            raise ValueError("mode_change_invalid")
        try:
            current = self.self_options()
            if options_digest(current) != expected_digest:
                return False
            updated = {**current, **(legacy_options or {}), "configuration_mode": target_mode}
            self._get("/addons/self/options", method="POST", body={"options": updated})
            return options_digest(self.self_options()) == options_digest(updated)
        except (DiscoverySourceError, ValueError, TypeError):
            return False

    def close(self):
        close = getattr(self.transport, "close", None)
        if close:
            close()

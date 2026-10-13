from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import IPv4Address
import json
import re
from urllib.parse import urlsplit

from .model import Binding, Controls, Reference

IEEE = re.compile(r"0x[0-9a-fA-F]{16}")
SLUG = re.compile(r"[a-z0-9_]{1,100}")
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}")


@dataclass(frozen=True)
class MqttSettings:
    server: str
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)


@dataclass(frozen=True)
class RecoveryConfiguration:
    enabled: bool
    bindings: tuple[Binding, ...]
    controls: dict[str, Controls]
    mqtt: MqttSettings | None
    errors: dict[str, str]


def fingerprint(binding: Binding) -> str:
    from dataclasses import asdict
    return sha256(json.dumps(asdict(binding), sort_keys=True).encode()).hexdigest()


def _ieee(value):
    if not isinstance(value, str) or not IEEE.fullmatch(value):
        raise ValueError("invalid IEEE")
    return value.lower()


def _bool(record, name, default=False):
    value = record.get(name, default)
    if type(value) is not bool:
        raise ValueError("invalid control")
    return value


def _mqtt(raw):
    if not isinstance(raw, dict):
        raise ValueError("invalid MQTT")
    server = raw.get("server", "")
    if not isinstance(server, str) or len(server) > 300:
        raise ValueError("invalid MQTT")
    parsed = urlsplit(server)
    if parsed.scheme not in ("mqtt", "mqtts") or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("invalid MQTT")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid MQTT")
    for name in ("username", "password"):
        if not isinstance(raw.get(name, ""), str) or len(raw.get(name, "")) > 1024:
            raise ValueError("invalid MQTT")
    return MqttSettings(server, raw.get("username", ""), raw.get("password", ""))


def parse_recovery(raw: dict, network_settings) -> RecoveryConfiguration:
    errors, bindings, controls = {}, [], {}
    mqtt = None
    try:
        enabled = _bool(raw, "enabled")
        records = raw.get("networks", [])
        if not isinstance(records, list) or len(records) > 253:
            raise ValueError("invalid list")
        if raw.get("mqtt"):
            mqtt = _mqtt(raw["mqtt"])
        if enabled and records and mqtt is None:
            raise ValueError("missing MQTT")
    except (ValueError, TypeError, AttributeError):
        return RecoveryConfiguration(False, (), {}, None, {"configuration": "Некорректные настройки восстановления/MQTT"})
    allowed_ips = {str(c.address) for c in network_settings.coordinators}
    for index, record in enumerate(records):
        key = f"record-{index + 1}"
        try:
            if not isinstance(record, dict):
                raise ValueError("invalid record")
            ip = str(IPv4Address(record.get("ip")))
            if ip not in allowed_ips:
                raise ValueError("unregistered IP")
            slug, topic = record.get("addon_slug"), record.get("base_topic")
            if not isinstance(slug, str) or not SLUG.fullmatch(slug) or "zigbee2mqtt" not in slug:
                raise ValueError("invalid slug")
            if not isinstance(topic, str) or not topic or len(topic) > 200 or topic.startswith("/") or topic.endswith("/") or any(ord(c) < 32 or ord(c) == 127 or c in "#+" for c in topic):
                raise ValueError("invalid topic")
            refs = record.get("references", [])
            if not isinstance(refs, list) or len(refs) > 2:
                raise ValueError("invalid references")
            references = []
            for ref in refs:
                endpoint = ref["endpoint"]
                if type(endpoint) is not int or not 1 <= endpoint <= 240 or any(not isinstance(ref.get(k), str) or not IDENTIFIER.fullmatch(ref[k]) for k in ("cluster", "attribute")):
                    raise ValueError("invalid reference")
                references.append(Reference(_ieee(ref["ieee"]), endpoint, ref["cluster"], ref["attribute"]))
            binding = Binding(ip, ip, slug, topic, _ieee(record.get("coordinator_ieee")), tuple(references))
            managed, paused = _bool(record, "managed"), _bool(record, "paused")
            revision = sha256(f"{fingerprint(binding)}:{enabled}:{managed}:{paused}".encode()).hexdigest()
            bindings.append(binding)
            controls[ip] = Controls(enabled and managed, paused, revision)
        except (ValueError, TypeError, KeyError, AttributeError):
            errors[key] = "Некорректная привязка сети; восстановление запрещено"
    duplicates = set()
    for field_name in ("ip", "addon_slug", "base_topic"):
        seen = {}
        for index, binding in enumerate(bindings):
            value = getattr(binding, field_name)
            if value in seen:
                duplicates.update((index, seen[value]))
            seen[value] = index
    valid = []
    for index, binding in enumerate(bindings):
        if index in duplicates:
            errors[f"duplicate-{index + 1}"] = "Повторная привязка IP/приложения/MQTT; восстановление запрещено"
        else:
            valid.append(binding)
    return RecoveryConfiguration(enabled, tuple(valid), {b.key: controls[b.key] for b in valid}, mqtt, errors)

"""Strict boundary validation; partially discovered settings confer no rights."""
import json
from ipaddress import IPv4Address
from ..recovery.settings import IEEE, SLUG, IDENTIFIER
from .model import Readiness, FieldValue

FIELDS = frozenset(("name", "ip", "serial_port", "adapter", "addon_slug", "base_topic",
                    "coordinator_ieee", "references"))
PINNED = frozenset(("ip", "serial_port", "addon_slug", "base_topic", "coordinator_ieee"))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non_finite_number")


def decode_metadata(payload: bytes) -> object:
    if not isinstance(payload, bytes) or len(payload) > 1048576:
        raise ValueError("metadata_size")
    quoted = escaped = False
    depth = 0
    for c in payload:
        if quoted:
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
        elif c == 34:
            quoted = True
        elif c in (91, 123):
            depth += 1
            if depth > 32:
                raise ValueError("metadata_depth")
        elif c in (93, 125):
            depth -= 1
    try:
        return json.loads(payload, object_pairs_hook=_unique, parse_constant=_invalid_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid_metadata") from None


def valid_topic(value):
    return (isinstance(value, str) and 0 < len(value) <= 200 and not value.startswith("/")
            and not value.endswith("/") and not any(ord(c) < 32 or ord(c) == 127 or c in "#+" for c in value))


def select_configuration_mode(options: dict) -> str:
    mode = options.get("configuration_mode", "legacy")
    if mode not in ("legacy", "guided"):
        raise ValueError("invalid_configuration_mode")
    return mode


def configuration_readiness(enabled, broker_configured, valid_networks, managed_networks, issues=()):
    reasons = list(issues)
    if enabled:
        if not broker_configured:
            reasons.append("mqtt_unconfigured")
        if not valid_networks:
            reasons.append("networks_empty")
    return Readiness(enabled, bool(broker_configured and valid_networks),
                     managed_networks if enabled and broker_configured else 0, tuple(dict.fromkeys(reasons)))


def validate_network(record, subnet):
    issues = list(record.issues)
    values = {}
    if any(type(v) is not bool for v in (record.managed, record.paused, record.accepted, record.tombstoned)):
        issues.append("invalid_controls")
    for key, field in record.fields.items():
        if key not in FIELDS or not isinstance(field, FieldValue) or field.mode not in ("auto", "manual"):
            issues.append("invalid_field")
        else:
            values[key] = field.value
    try:
        ip = IPv4Address(values.get("ip"))
        if ip not in subnet or ip in (subnet.network_address, subnet.broadcast_address):
            issues.append("ip_outside_subnet")
    except (ValueError, TypeError):
        issues.append("invalid_ip")
    slug, topic, ieee = (values.get(k) for k in ("addon_slug", "base_topic", "coordinator_ieee"))
    if not isinstance(slug, str) or not SLUG.fullmatch(slug) or "zigbee2mqtt" not in slug:
        issues.append("invalid_addon")
    if not valid_topic(topic):
        issues.append("invalid_topic")
    if not isinstance(ieee, str) or not IEEE.fullmatch(ieee):
        issues.append("invalid_ieee")
    port = values.get("serial_port")
    if type(port) is not int or not 1 <= port <= 65535:
        issues.append("invalid_port")
    refs = values.get("references", [])
    if not isinstance(refs, (list, tuple)) or len(refs) > 2:
        issues.append("invalid_references")
    else:
        for ref in refs:
            if not isinstance(ref, dict) or not isinstance(ref.get("ieee"), str) or not IEEE.fullmatch(ref["ieee"]) or type(ref.get("endpoint")) is not int or not 1 <= ref["endpoint"] <= 240 or any(not isinstance(ref.get(k), str) or not IDENTIFIER.fullmatch(ref[k]) for k in ("cluster", "attribute")):
                issues.append("invalid_references")
    name = values.get("name", "")
    if not isinstance(name, str) or len(name) > 100 or any(ord(c) < 32 for c in name):
        issues.append("invalid_name")
    return tuple(dict.fromkeys(issues))

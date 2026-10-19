"""Pure metadata matching. Verified metadata still grants no command permission."""
from collections import Counter
from dataclasses import replace
from hashlib import sha256
from ipaddress import IPv4Address
import json
from urllib.parse import urlsplit
from ..recovery.model import Reference
from ..recovery.radio import ATTRIBUTES
from ..recovery.settings import IEEE
from .model import Candidate, FieldValue
from .validation import PINNED, valid_topic


def broker_matches(server, broker):
    if server is None:
        return True
    try:
        observed, selected = urlsplit(server), urlsplit(broker.server)
        if observed.scheme not in ("mqtt", "mqtts") or observed.username is not None or observed.password is not None or observed.path not in ("", "/") or observed.query or observed.fragment:
            return False
        default = 8883 if observed.scheme == "mqtts" else 1883
        hosts = {h.lower() for h in (*broker.aliases, selected.hostname) if isinstance(h, str)}
        return bool(observed.hostname and observed.hostname.lower() in hosts
                    and observed.scheme == selected.scheme
                    and (observed.port or default) == (selected.port or default))
    except (ValueError, AttributeError, TypeError):
        return False


def _candidate(app, bridge, broker, subnet, conflicts, *, ambiguous=False):
    ip = bridge.ip if bridge and bridge.ip else app.serial_ip if app else None
    port = bridge.port if bridge and bridge.port else app.serial_port if app else None
    topic = bridge.base_topic if bridge else app.base_topic if app else None
    ieee = bridge.coordinator_ieee if bridge else None
    issues = []
    kind = "verified" if app and bridge else "proposed" if app else "external"
    linked = bool(app and bridge and (app.serial_ip and app.serial_ip == bridge.ip
                  and app.serial_port is not None and app.serial_port == bridge.port or app.base_topic and app.base_topic == bridge.base_topic))
    if app and bridge and not linked:
        kind = "proposed"
        issues.append("association_unconfirmed")
    if app and bridge and (app.serial_ip and app.serial_ip != bridge.ip or
                          app.serial_port and app.serial_port != bridge.port or
                          app.base_topic and app.base_topic != bridge.base_topic):
        issues.append("source_conflict")
        kind = "conflict"
    if broker is not None and any(not broker_matches(server, broker) for server in (
            app.broker_server if app else None, bridge.broker_server if bridge else None)):
        issues.append("foreign_broker")
        kind = "conflict"
    try:
        address = IPv4Address(ip)
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise ValueError()
    except (ValueError, TypeError):
        issues.append("ip_outside_subnet" if ip else "ip_missing")
        kind = "conflict" if ip else "proposed"
    if ambiguous or ip in conflicts:
        kind = "conflict"
        issues.append("identity_conflict")
    if not bridge or not isinstance(ieee, str) or not IEEE.fullmatch(ieee) or not valid_topic(topic):
        issues.append("bridge_metadata_missing")
        if kind == "verified":
            kind = "proposed"
    if broker is None:
        issues.append("mqtt_unconfigured")
        kind = "proposed" if kind != "conflict" else kind
    name = ((app.name if app else "Zigbee2MQTT") + (" · " + ip if ip else ""))[:100]
    values = {"name": name, "ip": ip, "serial_port": port, "adapter": app.adapter if app else None,
              "addon_slug": app.slug if app else None, "base_topic": topic,
              "coordinator_ieee": ieee.lower() if isinstance(ieee, str) else None, "references": []}
    fields = {k: FieldValue("auto", value, "supervisor" if k in ("name", "addon_slug", "adapter") and app else "mqtt",
                           bridge.observed_at if bridge else 0,
                           "retained" if bridge and bridge.retained else "unverified") for k, value in values.items()}
    token = json.dumps([values[k] for k in ("addon_slug", "ip", "serial_port", "base_topic", "coordinator_ieee")], sort_keys=True)
    return Candidate(sha256(token.encode()).hexdigest()[:32], fields, tuple(dict.fromkeys(issues)), kind)


def match_networks(apps, bridges, *, broker, subnet, conflicts=frozenset()):
    result, assigned = [], set()
    for app in apps[:253]:
        possible = [b for b in bridges if (app.serial_ip and b.ip == app.serial_ip) or
                    (app.base_topic and b.base_topic == app.base_topic)]
        if not possible and len(apps) == 1 and len(bridges) == 1:
            possible = list(bridges)
        if not possible:
            result.append(_candidate(app, None, broker, subnet, conflicts))
        else:
            for bridge in possible:
                assigned.add(bridge)
                result.append(_candidate(app, bridge, broker, subnet, conflicts, ambiguous=len(possible) > 1))
    for bridge in bridges:
        if bridge not in assigned:
            result.append(_candidate(None, bridge, broker, subnet, conflicts))
    counts = {field: Counter(r.fields[field].value for r in result if r.fields[field].value)
              for field in ("ip", "addon_slug", "base_topic")}
    unique = {}
    for row in result:
        if any(counts[field].get(row.fields[field].value, 0) > 1 for field in counts):
            row = replace(row, match_kind="conflict", issues=tuple(dict.fromkeys((*row.issues, "identity_conflict"))))
        unique[row.candidate_id] = row
    return tuple(sorted(unique.values(), key=lambda c: c.candidate_id))[:253]


def suggest_references(devices):
    choices = []
    for device in devices[:4096]:
        if not isinstance(device, dict):
            continue
        ieee, power = device.get("ieee_address"), device.get("power_source")
        interviewed = device.get("interview_state") == "SUCCESSFUL" or (
            "interview_state" not in device and device.get("interview_completed") is True and not device.get("interviewing"))
        if (device.get("type") != "Router" or device.get("disabled") or not interviewed or
            not isinstance(power, str) or not power.lower().startswith(("mains", "dc source")) or
            not isinstance(ieee, str) or not IEEE.fullmatch(ieee)):
            continue
        endpoints = device.get("endpoints", {})
        if not isinstance(endpoints, dict):
            continue
        per_device = []
        for endpoint, data in endpoints.items():
            if not isinstance(endpoint, str) or not endpoint.isdigit() or not 1 <= int(endpoint) <= 240 or not isinstance(data, dict):
                continue
            clusters = data.get("clusters", {})
            inputs = clusters.get("input", []) if isinstance(clusters, dict) else []
            reporting = data.get("configured_reportings", [])
            if not isinstance(inputs, list) or not isinstance(reporting, list):
                continue
            for (cluster, attribute), attr_id in ATTRIBUTES.items():
                if cluster not in inputs:
                    continue
                configured = any(isinstance(r, dict) and r.get("cluster") == cluster and
                                 r.get("attribute") in (attribute, attr_id) for r in reporting)
                per_device.append((0 if configured else 1, int(endpoint), cluster, attribute))
        if per_device:
            rank, endpoint, cluster, attribute = min(per_device)
            choices.append((rank, ieee.lower(), Reference(ieee.lower(), endpoint, cluster, attribute)))
    ordered = sorted(choices, key=lambda c: c[:2])
    seen, result = set(), []
    for _, ieee, reference in ordered:
        if ieee not in seen:
            result.append(reference)
            seen.add(ieee)
        if len(result) == 2:
            break
    return tuple(result)


def merge_suggestions(record, candidate):
    fields = dict(record.fields)
    for key, proposed in candidate.fields.items():
        old = fields.get(key)
        if old and (old.mode == "manual" or record.accepted and key in PINNED | {"references"}):
            fields[key] = replace(old, proposal=proposed.value if old.value != proposed.value else None)
        else:
            fields[key] = proposed
    return replace(record, fields=fields)

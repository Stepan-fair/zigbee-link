"""Bounded, correlated MQTT evidence; no actuator commands."""
from collections import deque
from dataclasses import dataclass
import json
import threading
import time
from urllib.parse import urlsplit
import uuid

from .model import Reference


@dataclass(frozen=True)
class ReportingReply:
    reference: Reference
    generation: str
    transaction: str
    at: float
    status: str
    data: dict
    retained: bool = False


@dataclass(frozen=True)
class MqttObservation:
    connected: bool
    generation: str
    health: bool | None
    health_sequence: int
    identity_match: bool | None
    radio_replies: tuple[ReportingReply, ...]


class MqttMonitor:
    def __init__(self, settings, bindings, client=None, clock=time.monotonic):
        if client is None:
            import paho.mqtt.client as mqtt
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="zigbee-link-" + uuid.uuid4().hex, clean_session=True)
        self.client, self.settings, self.clock = client, settings, clock
        self.bindings = {b.key: b for b in bindings}
        self.lock = threading.RLock()
        self.connected = False
        self.stopped = False
        self.cleanup_done = threading.Event()
        self.cleanup_ok = False
        self.cleanup_thread = None
        self.pending = {}
        self.epochs = {b.key: uuid.uuid4().hex for b in bindings}
        self.evidence = {b.key: {"health": None, "health_at": -1, "sequence": 0, "identity": None, "identity_at": -1, "radio": deque(maxlen=2)} for b in bindings}
        self.topics = {b.base_topic + "/bridge/" + suffix: (b.key, suffix) for b in bindings for suffix in (
            "info", "state", "response/health_check", "response/device/reporting/read")}
        client.username_pw_set(settings.username or None, settings.password or None)
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        client.max_queued_messages_set(512)
        client.max_inflight_messages_set(20)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        if urlsplit(settings.server).scheme == "mqtts":
            client.tls_set()

    def start(self):
        parsed = urlsplit(self.settings.server)
        self.client.connect_async(parsed.hostname, parsed.port or (8883 if parsed.scheme == "mqtts" else 1883), keepalive=30)
        self.client.loop_start()

    def stop(self):
        with self.lock:
            if self.cleanup_thread is None:
                self.stopped, self.connected = True, False
                for key in self.bindings:
                    self.invalidate(key)
                def cleanup():
                    try:
                        self.client.disconnect()
                        self.client.loop_stop()
                        self.cleanup_ok = True
                    except Exception:
                        pass
                    finally:
                        self.cleanup_done.set()
                self.cleanup_thread = threading.Thread(target=cleanup, name="zigbee-mqtt-cleanup", daemon=True)
                self.cleanup_thread.start()
        self.cleanup_done.wait(.25)

    def reconfigure(self, bindings):
        with self.lock:
            old_topics = set(self.topics)
            changed = {key for key, binding in self.bindings.items() if binding not in bindings}
            for key in changed:
                self.invalidate(key)
            self.bindings = {b.key: b for b in bindings}
            self.pending = {tx: p for tx, p in self.pending.items() if p["key"] in self.bindings and p["key"] not in changed}
            self.epochs = {b.key: self.epochs.get(b.key, uuid.uuid4().hex) for b in bindings}
            self.evidence = {b.key: self.evidence.get(b.key, {"health": None, "health_at": -1, "sequence": 0,
                "identity": None, "identity_at": -1, "radio": deque(maxlen=2)}) for b in bindings}
            self.topics = {b.base_topic + "/bridge/" + suffix: (b.key, suffix) for b in bindings for suffix in (
                "info", "state", "response/health_check", "response/device/reporting/read")}
            if self.connected:
                removed, added = old_topics - self.topics.keys(), self.topics.keys() - old_topics
                if removed:
                    self.client.unsubscribe(list(removed))
                if added:
                    self.client.subscribe([(topic, 1) for topic in added])

    def _on_connect(self, client, userdata, flags, reason, properties):
        if reason == 0:
            self.on_connected()
        else:
            self._on_disconnect(client, userdata, None, reason, properties)

    def on_connected(self):
        with self.lock:
            if self.stopped:
                self.client.disconnect()
                return
            self.connected = True
            for key in self.bindings:
                self.invalidate(key)
            self.client.subscribe([(t, 1) for t in self.topics])

    def _on_disconnect(self, *args):
        with self.lock:
            self.connected = False
            self.pending.clear()
            for key in self.bindings:
                self.invalidate(key)

    def _on_message(self, client, userdata, message):
        self.receive(message.topic, message.payload, bool(message.retain), self.clock())

    def invalidate(self, key):
        with self.lock:
            self.epochs[key] = uuid.uuid4().hex
            e = self.evidence[key]
            e.update(health=None, health_at=-1, identity=None, identity_at=-1)
            e["radio"].clear()
            self.pending = {tx: p for tx, p in self.pending.items() if p["key"] != key}
            return self.epochs[key]

    def _expire(self, now):
        for tx, pending in list(self.pending.items()):
            if now >= pending["deadline"]:
                del self.pending[tx]
                if pending["kind"] == "health_check":
                    e = self.evidence[pending["key"]]
                    e.update(health=False, health_at=now, sequence=e["sequence"] + 1)

    def invalidate_health(self, key):
        with self.lock:
            self.evidence[key].update(health=None, health_at=-1)
            self.pending = {tx: p for tx, p in self.pending.items() if p["key"] != key or p["kind"] != "health_check"}

    def _request(self, key, kind, now, reference=None):
        with self.lock:
            if self.stopped or key not in self.bindings or not self.connected:
                return ""
            self._expire(now)
            for tx, p in self.pending.items():
                if p["key"] == key and p["kind"] == kind:
                    return tx
            if len(self.pending) >= 512:
                return ""
            tx = uuid.uuid4().hex
            payload = {"transaction": tx}
            if reference is not None:
                payload.update(id=reference.ieee, endpoint=reference.endpoint, cluster=reference.cluster,
                               configs=[{"attribute": reference.attribute}])
            self.pending[tx] = {"key": key, "kind": kind, "generation": self.epochs[key],
                                "deadline": now + (15 if reference is None else 30), "reference": reference}
            try:
                result = self.client.publish(self.bindings[key].base_topic + "/bridge/request/" + kind,
                                             json.dumps(payload), qos=1, retain=False)
                if result.rc != 0:
                    self.pending.pop(tx, None)
                    return ""
            except (OSError, ValueError, RuntimeError):
                self.pending.pop(tx, None)
                return ""
            return tx

    def request_health(self, key, now):
        return self._request(key, "health_check", now)

    def request_reporting_read(self, key, reference, now):
        return self._request(key, "device/reporting/read", now, reference)

    def receive(self, topic, payload, retained, now):
        if topic not in self.topics or len(payload) > 1024 * 1024:
            return
        try:
            raw = json.loads(payload)
            if not isinstance(raw, dict):
                return
        except (ValueError, UnicodeError, RecursionError):
            return
        with self.lock:
            if self.stopped or not self.connected or topic not in self.topics:
                return
            self._expire(now)
            key, suffix = self.topics[topic]
            if suffix == "state":
                if not retained and raw.get("state") in ("online", "offline"):
                    self.invalidate(key)
                return
            if suffix == "info":
                if retained:
                    return
                coordinator, config = raw.get("coordinator"), raw.get("config")
                if not isinstance(coordinator, dict) or not isinstance(config, dict) or not isinstance(config.get("serial"), dict):
                    return
                ieee, port = coordinator.get("ieee_address"), config["serial"].get("port")
                if not isinstance(ieee, str) or not isinstance(port, str):
                    return
                try:
                    match = ieee.lower() == self.bindings[key].coordinator_ieee and urlsplit(port).hostname == self.bindings[key].ip
                except ValueError:
                    match = False
                # Even unchanged info may follow an independent Z2M restart.
                # Require another radio exchange instead of reusing its old proof.
                self.evidence[key]["radio"].clear()
                self.pending = {tx: p for tx, p in self.pending.items() if p["key"] != key or p["kind"] != "device/reporting/read"}
                self.evidence[key].update(identity=match, identity_at=now)
                return
            tx = raw.get("transaction")
            if retained or not isinstance(tx, str) or tx not in self.pending:
                return
            pending = self.pending[tx]
            if pending["key"] != key or suffix != "response/" + pending["kind"] or pending["generation"] != self.epochs[key]:
                return
            del self.pending[tx]
            e = self.evidence[key]
            data = raw.get("data", {})
            if pending["kind"] == "health_check":
                good = raw.get("status") == "ok" and isinstance(data, dict) and data.get("healthy") is True
                e.update(health=good, health_at=now, sequence=e["sequence"] + 1)
            elif isinstance(data, dict):
                # Keep only protocol fields required for proof, not arbitrary MQTT payloads.
                selected = {k: data[k] for k in ("id", "endpoint", "cluster", "configs") if k in data}
                e["radio"].append(ReportingReply(pending["reference"], self.epochs[key], tx, now,
                                                 raw.get("status", "error"), selected))

    def snapshot(self, key, now):
        with self.lock:
            self._expire(now)
            e = self.evidence[key]
            health = e["health"] if 0 <= now - e["health_at"] <= 90 else None
            identity = e["identity"] if e["identity"] is False or 0 <= now - e["identity_at"] <= 900 else None
            return MqttObservation(self.connected, self.epochs[key], health, e["sequence"],
                                   identity, tuple(e["radio"]))

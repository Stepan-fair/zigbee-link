"""Read-only discovery connection. Its data never enters live recovery evidence."""
from copy import deepcopy
import threading
import time
from urllib.parse import urlsplit
import uuid
from ..recovery.settings import IEEE, IDENTIFIER, _mqtt
from .model import BridgeMetadata
from .supervisor import serial_endpoint
from .validation import decode_metadata, valid_topic


class MetadataCollector:
    def __init__(self, connection, client=None, clock=time.monotonic):
        if client is None:
            import paho.mqtt.client as mqtt
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                 client_id="zigbee-link-discovery-" + uuid.uuid4().hex, clean_session=True)
        self.connection, self.client, self.clock = connection, client, clock
        self.lock = threading.RLock()
        self.active = self.closing = False
        self.cleanup_done = threading.Event()
        self.cleanup_ok = False
        self.deadline = 0
        self.bridges, self.devices, self.issues = {}, {}, set()
        self.messages = self.bytes = 0
        self.topics = ()
        settings = connection.settings
        client.username_pw_set(settings.username or None, settings.password or None)
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.max_queued_messages_set(256)
        client.max_inflight_messages_set(4)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_subscribe = self._on_subscribe
        client.on_message = self._on_message
        if urlsplit(settings.server).scheme == "mqtts":
            client.tls_set()

    def start(self, known_topics, *, discover_unknown, deadline=None):
        if any(not valid_topic(t) for t in known_topics):
            raise ValueError("invalid_topic")
        with self.lock:
            if self.closing:
                raise ValueError("collector_closed")
            self.active = True
            self.deadline = min(self.clock() + 30, deadline) if deadline is not None else self.clock() + 30
            self.topics = tuple(dict.fromkeys(("#",) if discover_unknown else
                                tuple(t + "/bridge/" + s for t in known_topics for s in ("info", "devices"))))
        parsed = urlsplit(self.connection.settings.server)
        self.client.connect_async(parsed.hostname, parsed.port or (8883 if parsed.scheme == "mqtts" else 1883), keepalive=30)
        self.client.loop_start()

    def _end_window(self):
        self.active = False
        for topic in self.topics:
            try:
                self.client.unsubscribe(topic)
            except Exception:
                self.issues.add("mqtt_unsubscribe_failed")

    def _on_connect(self, client, userdata, flags, reason, properties):
        with self.lock:
            if reason == 0 and self.active and self.clock() < self.deadline:
                if self.topics:
                    client.subscribe([(topic, 1) for topic in self.topics])
            elif self.active:
                self.issues.add("mqtt_unavailable")
                self._end_window()

    def _on_disconnect(self, *args):
        with self.lock:
            if self.active:
                self.issues.add("mqtt_unavailable")
                self._end_window()

    def _on_subscribe(self, client, userdata, mid, codes, properties):
        if any(getattr(code, "is_failure", False) or getattr(code, "value", code) >= 128 for code in codes):
            with self.lock:
                self.issues.add("mqtt_acl_denied")
                self._end_window()

    def _on_message(self, client, userdata, message):
        self.receive(message.topic, message.payload, message.retain, self.clock())

    def receive(self, topic, payload, retained, now):
        with self.lock:
            if not self.active:
                return
            if now >= self.deadline:
                self._end_window()
                return
            self.messages += 1
            if self.messages > 10000:
                self.issues.add("scan_limit")
                self._end_window()
                return
            suffix = next((s for s in ("/bridge/info", "/bridge/devices") if isinstance(topic, str) and topic.endswith(s)), None)
            if suffix is None:
                return
            base = topic[:-len(suffix)]
            if not valid_topic(base):
                return
            if len(payload) > 1048576:
                self.issues.add("metadata_size")
                return
            self.bytes += len(payload)
            if self.bytes > 8 * 1048576:
                self.issues.add("scan_limit")
                self._end_window()
                return
            try:
                raw = decode_metadata(payload)
                if suffix.endswith("info"):
                    self._bridge(base, raw, retained)
                else:
                    self._devices(base, raw)
            except (ValueError, TypeError, KeyError, AttributeError):
                self.issues.add("metadata_invalid")

    def _bridge(self, base, raw, retained):
        ieee = raw["coordinator"]["ieee_address"]
        if not isinstance(ieee, str) or not IEEE.fullmatch(ieee):
            raise ValueError("invalid_ieee")
        config = raw.get("config", {})
        serial = config.get("serial", {}) if isinstance(config, dict) else {}
        ip, port = serial_endpoint(serial.get("port")) if isinstance(serial, dict) else (None, None)
        mqtt = raw.get("mqtt", {})
        server = mqtt.get("server") if isinstance(mqtt, dict) else None
        if server is None and isinstance(config, dict) and isinstance(config.get("mqtt"), dict):
            server = config["mqtt"].get("server")
        if server:
            server = _mqtt({"server": server}).server
        else:
            server = None
        bridge = BridgeMetadata(base, ip, port, ieee.lower(), server, bool(retained), time.time())
        key = (base, bridge.ip, bridge.port, bridge.coordinator_ieee)
        if key not in self.bridges and len(self.bridges) >= 253:
            self.issues.add("scan_limit")
            self._end_window()
            return
        self.bridges[key] = bridge

    def _devices(self, base, raw):
        if not isinstance(raw, list):
            raise ValueError("devices_invalid")
        if len(raw) > 4096:
            self.issues.add("devices_limit")
            return
        if base not in self.devices and len(self.devices) >= 253:
            self.issues.add("scan_limit")
            self._end_window()
            return
        devices = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            selected = {k: item[k][:80] for k in ("ieee_address", "type", "power_source", "interview_state")
                        if isinstance(item.get(k), str)}
            selected.update({k: item[k] for k in ("disabled", "interview_completed", "interviewing")
                             if type(item.get(k)) is bool})
            friendly_name = item.get("friendly_name")
            if isinstance(friendly_name, str):
                selected["friendly_name"] = friendly_name[:100]
            endpoints = item.get("endpoints", {})
            selected["endpoints"] = {}
            if isinstance(endpoints, dict):
                for key, endpoint in endpoints.items():
                    if not str(key).isdigit() or not 1 <= int(key) <= 240 or not isinstance(endpoint, dict):
                        continue
                    clusters = endpoint.get("clusters", {})
                    inputs = clusters.get("input", []) if isinstance(clusters, dict) else []
                    inputs = [c for c in inputs[:256] if isinstance(c, str) and IDENTIFIER.fullmatch(c)] if isinstance(inputs, list) else []
                    reportings = endpoint.get("configured_reportings", [])
                    configs = []
                    for reporting in reportings[:256] if isinstance(reportings, list) else ():
                        if not isinstance(reporting, dict):
                            continue
                        cluster, attribute = reporting.get("cluster"), reporting.get("attribute")
                        if (isinstance(cluster, str) and IDENTIFIER.fullmatch(cluster) and
                            (isinstance(attribute, str) and IDENTIFIER.fullmatch(attribute) or
                             type(attribute) is int and 0 <= attribute <= 65535)):
                            configs.append({"cluster": cluster, "attribute": attribute})
                    selected["endpoints"][str(key)] = {"clusters": {"input": inputs}, "configured_reportings": configs}
            devices.append(selected)
        self.devices[base] = tuple(devices)

    def snapshot(self):
        with self.lock:
            return tuple(self.bridges.values()), deepcopy(self.devices), tuple(sorted(self.issues))

    def tick(self, now):
        with self.lock:
            if self.active and now >= self.deadline:
                self._end_window()

    def close(self):
        with self.lock:
            if self.closing:
                return
            self.closing = True
            self._end_window()
        def cleanup():
            try:
                self.client.disconnect()
                self.client.loop_stop()
                self.cleanup_ok = True
            except Exception:
                pass
            finally:
                self.cleanup_done.set()
        threading.Thread(target=cleanup, name="zigbee-discovery-close", daemon=True).start()
        self.cleanup_done.wait(.25)

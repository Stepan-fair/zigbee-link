import json
import threading
from types import SimpleNamespace
from app.setup.model import BrokerConnection
from app.recovery.settings import MqttSettings
from test_setup_matching import BROKER


class FakePaho:
    def __init__(self):
        self.subscriptions = []
        self.unsubscribed = []
        self.ready = False
        self.block_cleanup = None
    def username_pw_set(self, *args): pass
    def reconnect_delay_set(self, **kwargs): pass
    def max_queued_messages_set(self, *args): pass
    def max_inflight_messages_set(self, *args): pass
    def tls_set(self, *args, **kwargs): pass
    def connect_async(self, *args, **kwargs): self.endpoint = args
    def loop_start(self):
        self.on_connect(self, None, None, 0, None)
        self.ready = True
    def subscribe(self, topics):
        self.subscriptions.append(topics)
        return 0, 1
    def unsubscribe(self, topic): self.unsubscribed.append(topic)
    def disconnect(self): pass
    def loop_stop(self):
        if self.block_cleanup:
            self.block_cleanup.wait(2)
    def publish(self, *args, **kwargs): raise AssertionError("discovery must never publish")
    def emit(self, topic, payload, retained=True):
        self.on_message(self, None, SimpleNamespace(topic=topic, payload=payload, retain=retained))


def bridge_payload(ip="172.31.254.2", ieee="0x0000000000000001"):
    return json.dumps({"coordinator": {"ieee_address": ieee},
        "mqtt": {"server": "mqtt://core-mosquitto:1883"},
        "config": {"serial": {"port": f"tcp://{ip}:6638"},
                   "mqtt": {"password": "private-payload-marker"}}}).encode()


def collector(clock=lambda: 0):
    from app.setup.mqtt import MetadataCollector
    client = FakePaho()
    connection = BrokerConnection(BROKER, MqttSettings(BROKER.server, "service", "secret"))
    return MetadataCollector(connection, client=client, clock=clock), client


def test_nested_topics_retained_and_unrelated_messages():
    item, client = collector()
    item.start((), discover_unknown=True)
    client.emit("unrelated/private", b'not even json')
    client.emit("floor/a/bridge/info", bridge_payload())
    bridges, devices, issues = item.snapshot()
    assert [(b.base_topic, b.ip, b.port, b.retained) for b in bridges] == [("floor/a", "172.31.254.2", 6638, True)]
    assert not issues and not devices
    assert "private-payload-marker" not in repr(item.snapshot())
    item.close()


def test_discovery_client_never_publishes_and_removes_wildcard_at_deadline():
    now = [0]
    item, client = collector(lambda: now[0])
    item.start(("floor/a",), discover_unknown=True)
    client.emit("floor/a/bridge/info", bridge_payload())
    now[0] = 30
    item.tick(now[0])
    assert "#" in client.unsubscribed
    client.emit("floor/b/bridge/info", bridge_payload("172.31.254.3"))
    assert len(item.snapshot()[0]) == 1
    item.close()


def test_acl_failure_stops_unknown_discovery():
    item, client = collector()
    item.start((), discover_unknown=True)
    client.on_subscribe(client, None, 1, [SimpleNamespace(value=128, is_failure=True)], None)
    assert "mqtt_acl_denied" in item.snapshot()[2]
    assert "#" in client.unsubscribed
    item.close()


def test_metadata_limits_do_not_retain_unbounded_devices_or_candidates():
    item, client = collector()
    item.start((), discover_unknown=True)
    client.emit("a/bridge/devices", json.dumps([{}] * 4097).encode())
    assert "devices_limit" in item.snapshot()[2]
    client.emit("a/bridge/info", b' ' * 1048577)
    assert "metadata_size" in item.snapshot()[2]
    for n in range(254):
        client.emit(f"n{n}/bridge/info", bridge_payload())
    assert len(item.snapshot()[0]) <= 253
    assert "scan_limit" in item.snapshot()[2]
    item.close()


def test_raw_payload_budget_and_unrelated_flood_end_window():
    item, client = collector()
    item.start((), discover_unknown=True)
    payload = b'{"ignored":"' + b'a' * 600000 + b'"}'
    for _ in range(15):
        client.emit("a/bridge/info", payload)
    assert "scan_limit" in item.snapshot()[2]
    item.close()
    item, client = collector()
    item.start((), discover_unknown=True)
    for _ in range(10001):
        client.emit("unrelated", b'')
    assert "scan_limit" in item.snapshot()[2]
    item.close()


def test_blocked_mqtt_cleanup_is_bounded_and_does_not_spawn_repeated_closers():
    import time
    item, client = collector()
    client.block_cleanup = threading.Event()
    item.start((), discover_unknown=True)
    started = time.monotonic()
    item.close()
    item.close()
    assert time.monotonic() - started < 1
    assert not item.cleanup_done.is_set()
    client.block_cleanup.set()
    assert item.cleanup_done.wait(1)


def test_device_projection_drops_unknown_nested_credentials():
    item, client = collector()
    item.start((), discover_unknown=True)
    raw = [{"ieee_address": "0x0000000000000001", "type": "Router", "power_source": "Mains (single phase)",
            "secret": "private-device-marker", "disabled": {"password": "private-device-marker"},
            "endpoints": {"1": {"clusters": {"input": ["genOnOff"], "password": "private-device-marker"},
                "configured_reportings": [{"cluster": "genOnOff", "attribute": "onOff", "password": "private-device-marker"}]}}}]
    client.emit("a/bridge/devices", json.dumps(raw).encode())
    assert "private-device-marker" not in repr(item.snapshot())
    assert item.snapshot()[1]["a"][0]["endpoints"]["1"]["clusters"]["input"] == ["genOnOff"]
    item.close()

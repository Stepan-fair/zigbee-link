import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import pytest
from app.recovery.supervisor import HttpResult
from app.setup.supervisor import SupervisorCatalogReader
from app.setup.service import DiscoveryService
from app.setup.store import SetupStore
from app.setup.mqtt import MetadataCollector
from test_recovery_runtime import broker, wait_for, free_port
from setup_fixture import SetupFixture

pytestmark = pytest.mark.linux


class Transport:
    def __init__(self, fixture):
        self.origin = "http://127.0.0.1:" + str(fixture.http.server_port)
    def request(self, method, path, body=None, timeout=5):
        headers = {"Authorization": "Bearer fixture-token", "Content-Type": "application/json"}
        req = Request(self.origin + path, method=method, headers=headers,
                      data=json.dumps(body or {}).encode() if method == "POST" else None)
        try:
            with urlopen(req, timeout=timeout) as response:
                return HttpResult(response.status, response.read(1024 * 1024 + 1))
        except HTTPError as exc:
            return HttpResult(exc.code, b"")


def test_real_retained_discovery_two_networks_zero_publish(tmp_path, broker):
    fixture = SetupFixture("127.0.0.1", broker, "127.0.0.1", 0)
    reader = SupervisorCatalogReader(Transport(fixture))
    store = SetupStore(tmp_path / "setup.sqlite")
    now = [time.monotonic()]
    discovery = DiscoveryService(reader, store, MetadataCollector, clock=lambda: now[0])
    try:
        wait_for(fixture.client.is_connected)
        fixture.publish_metadata()
        assert discovery.request_scan()
        def complete():
            discovery.tick()
            return discovery.collector is not None and len(discovery.collector.bridges) == 2
        wait_for(complete)
        assert all(bridge.retained for bridge in discovery.collector.snapshot()[0])
        now[0] += 31
        discovery.tick()
        catalog = store.catalog()
        assert len(catalog.candidates) == 2 and all(c.match_kind == "matched" for c in catalog.candidates)
        assert not catalog.candidates[0].fields["references"].value
        assert len(catalog.candidates[1].fields["references"].value) == 1
        assert not fixture.commands and not fixture.all_requests
        assert "fixture-service-secret" not in repr(catalog)
    finally:
        discovery.close()
        fixture.close()
        store.close()


def test_real_supervisor_mode_body_is_preserved_and_verified(broker):
    from app.setup.supervisor import options_digest
    fixture = SetupFixture("127.0.0.1", broker, "127.0.0.1", 0)
    reader = SupervisorCatalogReader(Transport(fixture))
    try:
        previous = reader.self_options()
        assert reader.set_mode("guided", expected_digest=options_digest(previous))
        assert fixture.options == {**previous, "configuration_mode": "guided"}
        assert not fixture.commands
    finally:
        fixture.close()


def test_real_broker_acl_excludes_other_network_metadata(tmp_path):
    import subprocess
    import paho.mqtt.client as paho
    from app.setup.model import BrokerRecord, BrokerConnection
    from app.recovery.settings import MqttSettings
    port = free_port()
    passwords = tmp_path / "passwords"
    subprocess.run(["mosquitto_passwd", "-b", "-c", str(passwords), "publisher", "fixture-producer"], check=True, capture_output=True)
    subprocess.run(["mosquitto_passwd", "-b", str(passwords), "metadata", "fixture-reader"], check=True, capture_output=True)
    acl = tmp_path / "acl"
    acl.write_text("user publisher\ntopic write #\nuser metadata\ntopic read z2m/a/bridge/#\n")
    configuration = tmp_path / "restricted.conf"
    configuration.write_text(f"listener {port} 127.0.0.1\nallow_anonymous false\npassword_file {passwords}\nacl_file {acl}\npersistence false\nuser root\n")
    process = subprocess.Popen(["mosquitto", "-c", str(configuration)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    publisher = paho.Client(paho.CallbackAPIVersion.VERSION2)
    collector = None
    try:
        import socket
        def ready():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return True
            except OSError:
                return False
        wait_for(ready)
        publisher.username_pw_set("publisher", "fixture-producer")
        publisher.connect("127.0.0.1", port)
        publisher.loop_start()
        for suffix in ("a", "b"):
            payload = json.dumps({"coordinator": {"ieee_address": "0x0000000000000001"}, "config": {"serial": {"port": "tcp://172.31.254.2:6638"}}})
            publisher.publish(f"z2m/{suffix}/bridge/info", payload, qos=1, retain=True).wait_for_publish(timeout=2)
        settings = MqttSettings(f"mqtt://127.0.0.1:{port}", "metadata", "fixture-reader")
        client = paho.Client(paho.CallbackAPIVersion.VERSION2)
        client.publish = lambda *args, **kwargs: pytest.fail("Passive discovery published a command")
        collector = MetadataCollector(BrokerConnection(BrokerRecord("test", "manual", settings.server), settings), client=client)
        collector.start(("z2m/a", "z2m/b"), discover_unknown=True)
        wait_for(lambda: len(collector.bridges) == 1)
        time.sleep(.15)
        assert [bridge.base_topic for bridge in collector.snapshot()[0]] == ["z2m/a"]
    finally:
        if collector:
            collector.close()
        publisher.disconnect()
        publisher.loop_stop()
        process.terminate()
        process.wait(timeout=5)

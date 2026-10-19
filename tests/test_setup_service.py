import time
import threading
from app.setup.model import BrokerConnection
from app.recovery.settings import MqttSettings
from app.setup.store import SetupStore
from app.setup.supervisor import SupervisorCatalogReader
from test_setup_supervisor import SupervisorFixture
from test_setup_mqtt import FakePaho, bridge_payload


def spin_until(check, tick, seconds=1):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        tick()
        if check(): return
        time.sleep(.005)
    assert check()


def test_two_discovered_networks_publish_catalog_without_recovery_commands(tmp_path):
    from app.setup.service import DiscoveryService
    from app.setup.mqtt import MetadataCollector
    now, clients = [0], []
    fixture = SupervisorFixture()
    with SetupStore(tmp_path / "setup.sqlite") as store:
        def factory(connection):
            client = FakePaho()
            clients.append(client)
            return MetadataCollector(connection, client=client, clock=lambda: now[0])
        service = DiscoveryService(SupervisorCatalogReader(fixture), store, factory, clock=lambda: now[0])
        try:
            assert service.request_scan()
            spin_until(lambda: bool(clients and clients[0].ready), service.tick)
            clients[0].emit("floor/a/bridge/info", bridge_payload())
            clients[0].emit("floor/b/bridge/info", bridge_payload("172.31.254.3", "0x0000000000000002"))
            now[0] = 30
            spin_until(lambda: store.catalog().revision > 0, service.tick)
            assert len(store.catalog().candidates) == 2
            assert all(c.match_kind == "verified" for c in store.catalog().candidates)
            assert store.snapshot().networks == () and not store.snapshot().enabled
            assert not service.request_scan()
            assert all(method == "GET" for method, _, _ in fixture.calls)
            now[0] = 60
            assert service.request_scan()
        finally:
            service.close()


def test_flood_and_slow_reader_do_not_block_runtime(tmp_path):
    from app.setup.service import DiscoveryService
    release = threading.Event()
    class Reader:
        issues = ()
        def begin_scan(self, deadline): pass
        def cancel_scan(self): release.set()
        def apps(self):
            release.wait(1)
            return ()
        def mqtt_service(self, **kwargs): return None
    now = [0]
    with SetupStore(tmp_path / "setup.sqlite") as store:
        service = DiscoveryService(Reader(), store, lambda _: None, clock=lambda: now[0])
        try:
            assert service.request_scan()
            start = time.monotonic()
            service.tick()
            assert time.monotonic() - start < .1
            now[0] = 31
            service.tick()
            assert release.wait(.2)
        finally:
            service.close()


def test_conflicting_discovery_does_not_hide_second_network(tmp_path):
    from app.setup.service import DiscoveryService
    from app.setup.mqtt import MetadataCollector
    now, clients = [0], []
    with SetupStore(tmp_path / "setup.sqlite") as store:
        def factory(connection):
            client = FakePaho(); clients.append(client)
            return MetadataCollector(connection, client=client, clock=lambda: now[0])
        service = DiscoveryService(SupervisorCatalogReader(SupervisorFixture()), store, factory, clock=lambda: now[0])
        try:
            service.request_scan()
            spin_until(lambda: bool(clients and clients[0].ready), service.tick)
            for ip, ieee, topic in (("172.31.254.2", "0x0000000000000001", "floor/a"),
                                    ("172.31.254.2", "0x0000000000000003", "floor/a"),
                                    ("172.31.254.3", "0x0000000000000002", "floor/b")):
                clients[0].emit(topic + "/bridge/info", bridge_payload(ip, ieee))
            now[0] = 30
            spin_until(lambda: store.catalog().revision > 0, service.tick)
            rows = store.catalog().candidates
            assert any(r.fields["ip"].value == "172.31.254.3" and r.match_kind == "verified" for r in rows)
            assert all(r.match_kind == "conflict" for r in rows if r.fields["ip"].value == "172.31.254.2")
        finally:
            service.close()


def test_missing_mqtt_still_shows_installed_apps_as_proposals(tmp_path):
    from app.setup.service import DiscoveryService
    from app.recovery.supervisor import HttpResult
    fixture = SupervisorFixture()
    original = fixture.request
    fixture.request = lambda method, path, body=None, timeout=5: HttpResult(404, b'') if path == '/services/mqtt' else original(method, path, body, timeout)
    with SetupStore(tmp_path / "setup.sqlite") as store:
        service = DiscoveryService(SupervisorCatalogReader(fixture), store, lambda _: None)
        try:
            service.request_scan()
            spin_until(lambda: store.catalog().revision > 0, service.tick)
            assert {c.fields['addon_slug'].value for c in store.catalog().candidates} == {'a_zigbee2mqtt', 'b_zigbee2mqtt'}
            assert all(c.match_kind == 'proposed' for c in store.catalog().candidates)
            assert 'mqtt_unconfigured' in store.catalog().issues
        finally:
            service.close()

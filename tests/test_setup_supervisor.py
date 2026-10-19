from copy import deepcopy
import io
import json
from types import SimpleNamespace
import pytest
from app.recovery.supervisor import HttpResult


class SupervisorFixture:
    def __init__(self):
        self.calls = []
        self.options = {"parent": "auto", "address": "172.31.254.1/24", "recovery": {"enabled": False}}
        self.bad = False

    def request(self, method, path, body=None, timeout=5):
        self.calls.append((method, path, deepcopy(body)))
        if self.bad:
            return HttpResult(503, b"")
        if path == "/addons":
            data = {"addons": [{"slug": s, "repository": "repo"} for s in ("a_zigbee2mqtt", "b_zigbee2mqtt", "core_mosquitto")]}
        elif path == "/supervisor/info":
            data = {"version": "2026.10.2"}
        elif path == "/addons/self/options" and method == "POST":
            self.options = deepcopy(body["options"])
            data = {}
        elif path == "/addons/self/info":
            data = {"options": self.options, "ingress_port": 63001}
        elif path == "/services/mqtt":
            data = {"addon": "core_mosquitto", "host": "172.30.33.2", "port": 1883,
                    "ssl": False, "username": "service-user", "password": "private-service-marker"}
        elif path == "/addons/core_mosquitto/info":
            data = {"slug": "core_mosquitto", "hostname": "core-mosquitto", "ip_address": "172.30.33.2"}
        else:
            slug = path.split("/")[2]
            suffix = "2" if slug.startswith("a_") else "3"
            data = {"slug": slug, "name": "Zigbee2MQTT", "repository": "repo", "version": "2.14.2-1",
                    "state": "started", "options": {"serial": {"port": f"tcp://172.31.254.{suffix}:6638", "adapter": "ember"}, "mqtt": {}}}
        return HttpResult(200, json.dumps({"result": "ok", "data": data}).encode())


def test_reads_two_supported_apps_and_ignores_unrelated():
    from app.setup.supervisor import SupervisorCatalogReader
    fixture = SupervisorFixture()
    apps = SupervisorCatalogReader(fixture).apps()
    assert [(a.slug, a.serial_ip, a.serial_port) for a in apps] == [
        ("a_zigbee2mqtt", "172.31.254.2", 6638), ("b_zigbee2mqtt", "172.31.254.3", 6638)]
    assert apps[0].base_topic is None
    assert all(call[0] == "GET" for call in fixture.calls)


def test_missing_service_and_empty_addon_options_are_distinct():
    from app.setup.supervisor import SupervisorCatalogReader, DiscoverySourceError
    fixture = SupervisorFixture()
    original = fixture.request
    fixture.request = lambda method, path, body=None, timeout=5: HttpResult(404, b"") if path == "/services/mqtt" else original(method, path, body, timeout)
    reader = SupervisorCatalogReader(fixture)
    assert reader.mqtt_service() is None
    assert reader.apps()[0].base_topic is None
    fixture.bad = True
    with pytest.raises(DiscoverySourceError):
        reader.apps()


def test_never_sends_service_credentials_to_payload_broker():
    from app.setup.supervisor import SupervisorCatalogReader
    fixture = SupervisorFixture()
    connection = SupervisorCatalogReader(fixture).mqtt_service()
    assert connection.settings.server == "mqtt://172.30.33.2:1883"
    assert connection.settings.password == "private-service-marker"
    assert "core-mosquitto" in connection.record.aliases
    assert "private-service-marker" not in repr(connection)
    assert all("attacker" not in c[1] for c in fixture.calls)
    assert "private-service-marker" not in json.dumps(connection.record.__dict__)


def test_own_options_update_preserves_network_settings():
    from app.setup.supervisor import SupervisorCatalogReader, options_digest
    fixture = SupervisorFixture()
    reader = SupervisorCatalogReader(fixture)
    digest = options_digest(reader.self_options())
    assert reader.set_mode("guided", expected_digest=digest)
    assert fixture.options == {"parent": "auto", "address": "172.31.254.1/24", "configuration_mode": "guided", "recovery": {"enabled": False}}
    before = len([c for c in fixture.calls if c[0] == "POST"])
    assert not reader.set_mode("legacy", expected_digest=digest)
    assert len([c for c in fixture.calls if c[0] == "POST"]) == before
    assert all(c[1] == "/addons/self/options" for c in fixture.calls if c[0] == "POST")


@pytest.mark.parametrize("version,allowed", [("2026.10.0", False), ("2026.10.2.dev0", False),
    ("unknown", False), ("2026.10.2", True), ("2026.11.0", True)])
def test_admin_enforcement_requires_released_supervisor(version, allowed):
    from app.setup.supervisor import supports_admin_ingress, SupervisorCatalogReader
    assert supports_admin_ingress(version) is allowed
    assert SupervisorCatalogReader(SupervisorFixture()).capabilities().ingress_port == 63001


def test_http_worker_transmits_own_options_body(monkeypatch):
    import app.recovery.supervisor as module
    request_body = {"options": {"configuration_mode": "guided"}}
    seen = []
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, count): return b'{"result":"ok"}'
    def open_request(req, timeout):
        seen.append(json.loads(req.data))
        return Response()
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(
            {"method": "POST", "path": "/addons/self/options", "token": "fixture", "body": request_body}).encode())))
        patch.setattr(module.sys, "stdout", SimpleNamespace(buffer=io.BytesIO()))
        patch.setattr(module.request, "build_opener", lambda *args: SimpleNamespace(open=open_request))
        code = module._http_worker()
    assert code == 0
    assert seen == [request_body]


def test_http_owner_forwards_body_to_deadline_worker():
    from app.recovery.supervisor import HttpTransport
    class Process:
        returncode = 0
        payload = None
        def communicate(self, value=None, timeout=1):
            if value is not None:
                self.payload = json.loads(value)
            return b'200\n{"result":"ok"}', b''
        def poll(self): return 0
    process = Process()
    transport = HttpTransport("fixture", process_factory=lambda *a, **k: process)
    body = {"options": {"configuration_mode": "guided"}}
    assert transport.request("POST", "/addons/self/options", body=body).status == 200
    assert process.payload.get("body") == body


@pytest.mark.parametrize("response", [HttpResult(302, b""), HttpResult(200, b'not-json'),
    HttpResult(200, b' ' * 1048577)], ids=["redirect", "invalid-json", "oversized"])
def test_source_failures_are_not_valid_empty_catalog(response):
    from app.setup.supervisor import SupervisorCatalogReader, DiscoverySourceError
    reader = SupervisorCatalogReader(SimpleNamespace(request=lambda *a, **k: response))
    with pytest.raises(DiscoverySourceError):
        reader.apps()


def test_conflicting_repository_is_rejected_without_hiding_neighbor():
    from app.setup.supervisor import SupervisorCatalogReader
    fixture = SupervisorFixture()
    original = fixture.request
    def changed(method, path, body=None, timeout=5):
        response = original(method, path, body, timeout)
        if path == "/addons/a_zigbee2mqtt/info":
            data = json.loads(response.body)
            data["data"]["repository"] = "different"
            return HttpResult(200, json.dumps(data).encode())
        return response
    fixture.request = changed
    reader = SupervisorCatalogReader(fixture)
    assert [a.slug for a in reader.apps()] == ["b_zigbee2mqtt"]
    assert reader.issues == ("addon_unsupported",)

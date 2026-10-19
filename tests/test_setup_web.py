import asyncio
from dataclasses import replace
import json
import socket
import time
from aiohttp.test_utils import TestClient, TestServer
import pytest
from test_setup_runtime import controller, accept_one


async def client_for(ctl, *, ingress=True):
    from app.web.server import create_app
    from app.web.security import IngressSecurity
    class TestIngress(IngressSecurity):
        def check_peer(self, peer_ip, user_id, capabilities):
            return super().check_peer("172.30.32.2" if peer_ip == "127.0.0.1" else peer_ip, user_id, capabilities)
    security = TestIngress() if ingress else IngressSecurity()
    ctl.capabilities = ctl.reader.capabilities()
    client = TestClient(TestServer(create_app(ctl, security)))
    await client.start_server()
    return client


def test_http_rejects_direct_lan_and_forwarded_peer_spoof(tmp_path):
    async def run():
        ctl, _, _ = controller(tmp_path)
        async with await client_for(ctl, ingress=False) as client:
            for extra in ({}, {"X-Forwarded-For": "172.30.32.2", "Forwarded": "for=172.30.32.2"}):
                response = await client.get("/api/session", headers={"X-Remote-User-Id": "admin-id", **extra})
                assert response.status == 403
        ctl.close()
    asyncio.run(run())


def test_non_admin_capability_version_cannot_mutate(tmp_path):
    async def run():
        ctl, _, _ = controller(tmp_path)
        async with await client_for(ctl) as client:
            ctl.capabilities = replace(ctl.capabilities, version="2026.10.0", web_write_allowed=False)
            response = await client.post("/api/networks/control", json={"enabled": True, "expected_revision": 0}, headers={"X-Remote-User-Id": "admin-id"})
            assert response.status == 403
            assert (await client.get("/", headers={"X-Remote-User-Id": "admin-id"})).status == 200
        ctl.close()
    asyncio.run(run())


def test_stale_revision_409_and_no_pause_loss(tmp_path):
    async def run():
        ctl, _, _ = controller(tmp_path)
        snapshot, record = accept_one(ctl)
        async with await client_for(ctl) as client:
            headers = {"X-Remote-User-Id": "admin-id"}
            session = await (await client.get("/api/session", headers=headers)).json()
            headers["X-CSRF-Token"] = session["csrf_token"]
            response = await client.post("/api/networks/control", json={"network_id": record.network_id, "paused": True, "expected_revision": snapshot.revision}, headers=headers)
            result = await response.json()
            assert response.status == 200 and result["state"]["revision"] == snapshot.revision + 1
            response = await client.post("/api/networks/control", json={"network_id": record.network_id, "paused": False, "expected_revision": snapshot.revision}, headers=headers)
            assert response.status == 409 and ctl.store.snapshot().networks[0].paused
        ctl.close()
    asyncio.run(run())


def test_secrets_absent_from_every_response_and_logs(tmp_path, caplog):
    async def run():
        ctl, _, _ = controller(tmp_path)
        async with await client_for(ctl) as client:
            headers = {"X-Remote-User-Id": "admin-id"}
            session = await (await client.get("/api/session", headers=headers)).json()
            headers["X-CSRF-Token"] = session["csrf_token"]
            response = await client.post("/api/broker", json={"mode": "manual", "server": "mqtt://broker.invalid", "username": "private-user-marker", "password": "private-pass-marker", "expected_revision": 0}, headers=headers)
            assert response.status == 200
            contents = await response.text()
            for path in ("/api/state", "/api/diagnostics", "/api/session"):
                response = await client.get(path, headers=headers)
                assert response.status == 200 and response.headers["Cache-Control"] == "no-store"
                contents += await response.text()
            assert all(marker not in contents + caplog.text for marker in ("private-user-marker", "private-pass-marker", "source_digest", "secret_ref"))
        ctl.close()
    asyncio.run(run())


def test_invalid_requests_csrf_body_size_types_and_routes(tmp_path):
    async def run():
        ctl, _, _ = controller(tmp_path)
        async with await client_for(ctl) as client:
            user = {"X-Remote-User-Id": "admin-id"}
            token = (await (await client.get("/api/session", headers=user)).json())["csrf_token"]
            headers = {**user, "X-CSRF-Token": token}
            assert (await client.post("/api/networks/control", json={"expected_revision": 0, "enabled": True}, headers=user)).status == 403
            assert (await client.get("/api/state")).status == 403
            before = ctl.store.snapshot()
            assert (await client.get("/api/state", headers=headers)).status == 200
            assert ctl.store.snapshot() == before
            payloads = [({"expected_revision": True, "enabled": True}, 400),
                        ({"expected_revision": 0, "enabled": "true"}, 400),
                        ({"expected_revision": 0, "enabled": True, "unknown": 1}, 400),
                        ({"expected_revision": 0, "network_id": "foreign", "paused": True}, 400)]
            for payload, code in payloads:
                assert (await client.post("/api/networks/control", json=payload, headers=headers)).status == code
            assert (await client.post("/api/broker", data='{"server":NaN}', headers={**headers, "Content-Type": "application/json"})).status == 400
            assert (await client.post("/api/broker", data="{}", headers=headers)).status == 415
            assert (await client.post("/api/broker", data=b"x" * 65537, headers={**headers, "Content-Type": "application/json"})).status == 413
            assert (await client.get("/static/%2e%2e%2fconfig.yaml", headers=headers)).status == 404
        ctl.close()
    asyncio.run(run())


def test_slow_body_does_not_prevent_server_shutdown(tmp_path):
    from app.web.server import IngressServer
    from app.web.security import IngressSecurity
    ctl, _, _ = controller(tmp_path)
    ctl.capabilities = ctl.reader.capabilities()
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    class TestIngress(IngressSecurity):
        def check_peer(self, peer_ip, user_id, capabilities):
            return super().check_peer("172.30.32.2" if peer_ip == "127.0.0.1" else peer_ip, user_id, capabilities)
    security = TestIngress()
    server = IngressServer(ctl, port, security)
    server.start()
    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
    token = security.issue_csrf("admin-id")
    connection.sendall(("POST /api/broker HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: admin-id\r\nX-CSRF-Token: " + token + "\r\nContent-Type: application/json\r\nContent-Length: 64000\r\n\r\n{").encode())
    started = time.monotonic()
    server.close()
    assert time.monotonic() - started < 5
    connection.close()
    ctl.close()


def test_real_http_rate_and_sixteen_handler_limits(tmp_path):
    async def run():
        ctl, _, _ = controller(tmp_path)
        ctl.request_scan = lambda: False
        async with await client_for(ctl) as client:
            user = {"X-Remote-User-Id": "admin-id"}
            token = (await (await client.get("/api/session", headers=user)).json())["csrf_token"]
            headers = {**user, "X-CSRF-Token": token}
            for _ in range(30):
                assert (await client.post("/api/discovery/start", json={"expected_revision": 0}, headers=headers)).status == 200
            assert (await client.post("/api/discovery/start", json={"expected_revision": 0}, headers=headers)).status == 429
            other = {"X-Remote-User-Id": "second-admin"}
            token = (await (await client.get("/api/session", headers=other)).json())["csrf_token"]
            writers = []
            try:
                for _ in range(16):
                    reader, writer = await asyncio.open_connection(client.server.host, client.server.port)
                    writer.write(("POST /api/broker HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: second-admin\r\nX-CSRF-Token: " + token + "\r\nContent-Type: application/json\r\nContent-Length: 64000\r\n\r\n{").encode())
                    await writer.drain()
                    writers.append(writer)
                await asyncio.sleep(.05)
                assert (await client.get("/api/state", headers=other)).status == 429
            finally:
                for writer in writers:
                    writer.close()
                await asyncio.gather(*(writer.wait_closed() for writer in writers))
        ctl.close()
    asyncio.run(run())

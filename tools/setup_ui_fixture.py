"""Loopback-only synthetic browser QA, never loaded by the add-on runtime."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import threading
from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "zigbee_link"))
from app.config import parse_settings
from app.recovery.supervisor import HttpResult
from app.setup.model import Candidate, Catalog, FieldValue
from app.setup.runtime import SetupController
from app.setup.supervisor import SupervisorCatalogReader
from app.web.security import IngressSecurity
from app.web.server import create_app


class SyntheticSupervisor:
    def __init__(self):
        self.options = {"configuration_mode": "guided", "address": "172.31.254.1/24", "recovery": {"enabled": False}}

    def request(self, method, path, body=None, timeout=5):
        if path == "/addons/self/options" and method == "POST":
            self.options = body["options"]
            data = {}
        elif path == "/addons/self/info":
            data = {"options": self.options, "ingress_port": 63001}
        elif path == "/supervisor/info":
            data = {"version": "2026.10.2"}
        else:
            return HttpResult(404, b"")
        return HttpResult(200, json.dumps({"result": "ok", "data": data}).encode())


def sample(suffix, name, *, incomplete=False):
    values = dict(name=name, ip=f"172.31.254.{suffix}", serial_port=6638, addon_slug=f"net_{suffix}_zigbee2mqtt",
                  base_topic=f"floor/{suffix}", coordinator_ieee="" if incomplete else "0x" + f"{suffix:016x}", references=[])
    return Candidate(str(suffix), {key: FieldValue("auto", value, "supervisor", 1792400400, "found") for key, value in values.items()},
                     ("identity_incomplete",) if incomplete else (), "proposed" if incomplete else "matched")


def build_controller(data_dir):
    transport = SyntheticSupervisor()
    controller = SetupController(transport.options, parse_settings(transport.options), None, None, data_dir, threading.Event(),
                                 reader=SupervisorCatalogReader(transport))
    controller.capabilities = controller.reader.capabilities()
    snapshot = controller.edit_broker({"mode": "manual", "server": "mqtt://broker.invalid", "username": "fixture-user", "password": "fixture-password"}, expected_revision=0)
    catalog = controller.store.save_catalog(Catalog(candidates=(sample(2, "Первый этаж"), sample(3, "Мастерская"), sample(9, "Нужна проверка", incomplete=True))), expected_revision=0)
    for candidate in catalog.candidates[:2]:
        snapshot = controller.accept(candidate.candidate_id, catalog_revision=catalog.revision, expected_revision=snapshot.revision)
    snapshot = controller.control(snapshot.networks[0].network_id, managed=True, enabled=True, expected_revision=snapshot.revision)
    controller.network_status = type("Status", (), {"state": "ready", "parent": "eth0"})()
    # Browser scan is deterministic and never opens external MQTT or Supervisor connections.
    def rescan():
        previous = controller.store.catalog()
        controller.store.save_catalog(previous, expected_revision=previous.revision)
        controller._adopt_discovery()
        return True
    controller.request_scan = rescan
    return controller


def fixture_app(controller):
    class LoopbackFixtureSecurity(IngressSecurity):
        def check_peer(self, peer_ip, user_id, capabilities):
            return super().check_peer("172.30.32.2" if peer_ip == "127.0.0.1" else peer_ip, user_id, capabilities)
    denied = [False]
    @web.middleware
    async def synthetic_ingress(request, handler):
        peer = request.transport.get_extra_info("peername")
        if not peer or peer[0] != "127.0.0.1":
            raise web.HTTPForbidden()
        if request.path in ("/fixture", "/fixture/change", "/fixture/deny", "/fixture/allow", "/fixture/narrow"):
            return await request.match_info.handler(request)
        if denied[0] and request.path.startswith("/api/"):
            return web.json_response({"error": "fixture_denied"}, status=403)
        request = request.clone(headers={**request.headers, "X-Remote-User-Id": "synthetic-admin"})
        return await handler(request)
    app = create_app(controller, LoopbackFixtureSecurity())
    app.middlewares.insert(0, synthetic_ingress)
    async def controls(request):
        return web.Response(text='<!doctype html><html lang="ru"><meta charset="utf-8"><title>Проверка Zigbee Link</title><h1>Синтетическая проверка</h1><form method="post" action="./fixture/change"><button>Изменить паузу в другом окне</button></form><form method="post" action="./fixture/deny"><button>Сымитировать отказ API</button></form><form method="post" action="./fixture/allow"><button>Восстановить API</button></form><p><a href="./">Открыть экран Zigbee Link</a></p></html>', content_type="text/html")
    async def narrow(request):
        return web.Response(text='<!doctype html><html lang="ru"><meta charset="utf-8"><title>Узкий экран Zigbee Link</title><h1>Проверка ширины 390 пикселей</h1><iframe title="Zigbee Link 390 пикселей" src="/" width="390" height="844"></iframe></html>', content_type="text/html")
    async def change(request):
        snapshot = controller.store.snapshot()
        record = snapshot.networks[0]
        controller.control(record.network_id, paused=not record.paused, expected_revision=snapshot.revision)
        raise web.HTTPSeeOther("/fixture")
    async def deny(request):
        denied[0] = True
        raise web.HTTPSeeOther("/fixture")
    async def allow(request):
        denied[0] = False
        raise web.HTTPSeeOther("/fixture")
    app.router.add_get("/fixture", controls)
    app.router.add_get("/fixture/narrow", narrow)
    app.router.add_post("/fixture/change", change)
    app.router.add_post("/fixture/deny", deny)
    app.router.add_post("/fixture/allow", allow)
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="zigbee-link-ui-") as directory:
        controller = build_controller(Path(directory))
        try:
            web.run_app(fixture_app(controller), host="127.0.0.1", port=args.port, access_log=None)
        finally:
            controller.close()

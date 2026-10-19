"""Bounded Ingress HTTP boundary; no arbitrary Supervisor or file endpoints."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
import threading
from aiohttp import web

from ..setup.store import RevisionConflict, SetupStoreError
from ..setup.validation import decode_metadata

STATIC = Path(__file__).with_name("static")
ASSETS = {"index.html": "text/html", "app.js": "application/javascript", "app.css": "text/css"}
LIMITED = "Для защищённого экрана Zigbee Link нужен Supervisor 2026.10.2 или новее. Прежние настройки продолжают работать."
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
           "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}


def _state(controller):
    value = asdict(controller.view())
    transition = controller.store.transition()
    value["transition"] = None if not transition else {key: getattr(transition, key) for key in ("receipt", "phase", "source_mode", "target_mode", "setup_revision")}
    return value


def _change(controller, path, body):
    with controller.lock:
        revision = body.pop("expected_revision", None)
        if type(revision) is not int or revision < 0:
            raise ValueError("invalid_revision")
        if controller.store.snapshot().revision != revision:
            raise RevisionConflict("setup_revision_conflict")
        extra = {}
        if path == "/api/networks/control":
            if set(body) - {"network_id", "managed", "paused", "enabled"}:
                raise ValueError("invalid_keys")
            controller.control(body.pop("network_id", None), expected_revision=revision, **body)
        elif path == "/api/networks/edit":
            if set(body) - {"network_id", "patch", "confirm_identity"} or not isinstance(body.get("network_id"), str):
                raise ValueError("invalid_keys")
            controller.edit(body["network_id"], body.get("patch"), expected_revision=revision, confirm_identity=body.get("confirm_identity", False))
        elif path == "/api/networks/accept":
            if set(body) != {"candidate_id", "catalog_revision"} or not isinstance(body["candidate_id"], str):
                raise ValueError("invalid_keys")
            controller.accept(expected_revision=revision, **body)
        elif path == "/api/broker":
            controller.edit_broker(body, expected_revision=revision)
        elif path == "/api/discovery/start":
            if body:
                raise ValueError("invalid_keys")
            extra["started"] = controller.request_scan()
        elif path == "/api/mode/prepare":
            if set(body) != {"target_mode"}:
                raise ValueError("invalid_keys")
            controller.prepare_transition(body["target_mode"], expected_revision=revision)
        elif path == "/api/mode/commit":
            if set(body) != {"receipt"} or not isinstance(body["receipt"], str):
                raise ValueError("invalid_keys")
            extra["verified"] = controller.commit_transition(body["receipt"])
        else:
            raise ValueError("unknown_route")
        return {"state": _state(controller), **extra}


def create_app(controller, security):
    active = 0
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="zigbee-web")

    @web.middleware
    async def boundary(request, handler):
        nonlocal active
        response = None
        entered = False
        try:
            peer = request.transport.get_extra_info("peername") if request.transport else None
            peer_ip = peer[0] if peer else ""
            user = request.headers.get("X-Remote-User-Id")
            if not security.check_peer(peer_ip, user, controller.capabilities):
                # Old Supervisors receive an explanation, never a working API.
                if request.path == "/" and security.check_peer(peer_ip, user, replace(controller.capabilities, web_write_allowed=True)):
                    response = web.Response(text=LIMITED, content_type="text/plain")
                else:
                    response = web.json_response({"error": "ingress_required"}, status=403)
            elif active >= 16:
                response = web.json_response({"error": "busy"}, status=429)
            else:
                active += 1
                entered = True
                if request.method == "POST":
                    if not security.verify_csrf(user, request.headers.get("X-CSRF-Token")):
                        raise web.HTTPForbidden()
                    if not security.admit_mutation(user):
                        raise web.HTTPTooManyRequests()
                response = await handler(request)
        except RevisionConflict:
            response = web.json_response({"error": "revision_conflict"}, status=409)
        except SetupStoreError:
            response = web.json_response({"error": "storage_unavailable"}, status=503)
        except web.HTTPException as exc:
            response = web.json_response({"error": "request_rejected"}, status=exc.status)
        except asyncio.TimeoutError:
            response = web.json_response({"error": "request_timeout"}, status=408)
        except (ValueError, TypeError, KeyError):
            response = web.json_response({"error": "invalid_request"}, status=400)
        except Exception:
            response = web.json_response({"error": "service_unavailable"}, status=503)
        finally:
            if entered:
                active -= 1
        response.headers.update(HEADERS)
        return response

    app = web.Application(middlewares=[boundary], client_max_size=65536)

    async def call(function, *args):
        return await asyncio.get_running_loop().run_in_executor(executor, function, *args)

    async def state(request):
        return web.json_response(await call(_state, controller))

    async def session(request):
        return web.json_response({"csrf_token": security.issue_csrf(request.headers["X-Remote-User-Id"]),
                                 "state": await call(_state, controller)})

    async def diagnostics(request):
        value = await call(controller.diagnostics)
        return web.json_response(value, headers={"Content-Disposition": 'attachment; filename="zigbee-link-diagnostics.json"'})

    async def mutate(request):
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        raw = await asyncio.wait_for(request.read(), timeout=3)
        body = decode_metadata(raw)
        if not isinstance(body, dict):
            raise ValueError("invalid_body")
        return web.json_response(await call(_change, controller, request.path, body))

    async def asset(request):
        name = request.match_info.get("fixed_asset", "index.html")
        if name not in ASSETS or not (STATIC / name).is_file():
            raise web.HTTPNotFound()
        return web.Response(body=(STATIC / name).read_bytes(), content_type=ASSETS[name], charset="utf-8")

    async def cleanup(application):
        executor.shutdown(wait=False, cancel_futures=True)

    app.on_cleanup.append(cleanup)
    app.router.add_get("/", asset)
    app.router.add_get("/static/{fixed_asset}", asset)
    app.router.add_get("/api/session", session)
    app.router.add_get("/api/state", state)
    app.router.add_get("/api/diagnostics", diagnostics)
    for route in ("discovery/start", "networks/accept", "networks/edit", "networks/control", "broker", "mode/prepare", "mode/commit"):
        app.router.add_post("/api/" + route, mutate)
    return app


class IngressServer:
    def __init__(self, controller, port, security):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid_ingress_port")
        self.controller, self.port, self.security = controller, port, security
        self.loop = self.runner = self.thread = None
        self.ready = threading.Event()
        self.failed = False

    def start(self):
        if self.thread:
            return
        self.thread = threading.Thread(target=self._run, name="zigbee-ingress", daemon=True)
        self.thread.start()
        if not self.ready.wait(4) or self.failed:
            self.close()
            raise RuntimeError("ingress_unavailable")

    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        async def setup():
            self.runner = web.AppRunner(create_app(self.controller, self.security), access_log=None, shutdown_timeout=1.5)
            await self.runner.setup()
            await web.TCPSite(self.runner, "0.0.0.0", self.port, backlog=32).start()
        try:
            self.loop.run_until_complete(setup())
            self.ready.set()
            self.loop.run_forever()
        except Exception:
            self.failed = True
            self.ready.set()
        finally:
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()

    def close(self):
        if not self.loop or self.loop.is_closed():
            return
        if self.loop.is_running() and self.runner:
            future = asyncio.run_coroutine_threadsafe(self.runner.cleanup(), self.loop)
            try:
                future.result(timeout=3.8)
            except Exception:
                future.cancel()
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=.8)

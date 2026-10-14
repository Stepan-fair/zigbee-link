import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time
from urllib.request import Request, urlopen

import pytest
from app.arp import ProbeResult
from app.config import parse_settings
from app.manager import Status
from app.recovery.journal import EventJournal
from app.recovery.model import Binding
from app.recovery.mqtt import MqttMonitor
from app.recovery.service import RecoveryService
from app.recovery.settings import MqttSettings, parse_recovery
from app.recovery.store import RecoveryStore
from app.recovery.supervisor import SupervisorClient, HttpResult
from recovery_fixture import Fixture

pytestmark = pytest.mark.linux


def wait_for(predicate, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.03)
    pytest.fail("Required runtime condition not reached")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def broker(tmp_path):
    assert os.name == "posix" and shutil.which("mosquitto"), "Real Linux/Mosquitto is required"
    port = free_port()
    cfg = tmp_path / "mosquitto.conf"
    cfg.write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\nuser root\n")
    process = subprocess.Popen(["mosquitto", "-c", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    def listening():
        if process.poll() is not None:
            pytest.fail("Broker failed to start: " + process.stdout.read().decode(errors="replace"))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return True
        except OSError:
            return False
    wait_for(listening)
    yield port
    process.terminate()
    process.wait(timeout=5)


class Clock:
    def __init__(self):
        self.t = 0.
        self.utc = 1000.
    def monotonic(self):
        return self.t
    def time(self):
        return self.utc
    def advance(self, seconds):
        self.t += seconds
        self.utc += seconds


def test_real_mqtt_and_http_restore_independent_networks(tmp_path, broker):
    fixture = Fixture("127.0.0.1", broker, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(fixture.http.server_port)
    clock = Clock()
    cfg = parse_recovery(fixture.options["recovery"], parse_settings(fixture.options))
    class Transport:
        def request(self, method, path, body=None, timeout=5):
            req = Request(origin + path, data=b"{}" if method == "POST" else None,
                          method=method, headers={"Authorization": "Bearer fixture-token"})
            with urlopen(req, timeout=timeout) as r:
                return HttpResult(r.status, r.read())
    supervisor = SupervisorClient("fixture-token", Transport(), cfg.bindings, parse_settings(fixture.options), clock.monotonic)
    mqtt = MqttMonitor(cfg.mqtt, cfg.bindings, clock=clock.monotonic)
    store = RecoveryStore(tmp_path / "state.sqlite")
    present = {"172.31.254.2"}
    def probe(targets):
        return ProbeResult({ip: {"02:00:00:00:00:02"} for ip in targets if str(ip) in present}, True)
    service = RecoveryService(cfg, store, supervisor, mqtt, probe, EventJournal(tmp_path / "logs", clock=clock.time), clock)
    mqtt.start()
    try:
        wait_for(lambda: mqtt.snapshot(cfg.bindings[0].key, clock.t).connected and fixture.client.is_connected())
        def advance(seconds):
            for _ in range(seconds // 5):
                service.tick(Status("ready", "ready", "eth0"))
                time.sleep(.04)
                clock.advance(5)
        advance(300)
        assert fixture.commands == [["net_a_zigbee2mqtt", "start"]], fixture.commands
        assert fixture.radio_requests > 0
        present.add("172.31.254.3")
        advance(300)
        assert fixture.commands == [["net_a_zigbee2mqtt", "start"], ["net_b_zigbee2mqtt", "start"]]
        assert all(store.load(b.key).phase in ("confirmed", "unconfirmed", "checking") for b in cfg.bindings)
        fixture.options["recovery"]["networks"][0]["paused"] = True
        advance(60)
        assert store.load("172.31.254.2").phase == "paused"
        assert len(fixture.commands) == 2
    finally:
        service.close()
        fixture.close()


def test_self_signed_mqtt_certificate_is_rejected(tmp_path):
    assert os.name == "posix" and shutil.which("mosquitto") and shutil.which("openssl")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    port = free_port()
    cfg = tmp_path / "mosquitto.conf"
    cfg.write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\nuser root\ncertfile {cert}\nkeyfile {key}\n")
    process = subprocess.Popen(["mosquitto", "-c", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    context = ssl.create_default_context(cafile=str(cert))
    def healthy_tls():
        if process.poll() is not None:
            pytest.fail("TLS broker failed to start")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2) as s:
                with context.wrap_socket(s, server_hostname="localhost"):
                    return True
        except OSError:
            return False
    monitor = None
    try:
        wait_for(healthy_tls)
        binding = Binding("a", "172.31.254.2", "net_a_zigbee2mqtt", "z2m/a", "0x00124b0000000001")
        monitor = MqttMonitor(MqttSettings(f"mqtts://localhost:{port}"), (binding,))
        monitor.start()
        time.sleep(2)
        assert not monitor.snapshot("a", time.monotonic()).connected
    finally:
        if monitor:
            monitor.stop()
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.parametrize("part", ["headers", "body"])
def test_supervisor_slow_drip_has_total_deadline(part):
    import socketserver
    import sys
    import threading
    from app.recovery.supervisor import HttpTransport
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(8192)
            header=b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
            try:
                if part=="body": self.request.sendall(header)
                for byte in header if part=="headers" else b"x"*100:
                    self.request.sendall(bytes([byte])); time.sleep(.1)
            except OSError:
                pass
    server=socketserver.ThreadingTCPServer(("127.0.0.1",0),Handler)
    server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    origin="http://127.0.0.1:"+str(server.server_address[1])
    processes=[]
    def factory(args, **kwargs):
        code="import app.recovery.supervisor as s; s.ORIGIN="+repr(origin)+"; raise SystemExit(s._http_worker())"
        p=subprocess.Popen([sys.executable,"-c",code],**kwargs); processes.append(p); return p
    transport=HttpTransport("fixture-token",process_factory=factory)
    start=time.monotonic()
    try:
        result=transport.request("GET","/addons/self/info",timeout=.4)
        assert result.status==503 and time.monotonic()-start<2
        assert processes and processes[0].poll() is not None and not transport.processes
    finally:
        transport.close(); server.shutdown(); server.server_close()

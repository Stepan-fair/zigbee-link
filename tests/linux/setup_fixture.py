"""Synthetic two-network Supervisor/MQTT and exact ingress proxy for Linux CI."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import time
from urllib.request import Request, urlopen
from recovery_fixture import Fixture


def initial_options():
    return {"configuration_mode": "legacy", "parent": "auto", "address": "172.31.254.1/24", "coordinators": [],
            "scan_enabled": False, "recovery": {"enabled": False, "mqtt": {}, "networks": []}}


class SetupFixture(Fixture):
    def __init__(self, broker="broker", port=1883, http_host="0.0.0.0", http_port=80):
        self.broker_host, self.broker_port = broker, port
        self.all_requests = []
        super().__init__(broker, port, http_host, http_port)
        self.options = initial_options()

    def extra_get(self, path):
        if path == "/addons":
            data = {"addons": [{"slug": slug, "repository": "synthetic"} for slug in self.records]}
        elif path == "/supervisor/info":
            data = {"version": "2026.10.2"}
        elif path == "/addons/self/info":
            data = {"options": self.options, "ingress_port": 63001}
        elif path == "/services/mqtt":
            data = {"addon": "core_mosquitto", "host": self.broker_host, "port": self.broker_port, "ssl": False,
                    "username": "fixture-service", "password": "fixture-service-secret"}
        elif path == "/addons/core_mosquitto/info":
            data = {"slug": "core_mosquitto", "hostname": self.broker_host}
        elif path == "/fixture/requests":
            return {"requests": self.all_requests}
        elif path.startswith("/addons/") and path.endswith("/info") and path.split("/")[2] in self.records:
            slug = path.split("/")[2]
            record = self.records[slug]
            data = {"slug": slug, "name": "Zigbee2MQTT", "repository": "synthetic", "version": "2.14.2-1", "state": self.states[slug],
                    "options": {"serial": {"port": "tcp://" + record["ip"] + ":6638", "adapter": "ember"}, "mqtt": {"base_topic": record["base_topic"]}}}
        else:
            return None
        return {"result": "ok", "data": data}

    def extra_post(self, path, body):
        if path == "/addons/self/options":
            self.options = deepcopy(body["options"])
            return {"result": "ok", "data": {}}

    def message(self, client, userdata, message):
        self.all_requests.append(message.topic)
        super().message(client, userdata, message)

    def publish_metadata(self):
        for index, record in enumerate(self.records.values()):
            self.client.publish(record["base_topic"] + "/bridge/info", json.dumps({"coordinator": {"ieee_address": record["coordinator_ieee"]},
                "config": {"serial": {"port": "tcp://" + record["ip"] + ":6638"}, "mqtt": {"server": f"mqtt://{self.broker_host}:{self.broker_port}"}}}), retain=True)
            devices = [] if index == 0 else [{"ieee_address": "0x0000000000000012", "type": "Router", "interview_completed": True,
                "disabled": False, "power_source": "Mains (single phase)", "endpoints": {"1": {"clusters": {"input": ["genOnOff"]}}}}]
            self.client.publish(record["base_topic"] + "/bridge/devices", json.dumps(devices), retain=True)


def api(origin, path, payload=None, token=None, user=True):
    headers = {"Content-Type": "application/json"}
    if origin == "http://supervisor":
        headers["Authorization"] = "Bearer fixture-token"
    if user:
        headers["X-Remote-User-Id"] = "synthetic-admin"
    if token:
        headers["X-CSRF-Token"] = token
    req = Request(origin + path, headers=headers, data=json.dumps(payload).encode() if payload is not None else None)
    with urlopen(req, timeout=35) as response:
        return json.load(response)


def verify_proxy(origin):
    session = api(origin, "/api/session")
    token = session["csrf_token"]
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        state = api(origin, "/api/state")
        if len(state["catalog"]["candidates"]) == 2:
            break
        time.sleep(1)
    assert len(state["catalog"]["candidates"]) == 2, state
    assert "fixture-service-secret" not in json.dumps(state)
    before = api("http://supervisor", "/fixture/requests")
    assert before["requests"] == [], before
    def change(path, **payload):
        nonlocal state
        result = api(origin, path, {"expected_revision": state["revision"], **payload}, token)
        state = result["state"]
        return result
    change("/api/mode/prepare", target_mode="guided")
    result = change("/api/mode/commit", receipt=state["transition"]["receipt"])
    assert result["verified"] and state["mode"] == "guided"
    for candidate in state["catalog"]["candidates"]:
        change("/api/networks/accept", candidate_id=candidate["candidate_id"], catalog_revision=state["catalog"]["revision"])
    assert all(not r["managed"] for r in state["networks"])
    for network in state["networks"]:
        change("/api/networks/control", network_id=network["network_id"], managed=True)
    change("/api/networks/control", enabled=True)
    assert state["readiness"]["managed_count"] == 2
    print("Ingress proxy, passive discovery, durable migration and two observation-only accepts: PASS")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if mode == "verify":
        verify_proxy(sys.argv[2])
    elif mode == "app":
        # Only this fixture treats Docker's Ethernet veth as a physical port.
        import app.main as main
        from app.network import CommandRunner
        class EthernetFixtureRunner(CommandRunner):
            def classify(self, links):
                return {"eth0": "ethernet"}
            def run(self, args):
                value = super().run(args)
                if args[:5] == ["ip", "-j", "-d", "link", "show"]:
                    records = json.loads(value)
                    for record in records:
                        if record["ifname"] == "eth0":
                            record.pop("linkinfo", None)
                    return json.dumps(records)
                return value
        main.CommandRunner = EthernetFixtureRunner
        raise SystemExit(main.main())
    elif mode == "serial-watch":
        Path("/tmp/serial-connects").write_text("0")
        with socket.socket() as listener:
            listener.bind(("0.0.0.0", 6638))
            listener.listen()
            count = 0
            while True:
                connection, _ = listener.accept()
                connection.close()
                count += 1
                Path("/tmp/serial-connects").write_text(str(count))
    else:
        fixture = SetupFixture()
        try:
            while True:
                fixture.publish_metadata()
                time.sleep(1)
        finally:
            fixture.close()

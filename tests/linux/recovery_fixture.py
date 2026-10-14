"""Controlled Supervisor/Z2M responder for CI; never production service code."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import paho.mqtt.client as mqtt


def options(server="mqtt://broker:1883"):
    records = []
    for suffix, ip in (("a", "172.31.254.2"), ("b", "172.31.254.3")):
        records.append({"ip": ip, "addon_slug": f"net_{suffix}_zigbee2mqtt", "base_topic": f"z2m/{suffix}",
                        "coordinator_ieee": "0x00124b000000000" + ("1" if suffix == "a" else "2"),
                        "managed": True, "paused": False,
                        "references": [{"ieee": "0x00124b000000001" + ("1" if suffix == "a" else "2"),
                                        "endpoint": 1, "cluster": "genOnOff", "attribute": "onOff"}]})
    return {"parent": "auto", "address": "172.31.254.1/24", "scan_enabled": False,
            "coordinators": [{"name": "Fixture " + str(n), "ip": r["ip"]} for n, r in enumerate(records)],
            "recovery": {"enabled": True, "mqtt": {"server": server}, "networks": records}}


class Fixture:
    def __init__(self, broker="broker", port=1883, http_host="0.0.0.0", http_port=80):
        self.options = options(f"mqtt://{broker}:{port}")
        self.records = {r["addon_slug"]: r for r in self.options["recovery"]["networks"]}
        self.states = {slug: "stopped" for slug in self.records}
        self.commands = []
        self.health_requests = 0
        self.radio_requests = 0
        self.drip_requests = 0
        self.lock = threading.RLock()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="zigbee-fixture")
        self.client.on_connect = lambda c, u, f, r, p: c.subscribe("z2m/+/bridge/request/#")
        self.client.on_message = self.message
        self.client.connect_async(broker, port, keepalive=30)
        self.client.loop_start()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/fixture/drip":
                    with outer.lock:
                        outer.drip_requests += 1
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    try:
                        for _ in range(100):
                            self.wfile.write(b"x"); self.wfile.flush(); time.sleep(.1)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                with outer.lock:
                    if self.path == "/fixture/state":
                        return self.send({"states": outer.states, "commands": outer.commands,
                                          "health": outer.health_requests, "radio": outer.radio_requests, "drip": outer.drip_requests})
                    if self.path == "/fixture/options":
                        return self.send(outer.options)
                    if self.headers.get("Authorization") != "Bearer fixture-token":
                        return self.send({}, 401)
                    if self.path == "/addons/self/info":
                        return self.send({"result": "ok", "data": {"options": outer.options}})
                    if self.path == "/jobs/info":
                        return self.send({"result": "ok", "data": {"jobs": []}})
                    if self.path.endswith("/info"):
                        slug = self.path.split("/")[2]
                        if slug in outer.states:
                            return self.send({"result": "ok", "data": {"slug": slug, "name": "Zigbee2MQTT",
                                             "version": "2.14.2-1", "state": outer.states[slug]}})
                    if "/logs/latest" in self.path:
                        return self.send({"fixture": "no raw private logs"})
                    self.send({}, 404)

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer fixture-token":
                    return self.send({}, 401)
                if self.path in ("/fixture/pause", "/fixture/crash"):
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 1024:
                        return self.send({}, 400)
                    data = json.loads(self.rfile.read(length))
                    slug = data.get("slug")
                    with outer.lock:
                        if slug not in outer.records:
                            return self.send({}, 404)
                        if self.path == "/fixture/pause":
                            outer.records[slug]["paused"] = True
                        else:
                            outer.states[slug] = "stopped"
                            outer.client.publish(outer.records[slug]["base_topic"] + "/bridge/state", '{"state":"offline"}')
                        return self.send({"ok": True})
                _, resource, slug, command = self.path.split("/")
                with outer.lock:
                    if resource != "addons" or slug not in outer.records or command not in ("start", "restart"):
                        return self.send({}, 404)
                    outer.states[slug] = "started"
                    outer.commands.append([slug, command])
                    r = outer.records[slug]
                    outer.client.publish(r["base_topic"] + "/bridge/state", '{"state":"online"}')
                    outer.client.publish(r["base_topic"] + "/bridge/info", json.dumps({"coordinator": {"ieee_address": r["coordinator_ieee"]},
                                         "config": {"serial": {"port": "tcp://" + r["ip"] + ":6638"}}}), retain=True)
                    self.send({"result": "ok", "data": {}})

            def send(self, data, status=200):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.http = ThreadingHTTPServer((http_host, http_port), Handler)
        self.http.daemon_threads = True
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def message(self, client, userdata, message):
        try:
            raw = json.loads(message.payload)
            base, kind = message.topic.split("/bridge/request/", 1)
            with self.lock:
                r = next((r for r in self.records.values() if r["base_topic"] == base), None)
                if r is None or self.states[r["addon_slug"]] != "started":
                    return
                if kind == "health_check":
                    self.health_requests += 1
                    data = {"healthy": True}
                elif kind == "device/reporting/read":
                    self.radio_requests += 1
                    data = {"id": raw["id"], "endpoint": raw["endpoint"], "cluster": raw["cluster"],
                            "configs": [{"status": 0, "direction": 0, "attrId": 0, "dataType": 16, "minRepIntval": 1, "maxRepIntval": 300}]}
                else:
                    return
            client.publish(base + "/bridge/response/" + kind, json.dumps({"transaction": raw["transaction"], "status": "ok", "data": data}))
        except (ValueError, KeyError):
            return

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.client.disconnect()
        self.client.loop_stop()


if __name__ == "__main__":
    fixture = Fixture()
    try:
        while True:
            time.sleep(1)
    finally:
        fixture.close()

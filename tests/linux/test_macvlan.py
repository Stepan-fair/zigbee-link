"""Real kernel networking in disposable namespaces; never use host HA interfaces."""
import os
from pathlib import Path
import subprocess
import sys
import uuid
import pytest

pytestmark = [pytest.mark.linux, pytest.mark.skipif(sys.platform != "linux", reason="Linux namespaces required")]
ROOT = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


@pytest.fixture
def lan(tmp_path):
    if os.geteuid() != 0:
        pytest.fail("Required Linux integration gate must run as root; no silent skip")
    prefix = "zl" + uuid.uuid4().hex[:8]
    names = {key: prefix + key for key in ("h", "s", "a", "b")}
    created = []
    try:
        for name in names.values():
            run("ip", "netns", "add", name); created.append(name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        run("ip", "-n", names["s"], "link", "add", "br0", "type", "bridge")
        run("ip", "-n", names["s"], "link", "set", "br0", "up")
        for i, key in enumerate(("h", "a", "b")):
            attach(names, key, f"p{i}")
        run("ip", "-n", names["h"], "addr", "add", "192.168.50.20/24", "dev", "eth0")
        run("ip", "-n", names["h"], "route", "add", "default", "via", "192.168.50.1", "dev", "eth0")
        for key, ip in (("a", "172.31.254.2/24"), ("b", "172.31.254.3/24")):
            run("ip", "-n", names[key], "addr", "add", ip, "dev", "eth0")
        yield names, tmp_path
    finally:
        for name in reversed(created):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True)


def attach(names, key, peer):
    run("ip", "-n", names["s"], "link", "add", peer, "type", "veth", "peer", "name", "eth0", "netns", names[key])
    run("ip", "-n", names["s"], "link", "set", peer, "master", "br0")
    run("ip", "-n", names["s"], "link", "set", peer, "up")
    run("ip", "-n", names[key], "link", "set", "eth0", "up")


def inside(lan, body):
    names, directory = lan
    preamble = f'''
from pathlib import Path
import subprocess, json
from app.config import parse_settings
from app.network import CommandRunner, read_snapshot
from app.arp import ArpProbe
from app.manager import Identity, InterfaceManager
class Runner(CommandRunner):
    def classify(self, links): return {{"eth0": "ethernet"}}
    def run(self, argv):
        value = super().run(argv)
        if argv[:5] == ["ip", "-j", "-d", "link", "show"]:
            links=json.loads(value)
            for link in links:
                if link["ifname"] == "eth0": link.pop("linkinfo", None)
            return json.dumps(links)
        return value
# veth models physical Ethernet; actual commands/ARP/kernel remain real.
runner=Runner()
identity=Identity.load_or_create(Path({str(directory)!r}))
manager=InterfaceManager(parse_settings({{"scan_enabled": False}}), identity, runner, ArpProbe())
'''
    env = dict(os.environ, PYTHONPATH=str(ROOT / "zigbee_link"))
    result = subprocess.run(["ip", "netns", "exec", names["h"], sys.executable, "-c", preamble + body], text=True, capture_output=True, env=env)
    diagnostic = run("ip", "-n", names["h"], "-j", "-d", "link", "show") if result.returncode else ""
    assert result.returncode == 0, result.stdout + result.stderr + diagnostic


def test_two_coordinators_reachable_via_single_macvlan(lan):
    inside(lan, '''
status=manager.reconcile(); assert status.state == "ready", status
for ip in ("172.31.254.2", "172.31.254.3"):
    subprocess.run(["ping","-c","1","-W","2", ip], check=True)
assert len([l for l in read_snapshot(runner).links if l["ifname"] == "zigbee0"]) == 1
manager.stop()
assert read_snapshot(runner).link("zigbee0") is None
''')


def test_targeted_arp_observes_return_without_touching_other_coordinator(lan):
    inside(lan, '''
from ipaddress import IPv4Address
assert manager.reconcile().state == "ready"
result=manager.probe.probe_targets("zigbee0",identity.mac,IPv4Address("172.31.254.1"),(IPv4Address("172.31.254.2"),IPv4Address("172.31.254.3")))
assert result.complete and len(result.responders)==2, result
''')
    names, _ = lan
    run("ip", "-n", names["a"], "addr", "del", "172.31.254.2/24", "dev", "eth0")
    inside(lan, '''
from ipaddress import IPv4Address
assert manager.reconcile().state == "ready"
result=manager.probe.probe_targets("zigbee0",identity.mac,IPv4Address("172.31.254.1"),(IPv4Address("172.31.254.2"),IPv4Address("172.31.254.3")))
assert result.complete and IPv4Address("172.31.254.2") not in result.responders and IPv4Address("172.31.254.3") in result.responders, result
''')
    run("ip", "-n", names["a"], "addr", "add", "172.31.254.2/24", "dev", "eth0")
    inside(lan, '''
from ipaddress import IPv4Address
assert manager.reconcile().state == "ready"
result=manager.probe.probe_targets("zigbee0",identity.mac,IPv4Address("172.31.254.1"),(IPv4Address("172.31.254.2"),IPv4Address("172.31.254.3")))
assert result.complete and len(result.responders)==2, result
manager.stop()
''')


def test_host_ip_collision_prevents_ready(lan):
    names, _ = lan
    run("ip", "-n", names["a"], "addr", "add", "172.31.254.1/24", "dev", "eth0")
    inside(lan, '''
status=manager.reconcile(); assert status.state == "error", status
assert "занят" in status.message, status
assert read_snapshot(runner).link("zigbee0") is None
''')


def test_lan_address_change_preserves_coordinator_routes(lan):
    inside(lan, '''
assert manager.reconcile().state == "ready"
runner.run(["ip","addr","del","192.168.50.20/24","dev","eth0"])
runner.run(["ip","addr","add","192.168.60.20/24","dev","eth0"])
assert manager.reconcile().state == "ready"
for ip in ("172.31.254.2", "172.31.254.3"):
    subprocess.run(["ping","-c","1","-W","2",ip], check=True)
assert "172.31.254.1" in runner.run(["ip","-j","-4","addr","show","dev","zigbee0"])
manager.stop()
''')


def test_parent_recreation_recovers_owned_interface(lan):
    inside(lan, '''assert manager.reconcile().state == "ready"''')
    names, _ = lan
    run("ip", "-n", names["s"], "link", "delete", "p0")
    attach(names, "h", "p0")
    inside(lan, '''
status=manager.reconcile(); assert status.state == "ready", status
subprocess.run(["ping","-c","1","-W","2","172.31.254.3"], check=True)
manager.stop()
''')


def test_restart_reuses_mac_and_stop_cleans_owned_link(lan):
    inside(lan, '''assert manager.reconcile().state == "ready"''')
    inside(lan, '''
before=read_snapshot(runner).link("zigbee0")
assert manager.reconcile().state == "ready"
after=read_snapshot(runner).link("zigbee0")
assert before["ifindex"] == after["ifindex"] and before["address"] == after["address"] == identity.mac
manager.stop(); manager.stop()
assert read_snapshot(runner).link("zigbee0") is None
''')


def test_bridge_consumer_reaches_both_coordinators(lan):
    names, _ = lan
    client = names["h"] + "c"
    run("ip", "netns", "add", client)
    try:
        run("ip", "-n", names["h"], "link", "add", "docker0", "type", "bridge")
        run("ip", "-n", names["h"], "addr", "add", "172.30.33.1/24", "dev", "docker0")
        run("ip", "-n", names["h"], "link", "set", "docker0", "up")
        run("ip", "-n", names["h"], "link", "add", "vapp", "type", "veth", "peer", "name", "eth0", "netns", client)
        run("ip", "-n", names["h"], "link", "set", "vapp", "master", "docker0")
        run("ip", "-n", names["h"], "link", "set", "vapp", "up")
        run("ip", "-n", client, "link", "set", "eth0", "up")
        run("ip", "-n", client, "addr", "add", "172.30.33.2/24", "dev", "eth0")
        run("ip", "-n", client, "route", "add", "default", "via", "172.30.33.1")
        run("ip", "netns", "exec", names["h"], "sysctl", "-w", "net.ipv4.ip_forward=1")
        # Test fixture models Docker's existing MASQUERADE; production app adds no firewall rules.
        run("ip", "netns", "exec", names["h"], "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.30.33.0/24", "!", "-o", "docker0", "-j", "MASQUERADE")
        inside(lan, '''assert manager.reconcile().state == "ready"''')
        for ip in ("172.31.254.2", "172.31.254.3"):
            run("ip", "netns", "exec", client, "ping", "-c", "1", "-W", "2", ip)
        inside(lan, '''manager.stop()''')
    finally:
        subprocess.run(["ip", "netns", "delete", client], capture_output=True)


def test_unsolicited_ipv6_ra_cannot_add_address_or_route(lan):
    names, _ = lan
    inside(lan, '''assert manager.reconcile().state == "ready"''')
    # Model an ordinary IPv6-enabled host. RA is sent both to Ethernet multicast
    # and directly to the virtual MAC, so a multicast flag alone cannot pass this test.
    mac = __import__("json").loads(run("ip", "-n", names["h"], "-j", "link", "show", "dev", "zigbee0"))[0]["address"]
    run("ip", "netns", "exec", names["h"], "sysctl", "-w", "net.ipv6.conf.zigbee0.accept_ra=1")
    baseline_routes = __import__("json").loads(run("ip", "-n", names["h"], "-j", "-6", "route", "show", "dev", "zigbee0", "table", "all"))
    script = f'''
from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, sendp
for dst in ("33:33:00:00:00:01", {mac!r}):
    packet=Ether(dst=dst)/IPv6(src="fe80::2",dst="ff02::1",hlim=255)/ICMPv6ND_RA(routerlifetime=1800)/ICMPv6NDOptPrefixInfo(prefix="fd00:31:254::",prefixlen=64,L=1,A=1,validlifetime=3600,preferredlifetime=1800)
    sendp(packet,iface="eth0",count=3,inter=0.1,verbose=False)
'''
    run("ip", "netns", "exec", names["a"], sys.executable, "-c", script)
    inside(lan, '''
addresses=json.loads(runner.run(["ip","-j","-6","addr","show","dev","zigbee0"]))
assert all(not record.get("addr_info", []) for record in addresses), addresses
routes=json.loads(runner.run(["ip","-j","-6","route","show","dev","zigbee0","table","all"]))
assert routes == BASELINE_ROUTES, routes
subprocess.run(["ping","-c","1","-W","2","172.31.254.2"], check=True)
manager.stop()
'''.replace("BASELINE_ROUTES", repr(baseline_routes)))

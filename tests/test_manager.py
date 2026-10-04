import copy
import json
from ipaddress import IPv4Address
import pytest
from app.config import parse_settings
from app.network import NetworkSnapshot, NetworkError
from app.arp import ProbeResult
from app.manager import Identity, InterfaceManager


class FakeRunner:
    def __init__(self):
        self.links = [{"ifname": "eth0", "ifindex": 1, "link_type": "ether", "flags": ["UP", "LOWER_UP"]}]
        self.addresses = []
        self.routes = [{"dst": "default", "dev": "eth0"}]
        self.commands = []; self.fail_address = None; self.fail_once = False; self.replace_on_delete = False
        self.qdiscs = []; self.filters = []

    def classify(self, links): return {"eth0": "ethernet"}

    def run(self, args):
        if args[0] == "tc":
            if "-j" in args: return json.dumps(self.qdiscs if "qdisc" in args else self.filters)
            self.commands.append(args)
            if "qdisc" in args: self.qdiscs = [{"kind": "clsact"}]
            else: self.filters = [{"protocol": "ipv6", "pref": 49151, "kind": "matchall", "options": {"actions": [{"kind": "gact", "control_action": {"type": "drop"}}]}}]
            return ""
        if "-j" in args:
            records = self.links if "link" in args else self.addresses if "addr" in args else self.routes
            return json.dumps(copy.deepcopy(records))
        self.commands.append(args)
        if args[:3] == ["ip", "link", "add"]:
            parent = next(l for l in self.links if l["ifname"] == args[args.index("link", 3) + 1])
            self.qdiscs = []; self.filters = []
            self.links.append({"ifname": "zigbee0", "ifindex": max(l["ifindex"] for l in self.links) + 1, "link_index": parent["ifindex"], "link_type": "ether", "flags": [], "address": args[args.index("address") + 1], "linkinfo": {"info_kind": "macvlan", "info_data": {"mode": "bridge"}}})
        elif args[:3] == ["ip", "link", "set"]:
            l = next(l for l in self.links if l["ifname"] == "zigbee0")
            if "alias" in args: l["ifalias"] = args[args.index("alias") + 1]
            elif "addrgenmode" in args: l["inet6_addr_gen_mode"] = "none"
            elif "down" in args: l["flags"] = []
            else: l["flags"] = ["UP", "LOWER_UP"]
        elif args[:3] == ["ip", "link", "delete"]:
            self.links = [l for l in self.links if l["ifname"] != "zigbee0"]
            self.addresses = [a for a in self.addresses if a["ifname"] != "zigbee0"]
            self.routes = [r for r in self.routes if r.get("dev") != "zigbee0"]
        elif args[:3] == ["ip", "addr", "add"]:
            value = args[3]
            if value == self.fail_address:
                if self.fail_once: self.fail_address = None
                raise NetworkError("injected assignment failure")
            ip, prefix = value.split("/")
            self.addresses = [{"ifname": "zigbee0", "addr_info": [{"family": "inet", "local": ip, "prefixlen": int(prefix)}]}]
            self.routes.append({"dst": str(parse_settings({"address": value}).address.network), "dev": "zigbee0"})
        elif args[:3] == ["ip", "addr", "del"]:
            self.addresses = []; self.routes = [r for r in self.routes if r.get("dev") != "zigbee0"]
        elif args[:3] == ["ip", "route", "add"]:
            self.routes.append({"dst": args[3], "dev": "zigbee0"})
        else: raise AssertionError(args)
        return ""


class Probe:
    def __init__(self): self.conflict = False; self.checked = 0
    def check_address(self, *args):
        self.checked += 1
        return ProbeResult({args[-1]: {"02:aa:00:00:00:02"}} if self.conflict else {}, True)
    def scan(self, *args): return ProbeResult({}, True)


def make(tmp_path):
    identity = Identity.load_or_create(tmp_path)
    runner = FakeRunner(); probe = Probe()
    manager = InterfaceManager(parse_settings({"scan_enabled": False}), identity, runner, probe)
    return manager, runner, probe


def test_foreign_interface_never_deleted(tmp_path):
    m, r, p = make(tmp_path)
    r.links.append({"ifname": "zigbee0", "ifindex": 7, "flags": []})
    assert m.reconcile().state == "error"
    m.stop()
    assert not r.commands


def test_correct_owned_interface_reused_without_delete(tmp_path):
    m, r, p = make(tmp_path)
    assert m.reconcile().state == "ready"
    r.commands.clear()
    again = InterfaceManager(m.settings, Identity.load_or_create(tmp_path), r, p)
    assert again.reconcile().state == "ready"
    assert not r.commands
    assert p.checked == 2


def test_missing_interface_and_address_restored(tmp_path):
    m, r, p = make(tmp_path)
    assert m.reconcile().state == "ready"
    r.links = r.links[:1]; r.addresses = []; r.routes = r.routes[:1]
    assert m.reconcile().state == "ready"
    r.addresses = []; r.routes = r.routes[:1]
    assert m.reconcile().state == "ready"
    assert p.checked == 3


def test_collision_removes_only_new_owned_interface(tmp_path):
    m, r, p = make(tmp_path); p.conflict = True
    assert m.reconcile().state == "error"
    assert [l["ifname"] for l in r.links] == ["eth0"]
    assert not r.addresses


def test_reconfiguration_failure_restores_previous_owned_state(tmp_path):
    m, r, p = make(tmp_path)
    assert m.reconcile().state == "ready"
    r.fail_address = "172.31.253.1/24"
    changed = InterfaceManager(parse_settings({"address": r.fail_address, "scan_enabled": False}), Identity.load_or_create(tmp_path), r, p)
    assert changed.reconcile().state == "error"
    assert r.addresses[0]["addr_info"][0]["local"] == "172.31.254.1"


def test_interface_replaced_before_delete_is_preserved(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    r.links[1]["ifalias"] = "foreign"
    m.stop()
    assert r.links[1]["ifalias"] == "foreign"


def test_crash_recovery_requires_identity_match(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    identity = Identity.load_or_create(tmp_path)
    assert identity.mac == m.identity.mac
    r.links[1]["address"] = "02:aa:bb:cc:dd:ee"
    assert InterfaceManager(m.settings, identity, r, p).reconcile().state == "error"


def test_corrupt_identity_never_adopts_existing_interface(tmp_path):
    m, r, p = make(tmp_path)
    (tmp_path / "identity.json").write_text("broken")
    with pytest.raises(NetworkError): Identity.load_or_create(tmp_path)
    assert not r.commands


def test_stop_removes_only_owned_interface(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    m.stop(); m.stop()
    assert len(r.links) == 1


def test_unexpected_owned_address_is_not_removed(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    r.addresses[0]["addr_info"].append({"family": "inet", "local": "192.168.70.1", "prefixlen": 24})
    r.commands.clear()
    assert m.reconcile().state == "error"
    assert not r.commands


def test_scan_cancel_never_ready(tmp_path):
    m, r, p = make(tmp_path)
    p.check_address = lambda *a: ProbeResult({}, False)
    assert m.reconcile().state == "error"
    assert not r.addresses


def test_new_conflict_on_existing_address_removes_owned_address(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    p.conflict = True; m.verified_at -= 61
    assert m.reconcile().state == "error"
    assert len(r.links) == 1


def test_parent_only_failure_restores_old_parent(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    r.links.append({"ifname": "eth1", "ifindex": 9, "link_type": "ether", "flags": ["UP", "LOWER_UP"]})
    r.classify = lambda links: {"eth0": "ethernet", "eth1": "ethernet"}
    r.fail_address = "172.31.254.1/24"; r.fail_once = True
    m.settings = parse_settings({"parent": "eth1", "scan_enabled": False})
    assert m.reconcile().state == "error"
    assert m.identity.parent == "eth0"
    assert r.addresses[0]["addr_info"][0]["local"] == "172.31.254.1"


def test_link_return_rechecks_address_even_within_minute(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    r.links[0]["flags"] = ["UP"]
    assert m.reconcile().state == "waiting"
    r.links[0]["flags"] = ["UP", "LOWER_UP"]; p.conflict = True
    assert m.reconcile().state == "error"
    assert p.checked == 2


def test_ipv6_ingress_block_installed_before_up(tmp_path):
    m, r, p = make(tmp_path); assert m.reconcile().state == "ready"
    up_index = next(i for i, args in enumerate(r.commands) if args[:3] == ["ip", "link", "set"] and "up" in args)
    assert any(args[0] == "tc" and "ipv6" in args and "drop" in args for args in r.commands[:up_index])


def test_pending_creation_disappeared_can_restart(tmp_path):
    m, r, p = make(tmp_path)
    m.identity.parent = "eth0"
    m.identity.pending_index = 7
    m.identity.save()
    assert m.reconcile().state == "ready"
    assert Identity.load_or_create(tmp_path).pending_index is None


def test_pending_receipt_never_adopts_replacement(tmp_path):
    m, r, p = make(tmp_path)
    m.identity.parent = "eth0"
    m.identity.pending_index = 7
    m.identity.save()
    r.links.append({"ifname": "zigbee0", "ifindex": 8, "address": m.identity.mac,
                    "link_index": 1, "linkinfo": {"info_kind": "macvlan", "info_data": {"mode": "bridge"}}})
    assert m.reconcile().state == "error"
    assert not r.commands

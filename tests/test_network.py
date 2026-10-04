import pytest
from app.config import parse_settings
from app.network import NetworkSnapshot, select_parent, check_overlap, read_snapshot, NetworkError


def snapshot(links=None, routes=None, addresses=None):
    return NetworkSnapshot(links or [], addresses or [], routes or [], {"eth0": "ethernet", "eth1": "ethernet", "wlan0": "wifi"})


def link(name, **extra):
    return {"ifname": name, "ifindex": 1, "flags": ["UP", "LOWER_UP"], "link_type": "ether", **extra}


def test_single_active_ethernet_selected():
    s = snapshot([link("eth0"), link("eth1")], [{"dst": "default", "dev": "eth0", "metric": 100}])
    assert select_parent(parse_settings({}), s) == "eth0"


def test_equal_candidates_rejected():
    with pytest.raises(NetworkError):
        select_parent(parse_settings({}), snapshot([link("eth0"), link("eth1")]))


def test_virtual_and_wifi_excluded():
    s = snapshot([link("eth0"), link("wlan0"), link("docker0", linkinfo={"info_kind": "bridge"})])
    assert select_parent(parse_settings({}), s) == "eth0"
    with pytest.raises(NetworkError):
        select_parent(parse_settings({"parent": "wlan0"}), s)


@pytest.mark.parametrize("route", [{"dst": "172.31.254.0/24", "dev": "eth0"}, {"dst": "172.16.0.0/12", "dev": "tun0"}, {"dst": "172.31.254.2/32", "dev": "docker0"}, {"dst": "172.31.254.0/24", "type": "blackhole"}])
def test_main_and_docker_vpn_overlap_rejected(route):
    with pytest.raises(NetworkError):
        check_overlap(parse_settings({}), snapshot(routes=[route]), None)


def test_default_and_owned_routes_allowed():
    check_overlap(parse_settings({}), snapshot(routes=[{"dst": "default", "dev": "eth0"}, {"dst": "172.31.254.0/24", "dev": "zigbee0"}]), "zigbee0")


def test_local_address_overlap_rejected():
    with pytest.raises(NetworkError):
        check_overlap(parse_settings({}), snapshot(addresses=[{"ifname": "eth1", "addr_info": [{"family": "inet", "local": "172.31.254.8", "prefixlen": 24}]}]), None)


def test_invalid_snapshot_is_not_treated_as_empty():
    class BadRunner:
        def run(self, argv):
            return "not-json"
    with pytest.raises(NetworkError):
        read_snapshot(BadRunner())


def test_no_carrier_waits_and_vpn_default_not_selected():
    with pytest.raises(NetworkError):
        select_parent(parse_settings({}), snapshot([link("eth0", flags=["UP"])]))
    assert select_parent(parse_settings({}), snapshot([link("eth0"), link("tun0")], [{"dst": "default", "dev": "tun0"}])) == "eth0"


@pytest.mark.parametrize("addr", [{"local": "172.31.254.9", "prefixlen": 24}, {"family": "inet", "local": "bad", "prefixlen": 24}, {"family": "inet", "local": "172.31.254.9"}, "bad"])
def test_nested_malformed_address_records_fail_closed(addr):
    class Runner:
        def run(self, argv):
            import json
            return json.dumps([{"ifname": "eth0", "addr_info": [addr]}] if "addr" in argv else [])
        def classify(self, links): return {}
    with pytest.raises(NetworkError): read_snapshot(Runner())

import pytest
from app.config import parse_settings


def test_defaults_are_clean():
    s = parse_settings({})
    assert s.parent == "auto"
    assert str(s.address) == "172.31.254.1/24"
    assert s.coordinators == ()
    assert s.scan_enabled is True


@pytest.mark.parametrize("address", ["172.10.31.1/24", "127.0.0.1/24", "169.254.1.1/24", "172.31.254.0/24", "172.31.254.255/24", "172.31.254.1/16", "::1/24", "x"])
def test_public_and_reserved_addresses_rejected(address):
    with pytest.raises(ValueError):
        parse_settings({"address": address})


@pytest.mark.parametrize("ips", [["172.31.254.2", "172.31.254.2"], ["172.31.254.1"], ["172.31.253.2"], ["172.31.254.255"]])
def test_duplicate_coordinator_rejected(ips):
    with pytest.raises(ValueError):
        parse_settings({"coordinators": [{"name": "device", "ip": ip} for ip in ips]})


@pytest.mark.parametrize("raw", [{"scan_enabled": "false"}, {"parent": "eth0;reboot"}, {"parent": ""}, {"coordinators": "bad"}, {"coordinators": [{"name": "\nsecret", "ip": "172.31.254.2"}]}])
def test_invalid_types_and_injection_rejected(raw):
    with pytest.raises(ValueError):
        parse_settings(raw)

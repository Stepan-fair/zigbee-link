import json
from ipaddress import IPv4Network
import pytest


def test_enabled_empty_recovery_is_not_reported_configured():
    from app.setup.validation import configuration_readiness, select_configuration_mode
    result = configuration_readiness(True, False, 0, 0)
    assert result.enabled and not result.configured and result.managed_count == 0
    assert set(result.reasons) == {"mqtt_unconfigured", "networks_empty"}
    assert select_configuration_mode({}) == "legacy"
    assert select_configuration_mode({"configuration_mode": "guided"}) == "guided"
    with pytest.raises(ValueError):
        select_configuration_mode({"configuration_mode": "unknown"})


@pytest.mark.parametrize("payload", [b'{}' + b' ' * 1048576, b'[' * 33 + b'0' + b']' * 33,
                                    b'{"ip": "a", "ip": "b"}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e9999}'],
                         ids=["oversize", "depth", "duplicate", "nan", "infinity", "overflow"])
def test_metadata_limits_and_duplicate_identity_keys(payload):
    from app.setup.validation import decode_metadata
    with pytest.raises(ValueError):
        decode_metadata(payload)


def test_metadata_parser_handles_escaped_brackets_and_unicode():
    from app.setup.validation import decode_metadata
    raw = {"name": 'строка [{{ \\" ] } ' * 40}
    assert decode_metadata(json.dumps(raw).encode()) == raw
    assert decode_metadata(b'[' * 32 + b'0' + b']' * 32) is not None


@pytest.mark.parametrize("field,value,reason", [("ip", "192.168.50.2", "ip_outside_subnet"),
    ("addon_slug", "core_mosquitto", "invalid_addon"), ("base_topic", "a/#", "invalid_topic"),
    ("coordinator_ieee", "0x123", "invalid_ieee"), ("serial_port", True, "invalid_port")])
def test_network_validation_rejects_unsafe_binding(field, value, reason):
    from app.setup.model import FieldValue, NetworkRecord
    from app.setup.validation import validate_network
    values = dict(name="A", ip="172.31.254.2", addon_slug="a_zigbee2mqtt", base_topic="a",
                  coordinator_ieee="0x0000000000000001", serial_port=6638, references=[])
    values[field] = value
    fields = {k: FieldValue("manual", v, "user", 0, "verified") for k, v in values.items()}
    record = NetworkRecord("n-a", "172.31.254.2", fields, True, False, True)
    assert reason in validate_network(record, IPv4Network("172.31.254.0/24"))


def test_legacy_factory_logs_missing_networks_without_breaking_interface(tmp_path, caplog):
    from app.main import make_recovery
    from app.config import parse_settings
    result = make_recovery({"recovery": {"enabled": True}}, parse_settings({}), None, None, tmp_path, None)
    assert result is None
    assert "networks_empty" in caplog.text
    assert "Нет настроенных сетей" in caplog.text


def test_legacy_disabled_defaults_remain_quiet(tmp_path, caplog):
    from app.main import make_recovery
    from app.config import parse_settings
    assert make_recovery({}, parse_settings({}), None, None, tmp_path, None) is None
    assert not caplog.text

import pytest
from app.config import parse_settings
from app.recovery.settings import parse_recovery


def raw_record(ip="172.31.254.2", slug="abc_zigbee2mqtt", topic="zigbee2mqtt/first"):
    return {"ip": ip, "addon_slug": slug, "base_topic": topic,
            "coordinator_ieee": "0x00124b0000000001", "managed": True, "paused": False,
            "references": [{"ieee": "0x00124b0000000010", "endpoint": 1,
                            "cluster": "genOnOff", "attribute": "onOff"}]}


def settings():
    return parse_settings({"coordinators": [{"name":"First", "ip":"172.31.254.2"},
                                          {"name":"Second", "ip":"172.31.254.3"}]})


def config(records):
    return {"enabled": True, "mqtt": {"server":"mqtt://broker:1883", "password":"private-example"}, "networks": records}


def test_old_configuration_does_not_enable_recovery():
    cfg = parse_recovery({}, parse_settings({}))
    assert cfg.bindings == () and cfg.errors == {} and not cfg.enabled


def test_two_independent_networks_and_private_repr():
    cfg = parse_recovery(config([raw_record(), raw_record("172.31.254.3", "def_zigbee2mqtt", "zigbee2mqtt/second")]), settings())
    assert len(cfg.bindings) == 2 and not cfg.errors
    assert cfg.bindings[0].key != cfg.bindings[1].key
    assert cfg.controls[cfg.bindings[0].key].managed
    assert "private-example" not in repr(cfg)


@pytest.mark.parametrize("field,value", [("ip","172.31.254.9"),("addon_slug","../core"),
    ("base_topic","zigbee/#"),("base_topic","bridge/+/bad"),("coordinator_ieee","no"),
    ("paused","false"),("managed",1)])
def test_invalid_record_does_not_disable_valid_network(field,value):
    bad=raw_record(); bad[field]=value
    cfg=parse_recovery(config([bad,raw_record("172.31.254.3","def_zigbee2mqtt","zigbee2mqtt/second")]),settings())
    assert len(cfg.bindings)==1 and len(cfg.errors)==1
    assert cfg.bindings[0].ip=="172.31.254.3"


@pytest.mark.parametrize("field", ["ip","addon_slug","base_topic"])
def test_duplicates_block_both_records(field):
    first=raw_record(); second=raw_record("172.31.254.3","def_zigbee2mqtt","zigbee2mqtt/second")
    second[field]=first[field]
    cfg=parse_recovery(config([first,second]),settings())
    assert cfg.bindings==() and cfg.errors


def test_missing_mqtt_blocks_recovery_without_raising():
    cfg=parse_recovery({"enabled":True,"networks":[raw_record()]},settings())
    assert cfg.errors and not cfg.bindings


def test_defaults_do_not_arm_or_pause_record():
    r=raw_record(); r.pop("managed"); r.pop("paused")
    cfg=parse_recovery(config([r]),settings())
    assert not cfg.controls[cfg.bindings[0].key].managed
    assert not cfg.controls[cfg.bindings[0].key].paused


def test_controls_change_without_changing_binding_fingerprint():
    a=raw_record(); b=raw_record(); b["paused"]=True
    ca=parse_recovery(config([a]),settings()); cb=parse_recovery(config([b]),settings())
    assert ca.bindings==cb.bindings
    assert ca.controls[ca.bindings[0].key].revision!=cb.controls[cb.bindings[0].key].revision


def test_invalid_mqtt_credentials_never_in_errors():
    r=config([raw_record()]); r["mqtt"]["server"]="mqtt://user:private-example@broker"
    cfg=parse_recovery(r,settings())
    assert cfg.errors and "private-example" not in str(cfg.errors)

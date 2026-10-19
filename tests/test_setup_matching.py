from dataclasses import replace
from ipaddress import IPv4Network
from app.setup.model import AppMetadata, BridgeMetadata, BrokerRecord, FieldValue, NetworkRecord

BROKER = BrokerRecord("b", "auto", "mqtt://172.30.33.2:1883", "core_mosquitto", ("core-mosquitto", "172.30.33.2"))
SUBNET = IPv4Network("172.31.254.0/24")
A = AppMetadata("a_zigbee2mqtt", "Zigbee2MQTT A", "2.14.2", "started", "172.31.254.2", 6638, "ember", "floor/a")
B = replace(A, slug="b_zigbee2mqtt", name="B", serial_ip="172.31.254.3", base_topic="floor/b")
BA = BridgeMetadata("floor/a", "172.31.254.2", 6638, "0x0000000000000001", "mqtt://core-mosquitto:1883", True, 100)
BB = replace(BA, base_topic="floor/b", ip="172.31.254.3", coordinator_ieee="0x0000000000000002")


def test_two_apps_match_their_own_nested_topics():
    from app.setup.matching import match_networks
    rows = match_networks((A, B), (BB, BA), broker=BROKER, subnet=SUBNET)
    assert len(rows) == 2
    pairs = {(r.fields["addon_slug"].value, r.fields["ip"].value, r.fields["base_topic"].value) for r in rows}
    assert pairs == {("a_zigbee2mqtt", "172.31.254.2", "floor/a"), ("b_zigbee2mqtt", "172.31.254.3", "floor/b")}
    assert all(r.match_kind == "verified" for r in rows)


def test_single_app_without_evidence_stays_proposed():
    from app.setup.matching import match_networks
    row = match_networks((replace(A, serial_ip=None, serial_port=None, base_topic=None),), (BA,), broker=BROKER, subnet=SUBNET)[0]
    assert row.match_kind == "proposed"
    assert "association_unconfirmed" in row.issues


def test_conflicts_and_out_of_subnet_never_auto_accept():
    from app.setup.matching import match_networks
    for app, bridge in ((A, replace(BA, ip="192.168.50.2")), (A, replace(BA, port=8888))):
        rows = match_networks((app,), (bridge,), broker=BROKER, subnet=SUBNET)
        assert all(row.match_kind != "verified" for row in rows)
    rows = match_networks((A, B), (BA, BB), broker=BROKER, subnet=SUBNET, conflicts=frozenset({"172.31.254.2"}))
    assert {r.fields["ip"].value: r.match_kind for r in rows} == {"172.31.254.2": "conflict", "172.31.254.3": "verified"}


def test_mqtt_cannot_choose_a_new_broker():
    from app.setup.matching import match_networks
    rows = match_networks((A,), (replace(BA, broker_server="mqtt://attacker.invalid:1883"),), broker=BROKER, subnet=SUBNET)
    assert rows[0].match_kind == "conflict"
    assert "foreign_broker" in rows[0].issues


def test_duplicate_retained_producers_and_duplicate_apps_are_conflicts():
    from app.setup.matching import match_networks
    changed = replace(BA, coordinator_ieee="0x0000000000000003")
    assert all(r.match_kind == "conflict" for r in match_networks((A,), (BA, changed), broker=BROKER, subnet=SUBNET))
    assert all(r.match_kind == "conflict" for r in match_networks((A, replace(A, slug=B.slug)), (BA,), broker=BROKER, subnet=SUBNET))


def test_manual_and_pinned_values_survive_new_proposal():
    from app.setup.matching import match_networks, merge_suggestions
    candidate = match_networks((A,), (BA,), broker=BROKER, subnet=SUBNET)[0]
    fields = dict(candidate.fields)
    fields["name"] = FieldValue("manual", "Owner name", "user", 0, "verified")
    record = NetworkRecord("n", "172.31.254.2", fields, True, True, True)
    new_fields = dict(candidate.fields)
    new_fields["ip"] = replace(new_fields["ip"], value="172.31.254.9")
    merged = merge_suggestions(record, replace(candidate, fields=new_fields))
    assert merged.fields["name"].value == "Owner name"
    assert merged.fields["ip"].value == "172.31.254.2"
    assert merged.fields["ip"].proposal == "172.31.254.9"
    assert merged.paused and merged.managed


def test_radio_candidates_exclude_battery_and_prefer_configured_reporting():
    from app.setup.matching import suggest_references
    base = {"type": "Router", "power_source": "Mains (single phase)", "interview_state": "SUCCESSFUL",
            "endpoints": {"1": {"clusters": {"input": ["genBasic", "genOnOff"]}, "configured_reportings": []}}}
    devices = []
    for i in range(1, 5):
        devices.append({**base, "ieee_address": "0x" + f"{i:016x}"})
    devices[0] = {**devices[0], "power_source": "Battery"}
    devices[1] = {**devices[1], "disabled": True}
    devices[3] = {**devices[3], "endpoints": {"1": {"clusters": {"input": ["genOnOff"]},
                           "configured_reportings": [{"cluster": "genOnOff", "attribute": "onOff"}]}}}
    refs = suggest_references(tuple(devices))
    assert [r.ieee for r in refs] == ["0x0000000000000004", "0x0000000000000003"]
    assert refs[0].endpoint == 1 and refs[0].cluster == "genOnOff" and refs[0].attribute == "onOff"
    assert suggest_references(()) == ()
    assert suggest_references(({**base, "ieee_address": "0x0000000000000001", "type": "Coordinator"},)) == ()

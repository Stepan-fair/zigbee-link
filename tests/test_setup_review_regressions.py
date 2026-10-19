from copy import deepcopy
from dataclasses import asdict, replace
import json
import threading
import time
from types import SimpleNamespace
import pytest
from app.recovery.model import Controls
from app.setup.model import BrokerConnection, BrokerRecord
from app.recovery.settings import MqttSettings
from test_setup_acceptance import guided_two
from test_setup_runtime import controller
from test_setup_migration import legacy_options


def test_reference_extra_key_rejected_before_save_and_healthy_neighbour_kept(tmp_path):
    ctl, _, _, a, b = guided_two(tmp_path)
    before = ctl.store.snapshot()
    reference = {"ieee": "0x0000000000000010", "endpoint": 1, "cluster": "genOnOff", "attribute": "onOff", "unexpected": True}
    try:
        with pytest.raises(ValueError):
            ctl.edit(a.network_id, {"references": {"mode": "manual", "value": [reference]}}, expected_revision=before.revision)
        assert ctl.store.snapshot() == before
        assert len(ctl.configuration().bindings) == 2
        # The same semantic corruption already present on disk is isolated on read.
        record = next(r for r in before.networks if r.network_id == a.network_id)
        raw = asdict(record)
        raw["fields"]["references"]["value"] = [reference]
        ctl.store.db.execute("UPDATE networks SET payload=? WHERE network_id=?", (json.dumps(raw), a.network_id))
        ctl.store.db.commit()
        assert [binding.key for binding in ctl.configuration().bindings] == [b.state_key]
    finally:
        ctl.close()


def test_manual_discovery_broker_is_restored_after_restart_without_service_fallback(tmp_path):
    ctl, fixture, _ = controller(tmp_path)
    ctl.edit_broker({"mode": "manual", "server": "mqtt://manual.invalid", "username": "manual-user", "password": "manual-secret"}, expected_revision=0)
    ctl.close()
    ctl, _, _ = controller(tmp_path, options=fixture.options)
    try:
        connection, apps, issues = ctl.discovery._read_sources()
        assert connection.record.server == "mqtt://manual.invalid"
        assert connection.settings.username == "manual-user" and connection.settings.password == "manual-secret"
        assert len(apps) == 2
    finally:
        ctl.close()


def test_migration_keeps_live_legacy_broker_after_different_service_was_discovered(tmp_path):
    options = legacy_options()
    ctl, _, _ = controller(tmp_path, options=options)
    connection = ctl.reader.mqtt_service()
    snapshot = ctl.store.snapshot()
    ctl.store.save(replace(snapshot, broker=connection.record), expected_revision=snapshot.revision)
    ctl.discovery.connection = connection
    try:
        transition = ctl.prepare_transition("guided", expected_revision=ctl.store.snapshot().revision)
        assert ctl.commit_transition(transition.receipt)
        config = ctl.configuration()
        assert config.mqtt.server == options["recovery"]["mqtt"]["server"]
        assert config.mqtt.password == options["recovery"]["mqtt"]["password"]
        assert ctl.store.snapshot().networks[0].paused
    finally:
        ctl.close()


def test_invalid_legacy_row_is_imported_for_correction_with_original_budget(tmp_path):
    from app.recovery.model import Action
    options = legacy_options()
    options["recovery"]["networks"][0]["coordinator_ieee"] = ""
    ctl, _, _ = controller(tmp_path, options=options)
    ctl.recovery_store.reserve(Action("start", "172.31.254.2", "g"), 1000, "r")
    try:
        transition = ctl.prepare_transition("guided", expected_revision=0)
        assert ctl.commit_transition(transition.receipt)
        snapshot = ctl.store.snapshot()
        assert len(snapshot.networks) == 1
        record = snapshot.networks[0]
        assert not record.accepted and not record.managed and record.paused
        assert record.fields["ip"].value == "172.31.254.2" and record.issues
        assert record.state_key == "172.31.254.2"
        snapshot = ctl.edit(record.network_id, {"coordinator_ieee": {"mode": "manual", "value": "0x0000000000000001"}}, expected_revision=snapshot.revision, confirm_identity=True)
        assert snapshot.networks[0].accepted and ctl.recovery_store.command_count(record.state_key, 0) == 1
    finally:
        ctl.close()


def test_recovery_mqtt_stop_is_bounded_and_fences_late_callbacks():
    from app.recovery.mqtt import MqttMonitor
    from test_setup_mqtt import FakePaho
    from app.recovery.model import Binding
    client = FakePaho()
    blocked = threading.Event()
    client.block_cleanup = blocked
    binding = Binding("a", "172.31.254.2", "a_zigbee2mqtt", "floor/a", "0x0000000000000001")
    monitor = MqttMonitor(MqttSettings("mqtt://manual.invalid"), (binding,), client=client)
    monitor.start()
    try:
        started = time.monotonic()
        monitor.stop()
        assert time.monotonic() - started < .5
        monitor.on_connected()
        assert not monitor.snapshot("a", time.monotonic()).connected
        assert not monitor.cleanup_done.is_set()
    finally:
        blocked.set()
        monitor.stop()


def test_fresh_poll_uses_time_after_permission_read_not_previous_tick(tmp_path):
    from test_recovery_service import setup
    service, clock, supervisor, mqtt, probe, store = setup(tmp_path)
    runtime = next(iter(service.runtimes.values()))
    original = supervisor.self_controls
    def after_http():
        clock.advance(.1)
        return original()
    supervisor.self_controls = after_http
    sent = []
    mqtt.request_health = lambda *args: sent.append("health")
    try:
        service._poll_authorized(runtime, 0)
        assert sent == ["health"]
    finally:
        service.close()


def test_broker_rebuild_keeps_main_loop_free_without_accumulating_clients(tmp_path, monkeypatch):
    import app.recovery.mqtt as mqtt_module
    from test_setup_mqtt import FakePaho
    ctl, _, _, a, b = guided_two(tmp_path)
    original = mqtt_module.MqttMonitor
    made = []
    blocked = threading.Event()
    def make(*args, **kwargs):
        client = FakePaho()
        if not made:
            client.block_cleanup = blocked
        monitor = original(*args, client=client, **kwargs)
        made.append(monitor)
        return monitor
    monkeypatch.setattr(mqtt_module, "MqttMonitor", make)
    ctl.identity = SimpleNamespace(mac="02:00:00:00:00:01")
    ctl.probe = SimpleNamespace(probe_targets=lambda *args: None)
    try:
        ctl._apply()
        assert len(made) == 1
        ctl.edit_broker({"mode": "manual", "server": "mqtt://replacement.invalid"}, expected_revision=ctl.store.snapshot().revision)
        started = time.monotonic()
        ctl._apply()
        assert time.monotonic() - started < .6
        for _ in range(10):
            ctl._apply()
        assert len(made) == 1 and ctl.service is None
        blocked.set()
        assert made[0].cleanup_done.wait(1)
        deadline = time.monotonic() + 1
        while len(made) < 2 and time.monotonic() < deadline:
            ctl._apply()
            time.sleep(.01)
        assert len(made) == 2
    finally:
        blocked.set()
        started = time.monotonic()
        ctl.close()
        assert time.monotonic() - started < 5


def test_callback_for_removed_network_does_not_crash_surviving_monitor(monkeypatch):
    import app.recovery.mqtt as mqtt_module
    from app.recovery.model import Binding
    from test_setup_mqtt import FakePaho
    a = Binding("a", "172.31.254.2", "a_zigbee2mqtt", "floor/a", "0x0000000000000001")
    b = Binding("b", "172.31.254.3", "b_zigbee2mqtt", "floor/b", "0x0000000000000002")
    monitor = mqtt_module.MqttMonitor(MqttSettings("mqtt://broker.invalid"), (a, b), client=FakePaho())
    monitor.on_connected()
    previous = monitor.epochs["b"]
    def after_reconfigure(payload):
        monitor.reconfigure((b,))
        return {}
    monkeypatch.setattr(mqtt_module.json, "loads", after_reconfigure)
    try:
        monitor.receive("floor/a/bridge/info", b"{}", False, 0)
        assert monitor.epochs["b"] == previous and monitor.snapshot("b", 0).connected
    finally:
        monitor.stop()

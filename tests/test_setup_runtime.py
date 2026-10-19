from copy import deepcopy
from dataclasses import replace
import threading
import pytest

from app.config import parse_settings
from app.setup.model import BrokerRecord, Candidate, Catalog, FieldValue
from app.setup.store import RevisionConflict
from app.setup.supervisor import SupervisorCatalogReader
from test_setup_supervisor import SupervisorFixture
from test_recovery_service import Clock


def candidate(ip="172.31.254.2", slug="a_zigbee2mqtt", ieee="0x0000000000000001", topic="floor/a"):
    values = dict(name="Сеть A", ip=ip, serial_port=6638, addon_slug=slug,
                  base_topic=topic, coordinator_ieee=ieee, references=[])
    return Candidate(slug, {k: FieldValue("auto", v, "bridge_retained", 1000, "found") for k, v in values.items()}, (), "matched")


def controller(tmp_path, *, options=None):
    from app.setup.runtime import SetupController
    fixture = SupervisorFixture()
    if options is not None:
        fixture.options = deepcopy(options)
    clock = Clock()
    ctl = SetupController(fixture.options, parse_settings(fixture.options), None, None, tmp_path,
                          threading.Event(), reader=SupervisorCatalogReader(fixture), clock=clock)
    return ctl, fixture, clock


def accept_one(ctl, item=None):
    item = item or candidate()
    cat = ctl.store.save_catalog(Catalog(candidates=(item,)), expected_revision=ctl.store.catalog().revision)
    snapshot = ctl.accept(item.candidate_id, catalog_revision=cat.revision, expected_revision=ctl.store.snapshot().revision)
    return snapshot, snapshot.networks[-1]


def test_accept_defaults_observation_manual_pins_and_stale_edit(tmp_path):
    ctl, _, _ = controller(tmp_path)
    snapshot, record = accept_one(ctl)
    assert not record.managed and not record.paused
    snapshot = ctl.edit(record.network_id, {"ip": {"mode": "manual", "value": "172.31.254.8"}}, expected_revision=snapshot.revision, confirm_identity=True)
    assert snapshot.networks[0].fields["ip"].value == "172.31.254.8"
    with pytest.raises(RevisionConflict):
        ctl.control(record.network_id, paused=False, expected_revision=snapshot.revision - 1)
    with pytest.raises(ValueError):
        ctl.edit(record.network_id, {"ip": {"mode": "auto", "value": "172.31.254.9"}}, expected_revision=snapshot.revision)
    ctl.close()


def test_missing_broker_recovers_without_interface_restart(tmp_path):
    ctl, fixture, _ = controller(tmp_path)
    snapshot, _ = accept_one(ctl)
    transition = ctl.prepare_transition("guided", expected_revision=snapshot.revision)
    assert ctl.commit_transition(transition.receipt)
    assert not ctl.view().readiness.configured
    ctl.edit_broker({"mode": "manual", "server": "mqtt://broker.invalid", "username": "u", "password": "private-marker"}, expected_revision=ctl.store.snapshot().revision)
    assert ctl.view().readiness.configured
    assert ctl.effective_settings().coordinators[0].address.compressed == "172.31.254.2"
    assert "private-marker" not in str(ctl.diagnostics())
    assert fixture.options["configuration_mode"] == "guided"
    ctl.close()


def test_delete_readd_cannot_bypass_rate_limit(tmp_path):
    from app.recovery.model import Action
    ctl, _, _ = controller(tmp_path)
    snapshot, record = accept_one(ctl)
    ctl.recovery_store.reserve(Action("start", record.state_key, "g"), 1000, "r")
    ctl.edit(record.network_id, {"tombstoned": True}, expected_revision=snapshot.revision)
    snapshot, again = accept_one(ctl)
    assert again.state_key == record.state_key and again.network_id == record.network_id
    assert ctl.recovery_store.command_count(again.state_key, 0) == 1
    assert not again.managed
    ctl.close()


def test_pause_during_dispatch_and_stale_edit_cannot_send(tmp_path):
    ctl, fixture, _ = controller(tmp_path)
    snapshot, record = accept_one(ctl)
    ctl.edit_broker({"mode": "manual", "server": "mqtt://broker.invalid"}, expected_revision=snapshot.revision)
    transition = ctl.prepare_transition("guided", expected_revision=ctl.store.snapshot().revision)
    assert ctl.commit_transition(transition.receipt)
    snapshot = ctl.control(record.network_id, managed=True, enabled=True, expected_revision=ctl.store.snapshot().revision)
    binding = ctl.configuration().bindings[0]
    revision = ctl.controls_for((binding,))[binding.key].revision
    ctl.control(record.network_id, paused=True, expected_revision=snapshot.revision)
    sent = []
    result = ctl.guard_command(binding, revision, lambda: sent.append("start"))
    assert not sent and result.reason == "cancelled"
    ctl.close()


def test_rebind_a_does_not_reset_b_or_budget(tmp_path):
    from test_recovery_service import setup
    svc, clock, supervisor, mqtt, probe, store = setup(tmp_path)
    old_a, old_b = svc.config.bindings
    runtime_b = svc.runtimes[old_b.key]
    generation_b = mqtt.epochs[old_b.key]
    changed = replace(old_a, ip="172.31.254.8")
    mqtt.reconfigure = lambda bindings: None
    supervisor.reconfigure = lambda bindings: None
    svc.reconfigure(replace(svc.config, bindings=(changed, old_b)))
    assert svc.runtimes[old_b.key] is runtime_b and mqtt.epochs[old_b.key] == generation_b
    assert svc.runtimes[old_a.key].binding == changed
    svc.close()


def test_unknown_identity_does_not_restart_healthy_app(tmp_path):
    ctl, _, _ = controller(tmp_path)
    invalid = candidate(ieee="")
    cat = ctl.store.save_catalog(Catalog(candidates=(invalid,)), expected_revision=0)
    snapshot = ctl.accept(invalid.candidate_id, catalog_revision=cat.revision, expected_revision=0)
    assert not snapshot.networks[0].accepted and not snapshot.networks[0].managed
    assert not ctl.configuration().bindings
    ctl.close()


def test_incomplete_proposal_can_be_corrected_without_granting_automatic_rights(tmp_path):
    ctl, _, _ = controller(tmp_path)
    item = replace(candidate(ieee=""), match_kind="proposed", issues=("identity_incomplete",))
    snapshot, record = accept_one(ctl, item)
    assert not record.accepted and not record.managed
    snapshot = ctl.edit(record.network_id, {"coordinator_ieee": {"mode": "manual", "value": "0x0000000000000001"}}, expected_revision=snapshot.revision, confirm_identity=True)
    assert snapshot.networks[0].accepted and not snapshot.networks[0].managed
    ctl.close()


def test_mqtt_reconfigure_invalidates_only_changed_network():
    from app.recovery.mqtt import MqttMonitor
    from app.recovery.settings import MqttSettings
    from app.recovery.model import Binding
    from test_setup_mqtt import FakePaho
    a = Binding("a", "172.31.254.2", "a_zigbee2mqtt", "floor/a", "0x0000000000000001")
    b = Binding("b", "172.31.254.3", "b_zigbee2mqtt", "floor/b", "0x0000000000000002")
    mqtt = MqttMonitor(MqttSettings("mqtt://broker.invalid"), (a, b), client=FakePaho())
    old_a, old_b = mqtt.epochs["a"], mqtt.epochs["b"]
    mqtt.reconfigure((replace(a, ip="172.31.254.8"), b))
    assert mqtt.epochs["a"] != old_a and mqtt.epochs["b"] == old_b


def test_stale_worker_cannot_save_new_runtime(tmp_path):
    from concurrent.futures import Future
    from app.recovery.model import AppObservation, Controls
    from test_recovery_service import setup
    svc, clock, supervisor, mqtt, probe, store = setup(tmp_path)
    old = svc.config.bindings[0]
    future = Future()
    future._zigbee_runtime = svc.runtimes[old.key]
    svc.futures[old.key] = (future, "observe")
    mqtt.reconfigure = lambda bindings: None
    supervisor.reconfigure = lambda bindings: None
    svc.reconfigure(replace(svc.config, bindings=(replace(old, ip="172.31.254.8"), svc.config.bindings[1])))
    if not future.cancelled():
        future.set_result((Controls(True), AppObservation(True, "started")))
    svc._collect(1)
    assert svc.runtimes[old.key].controls is None
    svc.close()


def test_http_scope_cancel_does_not_cancel_other_network():
    import subprocess
    import sys
    from app.recovery.supervisor import HttpTransport
    processes = []
    def factory(args, **kwargs):
        process = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], **kwargs)
        processes.append(process)
        return process
    transport = HttpTransport("example", factory)
    results = {}
    threads = [threading.Thread(target=lambda key=key: results.update({key: transport.request("GET", "/addons/self/info", scope=key)})) for key in ("a", "b")]
    for thread in threads:
        thread.start()
    import time
    deadline = time.monotonic() + 2
    while len(processes) < 2 and time.monotonic() < deadline:
        time.sleep(.005)
    transport.cancel_scope("a")
    threads[0].join(1)
    assert not threads[0].is_alive() and threads[1].is_alive()
    transport.close()
    threads[1].join(2)
    assert not threads[1].is_alive()


def test_shutdown_stops_web_discovery_recovery_before_interface(tmp_path):
    ctl, _, _ = controller(tmp_path)
    events = []
    original_discovery = ctl.discovery.close
    ctl.discovery.close = lambda: (events.append("discovery"), original_discovery())
    class Service:
        def close(self, *, close_store):
            assert not close_store
            events.append("recovery")
    ctl.service = Service()
    ctl.close()
    events.append("interface")
    assert events == ["discovery", "recovery", "interface"]


def test_pause_fences_queued_radio_and_health_poll(tmp_path):
    from test_recovery_service import setup
    svc, clock, supervisor, mqtt, probe, store = setup(tmp_path)
    runtime = next(iter(svc.runtimes.values()))
    runtime.controls = supervisor.self_controls()[runtime.binding.key]
    supervisor.paused.add(runtime.binding.key)
    sent = []
    mqtt.request_health = lambda *args: sent.append("health")
    mqtt.request_reporting_read = lambda *args: sent.append("radio")
    svc._poll_authorized(runtime, 0)
    assert sent == []
    svc.close()

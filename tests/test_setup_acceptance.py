from dataclasses import replace
import pytest
from app.setup.model import Catalog, FieldValue
from app.setup.store import SetupStoreError
from app.manager import Status
from test_setup_runtime import controller, accept_one, candidate


def guided_two(tmp_path):
    ctl, fixture, clock = controller(tmp_path)
    snapshot, first = accept_one(ctl)
    snapshot, second = accept_one(ctl, candidate("172.31.254.3", "b_zigbee2mqtt", "0x0000000000000002", "floor/b"))
    snapshot = ctl.edit_broker({"mode": "manual", "server": "mqtt://broker.invalid"}, expected_revision=snapshot.revision)
    transition = ctl.prepare_transition("guided", expected_revision=snapshot.revision)
    assert ctl.commit_transition(transition.receipt)
    for record in (first, second):
        snapshot = ctl.control(record.network_id, managed=True, enabled=True, expected_revision=ctl.store.snapshot().revision)
    return ctl, fixture, clock, first, second


def test_two_guided_networks_a_returns_without_restarting_healthy_b(tmp_path):
    from app.recovery.service import RecoveryService
    from test_recovery_service import Supervisor, Mqtt, Probe, pump
    ctl, fixture, clock, a, b = guided_two(tmp_path)
    config = ctl.configuration()
    supervisor = Supervisor(config, clock)
    supervisor.self_controls = lambda: ctl.controls_for(config.bindings)
    supervisor.command_with_revision = lambda binding, kind, revision: ctl.guard_command(binding, revision, lambda: supervisor.command(binding, kind))
    mqtt = Mqtt(supervisor, clock)
    probe = Probe()
    probe.present = {"172.31.254.3"}
    service = RecoveryService(config, ctl.recovery_store, supervisor, mqtt, probe, ctl.journal, clock)
    ctl.service = service
    pump(service, clock, 240)
    assert supervisor.commands == [(b.state_key, "start")]
    probe.present.add("172.31.254.2")
    pump(service, clock, 240)
    assert supervisor.commands == [(b.state_key, "start"), (a.state_key, "start")]
    ctl.control(a.network_id, paused=True, expected_revision=ctl.store.snapshot().revision)
    supervisor.states[a.state_key] = "stopped"
    pump(service, clock, 300)
    assert len(supervisor.commands) == 2
    assert ctl.recovery_store.load(a.state_key).phase == "paused"
    ctl.close()


def test_month_of_retained_metadata_is_not_live_radio_evidence(tmp_path):
    ctl, _, clock, a, b = guided_two(tmp_path)
    clock.advance(31 * 86400)
    view = ctl.view()
    assert all(record["radio"] != "confirmed" for record in view.networks)
    assert all(ctl.recovery_store.command_count(record.state_key, 0) == 0 for record in (a, b))
    ctl.close()


def test_manual_override_and_pause_survive_rescan_and_restart(tmp_path):
    from test_setup_runtime import controller as reopen
    ctl, fixture, _, a, b = guided_two(tmp_path)
    snapshot = ctl.edit(a.network_id, {"name": {"mode": "manual", "value": "My network"}}, expected_revision=ctl.store.snapshot().revision)
    snapshot = ctl.control(a.network_id, paused=True, expected_revision=snapshot.revision)
    catalog = ctl.store.catalog()
    proposal = candidate("172.31.254.8")
    ctl.store.save_catalog(replace(catalog, candidates=(proposal,)), expected_revision=catalog.revision)
    ctl._adopt_discovery()
    options = fixture.options
    ctl.close()
    ctl, _, _ = reopen(tmp_path, options=options)
    record = next(r for r in ctl.store.snapshot().networks if r.network_id == a.network_id)
    assert record.fields["name"].value == "My network" and record.paused
    assert record.fields["ip"].value == "172.31.254.2" and record.fields["ip"].proposal == "172.31.254.8"
    ctl.close()


def test_corrupt_row_isolated_from_second_network_and_never_replaced(tmp_path):
    ctl, _, _, a, b = guided_two(tmp_path)
    ctl.store.db.execute("UPDATE networks SET payload=? WHERE network_id=?", ('{"bad":', a.network_id))
    ctl.store.db.commit()
    config = ctl.configuration()
    assert [binding.key for binding in config.bindings] == [b.state_key]
    assert list(ctl.controls_for(config.bindings)) == [b.state_key]
    snapshot = ctl.control(b.network_id, paused=True, expected_revision=ctl.store.snapshot().revision)
    assert ctl.store.db.execute("SELECT payload FROM networks WHERE network_id=?", (a.network_id,)).fetchone()[0] == '{"bad":'
    ctl.close()


def test_full_setup_database_keeps_pause_and_recovery_budget(tmp_path):
    from app.recovery.model import Action
    ctl, _, _, a, b = guided_two(tmp_path)
    snapshot = ctl.control(a.network_id, paused=True, expected_revision=ctl.store.snapshot().revision)
    ctl.recovery_store.reserve(Action("start", a.state_key, "g"), 1000, "r")
    pages = ctl.store.db.execute("PRAGMA page_count").fetchone()[0]
    ctl.store.db.execute(f"PRAGMA max_page_count={pages}")
    rows = tuple(replace(candidate(slug=f"n{i}_zigbee2mqtt"), fields={"name": FieldValue("auto", "x" * 1000, "mqtt", 0, "found")}) for i in range(253))
    with pytest.raises(SetupStoreError):
        ctl.store.save_catalog(Catalog(candidates=rows), expected_revision=ctl.store.catalog().revision)
    assert ctl.store.snapshot() == snapshot
    assert ctl.recovery_store.command_count(a.state_key, 0) == 1
    ctl.close()


def test_incomplete_network_cannot_enable_management(tmp_path):
    ctl, _, _ = controller(tmp_path)
    snapshot, record = accept_one(ctl, replace(candidate(ieee=""), match_kind="proposed"))
    with pytest.raises(ValueError):
        ctl.control(record.network_id, managed=True, expected_revision=snapshot.revision)
    ctl.close()

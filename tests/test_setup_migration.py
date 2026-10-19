from copy import deepcopy
from dataclasses import replace
import pytest
from app.recovery.model import Action
from test_setup_runtime import controller, accept_one
from test_recovery_settings import config, raw_record


def legacy_options():
    return {"parent": "auto", "address": "172.31.254.1/24", "coordinators": [{"name": "A", "ip": "172.31.254.2"}],
            "recovery": config([dict(raw_record(), paused=True)])}


def test_legacy_to_guided_preserves_controls_pause_receipts_and_quota(tmp_path):
    ctl, fixture, _ = controller(tmp_path, options=legacy_options())
    ctl.recovery_store.reserve(Action("start", "172.31.254.2", "g"), 1000, "r")
    transition = ctl.prepare_transition("guided", expected_revision=0)
    assert not ctl.controls_for(ctl.configuration().bindings)
    assert ctl.commit_transition(transition.receipt)
    snapshot = ctl.store.snapshot()
    network = snapshot.networks[0]
    assert network.state_key == "172.31.254.2" and network.managed and network.paused
    assert ctl.recovery_store.command_count(network.state_key, 0) == 1
    assert ctl.recovery_store.pending(network.state_key) is not None
    ctl.close()
    ctl, _, _ = controller(tmp_path, options=fixture.options)
    assert ctl.view().mode == "guided" and ctl.store.snapshot().networks[0].paused
    ctl.close()


@pytest.mark.parametrize("phase", ["prepared", "options_written", "verified"])
def test_transition_crash_at_every_phase_never_runs_both_sources(tmp_path, phase):
    ctl, fixture, _ = controller(tmp_path, options=legacy_options())
    transition = ctl.prepare_transition("guided", expected_revision=0)
    if phase != "prepared":
        assert ctl.commit_transition(transition.receipt)
        ctl.store.save_transition(replace(ctl.store.transition(), phase=phase))
    options = deepcopy(fixture.options)
    ctl.close()
    ctl, _, _ = controller(tmp_path, options=options)
    assert ctl.recovery_store.command_count("172.31.254.2", 0) == 0
    if phase == "prepared":
        assert not ctl.controls_for(ctl.configuration().bindings)
    else:
        assert ctl.view().mode == "guided"
    ctl.close()


def test_guided_to_legacy_requires_explicit_safe_resume(tmp_path):
    ctl, fixture, _ = controller(tmp_path, options=legacy_options())
    transition = ctl.prepare_transition("guided", expected_revision=0)
    assert ctl.commit_transition(transition.receipt)
    transition = ctl.prepare_transition("legacy", expected_revision=ctl.store.snapshot().revision)
    assert ctl.commit_transition(transition.receipt)
    assert all(not r["managed"] and r["paused"] for r in fixture.options["recovery"]["networks"])
    assert not any(c.managed for c in ctl.controls_for(ctl.configuration().bindings).values())
    ctl.close()

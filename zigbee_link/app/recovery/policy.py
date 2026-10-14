"""Pure recovery policy. An unknown observation never authorizes a restart."""
from dataclasses import replace
from .model import Action, Binding, Budget, Decision, Observation, RecoveryState

BACKOFF = (60, 300, 900, 3600)


def evaluate(binding: Binding, state: RecoveryState, obs: Observation, budget: Budget, now: float) -> Decision:
    def result(phase, reason, action=None, **changes):
        updated = replace(state, phase=phase, **changes)
        return Decision(updated, action, reason, (reason,) if state.phase != phase else ())

    controls = obs.controls
    if controls is None or now - controls.observed_at > 20 or now < controls.observed_at:
        return result("dependency", "permission_unknown")
    if not controls.managed:
        return result("observing", "disabled")
    if controls.paused:
        return result("paused", "maintenance")
    if obs.configuration_error:
        return result("blocked", "configuration_error")
    if obs.conflict:
        return result("blocked", "address_conflict", successes=0, return_since=None)
    if obs.identity_match is False:
        return result("blocked", "identity_mismatch")
    if not obs.network_ready:
        return result("dependency", "network_unavailable", successes=0, return_since=None, stable_since=None)
    if not obs.supervisor.available:
        return result("dependency", "supervisor_unavailable")
    if not obs.supervisor.binding_valid:
        return result("blocked", "binding_invalid")
    if not obs.mqtt_connected:
        return result("dependency", "mqtt_unavailable", stable_since=None)
    if state.pending_action:
        return result("checking", "command_pending")
    if obs.supervisor.busy:
        return result("dependency", "app_busy")
    if obs.present is None or now - obs.at > 45 or now < obs.at:
        return result("dependency", "measurement_unknown", stable_since=None)
    if state.generation != obs.generation:
        state = replace(state, generation=obs.generation, misses=0, successes=0,
                        return_since=None, stable_since=None, health_misses=0,
                        last_observation=-1, last_health_sequence=-1, run_seen_at=now)
    if obs.at != state.last_observation:
        state = replace(state, last_observation=obs.at,
                        misses=state.misses + 1 if obs.present is False else 0,
                        successes=state.successes + 1 if obs.present else 0,
                        return_since=(state.return_since if state.return_since is not None else now) if obs.present else None,
                        stable_since=state.stable_since if obs.present else None)
    if obs.health_sequence != state.last_health_sequence:
        state = replace(state, last_health_sequence=obs.health_sequence,
                        health_misses=(state.health_misses + 1 if obs.mqtt_health is False else 0))
    if not obs.present:
        return result("absent" if state.misses >= 3 else "suspect", "coordinator_absent", stable_since=None)
    if state.successes < 3 or state.return_since is None or now - state.return_since < 60:
        return result("returning", "return_grace")
    if obs.supervisor.state == "started" and obs.mqtt_health is True:
        stable = state.stable_since if state.stable_since is not None else now
        phase = "confirmed" if obs.identity_match is True and obs.radio is True else "degraded" if obs.radio is False else "unconfirmed"
        return result(phase, "radio_confirmed" if phase == "confirmed" else "radio_not_confirmed",
                      stable_since=stable, attempt_stage=0 if now - stable >= 300 else state.attempt_stage)
    if obs.supervisor.state not in ("started", "stopped", "error"):
        return result("dependency", "app_state_unknown")
    if not budget.clock_trusted:
        return result("waiting", "clock_untrusted")
    if budget.hour_count >= 4 or budget.day_count >= 10:
        return result("waiting", "action_budget")
    if now < state.next_attempt:
        return result("waiting", "action_backoff")
    if obs.supervisor.state == "started":
        if state.run_seen_at is None or now - state.run_seen_at < 180 or state.health_misses < 3:
            return result("checking", "startup_or_health_grace")
        kind = "restart"
    else:
        kind = "start"
    delay = BACKOFF[min(state.attempt_stage, len(BACKOFF) - 1)]
    return result("starting", "recover_" + kind, Action(kind, binding.key, obs.generation),
                  next_attempt=now + delay, attempt_stage=min(state.attempt_stage + 1, 3), stable_since=None)

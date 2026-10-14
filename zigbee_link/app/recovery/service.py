"""Independent, bounded recovery workers; the network manager remains the writer."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from ipaddress import IPv4Address
import logging
import math
import time
import uuid

from .journal import SafeEvent
from .model import AppObservation, Action, Budget, Observation, RecoveryState
from .policy import evaluate
from .radio import RadioVerifier
from .store import StoreError

LOG = logging.getLogger("zigbee-link")
PHASE_NAMES = {"observing": "наблюдение", "paused": "пауза обслуживания", "dependency": "ожидание зависимостей",
               "blocked": "восстановление заблокировано", "checking": "проверка приложения", "suspect": "проверка отсутствия",
               "absent": "координатор отсутствует", "returning": "проверка возвращения", "waiting": "ожидание повторной попытки",
               "starting": "запуск приложения", "confirmed": "радиообмен подтверждён", "degraded": "радиопроверка не прошла",
               "unconfirmed": "приложение отвечает, радиообмен не подтверждён"}


class SystemClock:
    monotonic = staticmethod(time.monotonic)
    time = staticmethod(time.time)


@dataclass
class Runtime:
    binding: object
    app: AppObservation = AppObservation()
    controls: object = None
    next_observe: float = 0
    next_health: float = 0
    next_radio: float = 0
    reference_index: int = 0
    reference_times: object = None
    last_phase: str = ""


class RecoveryService:
    def __init__(self, config, store, supervisor, mqtt, probe, journal, clock=None, cancelled=lambda: False):
        self.config, self.store, self.supervisor, self.mqtt = config, store, supervisor, mqtt
        self.probe, self.journal = probe, journal
        self.clock, self.cancelled = clock or SystemClock(), cancelled
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="zigbee-recovery")
        self.futures = {}
        self.runtimes = {b.key: Runtime(b, reference_times={}) for b in config.bindings}
        self.closed = False
        self.store_available = True
        self.verifier = RadioVerifier()
        self.arp_at = -100
        self.arp = {}
        self.next_arp = 0
        self.network_ready = False
        mono, wall = self.clock.monotonic(), self.clock.time()
        saved = store.meta("logical_utc")
        old = float(saved) if saved is not None else wall
        if not math.isfinite(old):
            raise StoreError("Повреждено время состояния восстановления")
        # Credit at most one hour of unobserved downtime; never reset daily quotas
        # simply because the host wall clock jumped forward while we were off.
        self.logical_utc = max(old, min(wall, old + 3600))
        self.last_mono, self.last_wall = mono, wall
        self.clock_guard = mono + (60 if saved is not None else 0)
        for key in self.runtimes:
            state = store.load(key)
            remaining = max(60, min(3600, state.next_attempt - state.last_observation)) if state.attempt_stage else 0
            store.save(key, replace(state, successes=0, misses=0, return_since=None, stable_since=None,
                                    last_observation=-1, generation="", next_attempt=mono + remaining))

    def _emit(self, key, state, code, action="", outcome="", facts=None):
        runtime = self.runtimes[key]
        self.journal.emit(SafeEvent(code, key, phase=state.phase, previous=runtime.last_phase,
                                   incident=state.incident_id, action=action, outcome=outcome, facts=facts or {}))
        if runtime.last_phase != state.phase:
            LOG.info("Сеть %s: %s (%s)", key, PHASE_NAMES.get(state.phase, state.phase), code)
            runtime.last_phase = state.phase

    def _observe(self, binding):
        controls = self.supervisor.self_controls()
        return controls.get(binding.key), self.supervisor.observe(binding)

    def _dispatch(self, binding, action, revision):
        receipt = None
        try:
            controls = self.supervisor.self_controls().get(binding.key)
            app = self.supervisor.observe(binding)
            if not self._authorized(controls, revision, app):
                return None, "cancelled"
            receipt = self.store.reserve(action, self.logical_utc, revision, run_id=app.run_id)
            for code in self.supervisor.diagnose(binding):
                self._emit(binding.key, self.store.load(binding.key), code)
            app = self.supervisor.observe(binding)
            controls = self.supervisor.self_controls().get(binding.key)
            if not self._authorized(controls, revision, app) or (action.kind == "start" and app.state not in ("stopped", "error")):
                self.store.resolve(receipt, "cancelled", app.run_id)
                return receipt, "cancelled"
            current = self.mqtt.snapshot(binding.key, self.clock.monotonic())
            target = IPv4Address(binding.ip)
            presence = self.probe((target,))
            if not current.connected or not self.network_ready or not presence.complete or len(presence.responders.get(target, set())) != 1:
                self.store.resolve(receipt, "cancelled", app.run_id)
                return receipt, "dependency_changed"
            # ARP may have waited for the common packet budget; refresh permission
            # once more after that wait and immediately before the command.
            controls = self.supervisor.self_controls().get(binding.key)
            if not self._authorized(controls, revision, app) or not self.mqtt.snapshot(binding.key, self.clock.monotonic()).connected:
                self.store.resolve(receipt, "cancelled", app.run_id)
                return receipt, "cancelled"
            if app.state == "started" and current.health is True:
                self.store.resolve(receipt, "cancelled", app.run_id)
                return receipt, "already_healthy"
            # Prove durable storage is still writable immediately before sending.
            self.store.meta("last_authorized", str(self.logical_utc))
            if self.closed or self.cancelled() or not self.store_available:
                self.store.resolve(receipt, "cancelled", app.run_id)
                return receipt, "cancelled"
            self.mqtt.invalidate(binding.key)
            result = self.supervisor.command(binding, action.kind)
            # Old process replies during the HTTP request cannot resolve its outcome.
            self.mqtt.invalidate_health(binding.key)
            return receipt, result.reason
        except StoreError:
            self.store_available = False
            return receipt, "storage_unavailable"
        except (OSError, ValueError, RuntimeError):
            self.mqtt.invalidate(binding.key)
            return receipt, "outcome_unknown"

    def _authorized(self, controls, revision, app):
        now = self.clock.monotonic()
        return bool(not self.closed and not self.cancelled() and self.store_available and controls is not None
                    and controls.managed and not controls.paused and controls.revision == revision
                    and 0 <= now - controls.observed_at <= 20 and app.available
                    and app.binding_valid and not app.busy and app.state in ("started", "stopped", "error"))

    def _collect(self, now):
        for key, (future, kind) in list(self.futures.items()):
            if not future.done():
                continue
            del self.futures[key]
            try:
                value = future.result()
                if kind == "arp":
                    self.arp_at = now
                    self.arp = {b.key: (value.responders.get(IPv4Address(b.ip), set()) if value.complete else None)
                                for b in self.config.bindings}
                elif kind == "observe":
                    runtime = self.runtimes[key]
                    runtime.controls, runtime.app = value
                    runtime.next_observe = now + 15
                elif kind == "command":
                    runtime = self.runtimes[key]
                    runtime.controls, runtime.app = None, AppObservation()
                    runtime.next_observe = now
                    runtime.next_health = now
                    state = self.store.load(key)
                    self._emit(key, state, "command_result", outcome=value[1])
            except StoreError:
                self.store_available = False
            except (OSError, ValueError, RuntimeError):
                if kind == "arp":
                    self.arp, self.arp_at = {}, now
                elif key in self.runtimes:
                    self.runtimes[key].controls = None
                    self.runtimes[key].app = AppObservation()
                    self.runtimes[key].next_observe = now + 15

    def _mqtt_poll(self, runtime, now):
        controls = runtime.controls
        if controls is None or not controls.managed or controls.paused or not 0 <= now - controls.observed_at <= 20:
            return
        if runtime.binding.key in self.futures and self.futures[runtime.binding.key][1] == "command":
            return
        current = self.mqtt.snapshot(runtime.binding.key, now)
        if not current.connected:
            return
        if now >= runtime.next_health:
            self.mqtt.request_health(runtime.binding.key, now)
            runtime.next_health = now + 60
        if runtime.app.state != "started" or current.health is not True or current.identity_match is not True:
            return
        references = runtime.binding.references
        if references and now >= runtime.next_radio:
            for _ in references:
                reference = references[runtime.reference_index % len(references)]
                runtime.reference_index += 1
                if now - runtime.reference_times.get(reference, float("-inf")) >= 300:
                    self.mqtt.request_reporting_read(runtime.binding.key, reference, now)
                    runtime.reference_times[reference] = now
                    runtime.next_radio = now + 30
                    break

    def _process(self, runtime, now, network_ready):
        key = runtime.binding.key
        self._mqtt_poll(runtime, now)
        mqtt = self.mqtt.snapshot(key, now)
        radio = None
        for reply in mqtt.radio_replies:
            if reply.reference not in runtime.binding.references:
                continue
            proof = self.verifier.validate(reply.reference, reply, mqtt.generation, now)
            if proof.confirmed:
                radio = True
                runtime.next_radio = max(runtime.next_radio, proof.expires_at)
                break
            radio = False
        responders = self.arp.get(key)
        state = self.store.load(key)
        pending = self.store.pending(key)
        if pending and key not in self.futures and runtime.app.available and not runtime.app.busy and mqtt.connected:
            if runtime.app.state == "started" and mqtt.health is True:
                self.store.resolve(pending["receipt"], "confirmed", runtime.app.run_id)
                state = self.store.load(key)
            elif self.logical_utc - pending["created"] >= 180 and (runtime.app.state in ("stopped", "error") or runtime.app.state == "started" and mqtt.health is False):
                self.store.resolve(pending["receipt"], "failed", runtime.app.run_id)
                state = self.store.load(key)
        observation = Observation(self.arp_at, network_ready, None if responders is None else bool(responders),
                                  bool(responders and len(responders) > 1), runtime.app, runtime.controls,
                                  mqtt.connected, mqtt.health, mqtt.identity_match, radio, mqtt.generation,
                                  health_sequence=mqtt.health_sequence)
        budget = Budget(self.store.command_count(key, self.logical_utc - 3600),
                        self.store.command_count(key, self.logical_utc - 86400), now >= self.clock_guard)
        decision = evaluate(runtime.binding, state, observation, budget, now)
        if decision.action and (key in self.futures or len(self.futures) >= 4):
            decision = replace(decision, action=None, reason="scheduler_busy",
                               state=replace(decision.state, phase="waiting", next_attempt=state.next_attempt,
                                             attempt_stage=state.attempt_stage))
        next_state = decision.state
        if next_state.phase in ("suspect", "absent", "starting", "blocked") and not next_state.incident_id:
            next_state = replace(next_state, incident_id=uuid.uuid4().hex)
        self.store.save(key, next_state)
        self._emit(key, next_state, decision.reason, facts={"misses": next_state.misses,
                   "successes": next_state.successes, "hour_count": budget.hour_count, "day_count": budget.day_count})
        if next_state.incident_id and next_state.stable_since is not None and now - next_state.stable_since >= 300 and next_state.phase in ("confirmed", "unconfirmed", "degraded"):
            self.store.finish_incident(key, "radio_confirmed" if next_state.phase == "confirmed" else "application_only")
        if decision.action and key not in self.futures and len(self.futures) < 4:
            self.futures[key] = (self.pool.submit(self._dispatch, runtime.binding, decision.action,
                                                runtime.controls.revision), "command")

    def tick(self, network_status):
        if self.closed or self.cancelled():
            return
        now, wall = self.clock.monotonic(), self.clock.time()
        elapsed = max(0, now - self.last_mono)
        if now < self.last_mono or abs((wall - self.last_wall) - elapsed) > 10:
            self.clock_guard = now + 60
        self.logical_utc += elapsed
        self.last_mono, self.last_wall = now, wall
        self._collect(now)
        network_ready = network_status.state == "ready"
        self.network_ready = network_ready
        if not network_ready:
            self.arp = {}
        if network_ready and now >= self.next_arp and "__arp__" not in self.futures and len(self.futures) < 4:
            targets = tuple(IPv4Address(b.ip) for b in self.config.bindings)
            self.futures["__arp__"] = (self.pool.submit(self.probe, targets), "arp")
            self.next_arp = now + 30
        try:
            if self.store_available:
                self.store.meta("logical_utc", str(self.logical_utc))
                for runtime in self.runtimes.values():
                    self._process(runtime, now, network_ready)
        except StoreError:
            self.store_available = False
            LOG.error("Состояние восстановления недоступно; новые команды запрещены")
        # Observe even if storage is unavailable; fair scheduling prevents one slow
        # network from occupying every slot or starving later bindings.
        for runtime in sorted(self.runtimes.values(), key=lambda r: r.next_observe):
            key = runtime.binding.key
            if len(self.futures) >= 4:
                break
            if now >= runtime.next_observe and key not in self.futures:
                self.futures[key] = (self.pool.submit(self._observe, runtime.binding), "observe")
        if int(now) % 3600 == 0 and self.store_available:
            try:
                self.store.prune(self.logical_utc)
            except StoreError:
                self.store_available = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        for future, kind in self.futures.values():
            future.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.mqtt.stop()
        self.store.close()

"""One durable configuration/permission authority for discovery, UI and recovery."""
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha256
from ipaddress import IPv4Address
import logging
import os
from pathlib import Path
import threading
import uuid

from ..config import Coordinator
from ..recovery.journal import EventJournal, SafeEvent
from ..recovery.model import Binding, Controls, Reference
from ..recovery.service import SystemClock
from ..recovery.settings import RecoveryConfiguration, MqttSettings, parse_recovery, _mqtt, fingerprint
from ..recovery.store import RecoveryStore
from ..recovery.supervisor import HttpTransport, CommandOutcome
from .model import (BrokerConnection, BrokerRecord, FieldValue, NetworkRecord,
                    RuntimeView, SupervisorCapabilities, Transition)
from .matching import merge_suggestions
from .secrets import SecretStore
from .service import DiscoveryService
from .store import SetupStore, SetupStoreError, RevisionConflict
from .supervisor import SupervisorCatalogReader, DiscoverySourceError, options_digest
from .validation import FIELDS, PINNED, validate_network, select_configuration_mode, configuration_readiness

LOG = logging.getLogger("zigbee-link")
NONBLOCKING = {"radio_reference_unavailable"}


class SetupController:
    def __init__(self, options, network_settings, identity, probe, data_dir: Path, stopped, *, reader=None, clock=None):
        self.lock = threading.RLock()
        self.options = deepcopy(options)
        self.settings, self.identity, self.probe, self.stopped = network_settings, identity, probe, stopped
        self.clock = clock or SystemClock()
        self.data_dir = data_dir
        self.store = SetupStore(data_dir / "setup.sqlite")
        self.secrets = SecretStore(data_dir / "setup-secrets")
        self.recovery_store = RecoveryStore(data_dir / "recovery.sqlite")
        self.journal = EventJournal(data_dir / "diagnostics")
        self.reader = reader or SupervisorCatalogReader(HttpTransport(os.environ.get("SUPERVISOR_TOKEN", "")))
        from .mqtt import MetadataCollector
        self.discovery = DiscoveryService(self.reader, self.store, MetadataCollector, clock=self.clock.monotonic,
                                          subnet=self.settings.address.network)
        self.mode = select_configuration_mode(options)
        self.capabilities = SupervisorCapabilities()
        self.service = None
        self.web = None
        self.next_web = 0
        self.closed = False
        self.last_catalog = -1
        self.next_capabilities = 0
        self.network_status = None
        self.last_error = ""
        self.applied_config = None
        self._recover_transition()
        self.secrets.collect({s.broker.secret_ref for s in (self.store.snapshot(),) if s.broker and s.broker.secret_ref})

    def _event(self, code, *, source="auto", outcome=None):
        snapshot = self.store.snapshot()
        self.journal.emit(SafeEvent(code, "setup", action="source_" + source,
                          outcome=outcome or "mode_" + self.mode,
                          facts={"revision": snapshot.revision, "network_count": len(snapshot.networks),
                                 "candidate_count": len(self.store.catalog().candidates)}))

    def _frozen(self):
        transition = self.store.transition()
        return bool(transition and transition.phase != "verified")

    def _snapshot(self, expected_revision):
        if self.closed or self._frozen():
            raise ValueError("transition_pending")
        snapshot = self.store.snapshot()
        if type(expected_revision) is not int or snapshot.revision != expected_revision:
            raise RevisionConflict("setup_revision_conflict")
        return snapshot

    def _valid(self, record):
        issues = validate_network(replace(record, issues=()), self.settings.address.network)
        if record.fields.get("ip") and record.fields["ip"].value == str(self.settings.address.ip):
            issues += ("host_address_conflict",)
        return tuple(dict.fromkeys((*issues, *(i for i in record.issues if i not in NONBLOCKING))))

    def _check_records(self, snapshot):
        seen = {key: set() for key in ("ip", "addon_slug", "base_topic", "coordinator_ieee")}
        for record in snapshot.networks:
            if record.tombstoned or not record.accepted or "record_corrupt" in record.issues:
                continue
            if self._valid(record):
                raise ValueError("invalid_network")
            for key in seen:
                value = record.fields[key].value
                if value in seen[key]:
                    raise ValueError("duplicate_network")
                seen[key].add(value)

    def _save(self, snapshot, expected_revision, *, source="manual", code="setup_edit"):
        self._check_records(snapshot)
        saved = self.store.save(snapshot, expected_revision=expected_revision)
        self._event(code, source=source)
        return saved

    def edit(self, network_id, patch, *, expected_revision, confirm_identity=False):
        with self.lock, self.store.transaction(preserve_validation=True):
            snapshot = self._snapshot(expected_revision)
            if not isinstance(patch, dict) or not patch or set(patch) - FIELDS - {"tombstoned"} or type(confirm_identity) is not bool:
                raise ValueError("invalid_patch")
            record = next((r for r in snapshot.networks if r.network_id == network_id and not r.tombstoned), None)
            if record is None or "record_corrupt" in record.issues:
                raise ValueError("unknown_network")
            if "tombstoned" in patch:
                if patch != {"tombstoned": True}:
                    raise ValueError("invalid_patch")
                edited = replace(record, managed=False, paused=True, tombstoned=True)
            else:
                fields = dict(record.fields)
                for name, change in patch.items():
                    if not isinstance(change, dict) or set(change) - {"mode", "value"} or change.get("mode") not in ("auto", "manual"):
                        raise ValueError("invalid_field")
                    old = fields.get(name)
                    if "value" in change:
                        value = deepcopy(change["value"])
                    elif old:
                        value = old.proposal if change["mode"] == "auto" and old.proposal is not None else old.value
                    else:
                        raise ValueError("missing_field")
                    if name in PINNED and old and value != old.value and not confirm_identity:
                        raise ValueError("identity_confirmation_required")
                    fields[name] = FieldValue(change["mode"], value, "manual" if change["mode"] == "manual" else (old.source if old else "manual"),
                                              self.clock.time(), "accepted")
                edited = replace(record, fields=fields, issues=())
                if confirm_identity and snapshot.broker:
                    # Alias mutation and settings CAS are in the same transaction.
                    bound = self.store.bind_alias(record.network_id,
                        (snapshot.broker.identity, fields["coordinator_ieee"].value),
                        addon_slug=fields["addon_slug"].value, expected_revision=snapshot.revision)
                    snapshot, expected_revision = bound, bound.revision
            records = tuple(edited if r.network_id == network_id else r for r in snapshot.networks)
            return self._save(replace(snapshot, networks=records), expected_revision)

    def edit_broker(self, patch, *, expected_revision):
        with self.lock:
            snapshot = self._snapshot(expected_revision)
            if not isinstance(patch, dict) or set(patch) - {"mode", "server", "username", "password", "clear_password"}:
                raise ValueError("invalid_broker")
            if patch.get("mode") == "auto":
                if set(patch) != {"mode"}:
                    raise ValueError("invalid_broker")
                connection = self.discovery.connection
                if not connection or connection.record.mode != "auto":
                    connection = self.reader.mqtt_service()
                if connection is None:
                    raise ValueError("mqtt_unconfigured")
                broker = connection.record
                self.discovery.set_connection(None)
            elif patch.get("mode", "manual") == "manual":
                old = snapshot.broker
                same_server = old and patch.get("server", old.server) == old.server
                previous = self.secrets.read(old.secret_ref) if same_server and old.mode == "manual" and old.secret_ref else ("", "")
                if type(patch.get("clear_password", False)) is not bool:
                    raise ValueError("invalid_broker")
                settings = _mqtt({"server": patch.get("server", old.server if old else ""),
                                  "username": patch.get("username", previous[0]),
                                  "password": "" if patch.get("clear_password") else (patch.get("password") or previous[1])})
                secret_ref = self.secrets.write(settings.username, settings.password)
                identity = "manual:" + sha256(settings.server.encode()).hexdigest()
                broker = BrokerRecord(identity, "manual", settings.server, secret_ref=secret_ref)
                connection = BrokerConnection(broker, settings)
                self.discovery.set_connection(connection)
            else:
                raise ValueError("invalid_broker")
            # Explicit broker edits never copy automatic credentials to another identity.
            return self._save(replace(snapshot, broker=broker), expected_revision, code="setup_broker")

    def control(self, network_id, *, managed=None, paused=None, enabled=None, expected_revision):
        with self.lock:
            snapshot = self._snapshot(expected_revision)
            if all(v is None for v in (managed, paused, enabled)) or any(v is not None and type(v) is not bool for v in (managed, paused, enabled)):
                raise ValueError("invalid_controls")
            if network_id is None:
                if managed is not None or paused is not None:
                    raise ValueError("network_required")
            elif not any(r.network_id == network_id and not r.tombstoned for r in snapshot.networks):
                raise ValueError("unknown_network")
            records = tuple(replace(r, managed=r.managed if managed is None else managed,
                                    paused=r.paused if paused is None else paused) if r.network_id == network_id else r
                            for r in snapshot.networks)
            return self._save(replace(snapshot, networks=records, enabled=snapshot.enabled if enabled is None else enabled), expected_revision, code="setup_control")

    def accept(self, candidate_id, *, catalog_revision, expected_revision):
        with self.lock, self.store.transaction(preserve_validation=True):
            snapshot = self._snapshot(expected_revision)
            catalog = self.store.catalog()
            if type(catalog_revision) is not int or catalog.revision != catalog_revision:
                raise RevisionConflict("catalog_revision_conflict")
            candidate = next((c for c in catalog.candidates if c.candidate_id == candidate_id), None)
            if candidate is None or candidate.match_kind != "matched" or set(candidate.issues) - NONBLOCKING:
                raise ValueError("candidate_not_ready")
            fields = deepcopy(candidate.fields)
            trial = NetworkRecord("trial", "trial", fields, False, False, True)
            if self._valid(trial):
                raise ValueError("candidate_not_ready")
            broker_id = snapshot.broker.identity if snapshot.broker else "unconfigured"
            network_id, state_key = self.store.state_key((broker_id, fields["coordinator_ieee"].value), addon_slug=fields["addon_slug"].value)
            old = next((r for r in snapshot.networks if r.network_id == network_id), None)
            if old and not old.tombstoned:
                raise ValueError("network_already_accepted")
            record = NetworkRecord(network_id, state_key, fields, False, False, True)
            records = tuple(r for r in snapshot.networks if r.network_id != network_id) + (record,)
            return self._save(replace(snapshot, networks=records), expected_revision, code="setup_accept")

    def _import_legacy(self, snapshot):
        config = parse_recovery(self.options.get("recovery", {}), self.settings)
        broker = snapshot.broker
        if config.mqtt and not broker:
            secret = self.secrets.write(config.mqtt.username, config.mqtt.password)
            broker = BrokerRecord("manual:" + sha256(config.mqtt.server.encode()).hexdigest(), "manual", config.mqtt.server, secret_ref=secret)
        records = list(snapshot.networks)
        for binding in config.bindings:
            network_id, state_key = self.store.state_key(((broker.identity if broker else "unconfigured"), binding.coordinator_ieee),
                                                        legacy_key=binding.key, addon_slug=binding.addon_slug)
            control = config.controls[binding.key]
            values = dict(name=next((c.name for c in self.settings.coordinators if str(c.address) == binding.ip), binding.addon_slug),
                          ip=binding.ip, serial_port=6638, addon_slug=binding.addon_slug, base_topic=binding.base_topic,
                          coordinator_ieee=binding.coordinator_ieee, references=[asdict(r) for r in binding.references])
            record = NetworkRecord(network_id, state_key, {k: FieldValue("manual", v, "legacy", self.clock.time(), "accepted") for k, v in values.items()},
                                   control.managed, control.paused, True)
            records = [r for r in records if r.network_id != network_id] + [record]
        return self.store.save(replace(snapshot, enabled=config.enabled, broker=broker, networks=tuple(records)), expected_revision=snapshot.revision)

    def _target_options(self, target):
        options = deepcopy(self.options)
        options["configuration_mode"] = target
        if target == "legacy":
            recovery = deepcopy(options.get("recovery", {}))
            for record in recovery.get("networks", []):
                if isinstance(record, dict):
                    record.update(managed=False, paused=True)
            options["recovery"] = recovery
        return options

    def prepare_transition(self, target_mode, *, expected_revision):
        with self.lock, self.store.transaction(preserve_validation=True):
            snapshot = self._snapshot(expected_revision)
            actual = self.reader.self_options()
            if select_configuration_mode(actual) != self.mode or target_mode not in ("legacy", "guided") or target_mode == self.mode:
                raise ValueError("mode_conflict")
            self.options = actual
            if target_mode == "guided":
                snapshot = self._import_legacy(snapshot)
            transition = Transition(uuid.uuid4().hex, self.mode, target_mode, options_digest(actual), snapshot.revision, "prepared")
            self.store._put("transition_target_digest", options_digest(self._target_options(target_mode)))
            self.store.save_transition(transition)
            self._event("setup_migration", outcome="prepared")
            return transition

    def _recover_transition(self):
        transition = self.store.transition()
        if transition and transition.phase in ("options_written", "blocked"):
            try:
                self._verify_transition(transition, self.reader.self_options())
            except (DiscoverySourceError, ValueError):
                pass

    def _verify_transition(self, transition, actual):
        with self.store.transaction():
            expected = self.store._meta("transition_target_digest")
            if options_digest(actual) != expected or select_configuration_mode(actual) != transition.target_mode or self.store.snapshot().revision != transition.setup_revision:
                return False
            self.options, self.mode = actual, transition.target_mode
            self.store.save_transition(replace(transition, phase="verified"))
            self._event("setup_migration", outcome="verified")
            return True

    def commit_transition(self, receipt):
        with self.lock:
            transition = self.store.transition()
            if not transition or transition.receipt != receipt:
                raise ValueError("unknown_transition")
            if transition.phase == "verified":
                return True
            try:
                actual = self.reader.self_options()
                if self._verify_transition(transition, actual):
                    return True
                if transition.phase != "prepared" or options_digest(actual) != transition.source_digest:
                    self.store.save_transition(replace(transition, phase="blocked"))
                    return False
                # Persist the uncertain-write fence before admitting the HTTP write.
                self.store.save_transition(replace(transition, phase="options_written"))
                target = self._target_options(transition.target_mode)
                self.reader.set_mode(transition.target_mode, expected_digest=transition.source_digest,
                                     legacy_options={"recovery": target["recovery"]} if transition.target_mode == "legacy" else None)
                return self._verify_transition(transition, self.reader.self_options())
            except (DiscoverySourceError, ValueError):
                return False

    def _connection(self, snapshot):
        broker = snapshot.broker
        if not broker:
            return None
        if broker.mode == "manual":
            credentials = self.secrets.read(broker.secret_ref)
            return BrokerConnection(broker, MqttSettings(broker.server, *credentials))
        connection = self.discovery.connection
        return connection if connection and connection.record.identity == broker.identity else None

    def configuration(self):
        with self.lock:
            if self.mode == "legacy":
                return parse_recovery(self.options.get("recovery", {}), self.settings)
            snapshot = self.store.snapshot()
            bindings, controls, errors = [], {}, {}
            for record in snapshot.networks:
                if not record.accepted or record.tombstoned:
                    continue
                issues = self._valid(record)
                if issues:
                    errors[record.state_key] = "configuration_error"
                    continue
                values = {k: f.value for k, f in record.fields.items()}
                binding = Binding(record.state_key, values["ip"], values["addon_slug"], values["base_topic"], values["coordinator_ieee"],
                                  tuple(Reference(**ref) for ref in values.get("references", ())))
                bindings.append(binding)
                revision = f"guided:{snapshot.revision}:{fingerprint(binding)}"
                controls[binding.key] = Controls(snapshot.enabled and record.managed, record.paused, revision)
            # A corrupt/conflicting row cannot grant command rights to its neighbours.
            duplicate_keys = set()
            for name in ("ip", "addon_slug", "base_topic", "coordinator_ieee"):
                groups = {}
                for binding in bindings:
                    groups.setdefault(getattr(binding, name), []).append(binding.key)
                duplicate_keys.update(k for group in groups.values() if len(group) > 1 for k in group)
            bindings = tuple(b for b in bindings if b.key not in duplicate_keys)
            connection = self._connection(snapshot)
            return RecoveryConfiguration(snapshot.enabled, bindings, {b.key: controls[b.key] for b in bindings}, connection.settings if connection else None, errors)

    def controls_for(self, bindings):
        with self.lock:
            try:
                if self.closed or self.stopped.is_set() or self._frozen():
                    return {}
                actual = self.reader.self_options()
                if select_configuration_mode(actual) != self.mode:
                    return {}
                self.options = actual
                config = self.configuration()
                return {b.key: replace(config.controls[b.key], observed_at=self.clock.monotonic()) for b in bindings if b in config.bindings}
            except (OSError, ValueError, SetupStoreError, DiscoverySourceError):
                return {}

    def guard_command(self, binding, revision, send):
        # A pause that has returned to the user fences every later admission.
        with self.lock:
            control = self.controls_for((binding,)).get(binding.key)
            if not control or not control.managed or control.paused or control.revision != revision:
                return CommandOutcome(False, "cancelled")
            return send()

    def effective_settings(self):
        with self.lock:
            if self.mode != "guided":
                return self.settings
            snapshot = self.store.snapshot()
            coordinators = tuple(Coordinator(r.fields.get("name", FieldValue("auto", "Zigbee", "", 0, "")).value or "Zigbee",
                                             IPv4Address(r.fields["ip"].value)) for r in snapshot.networks
                                 if r.accepted and not r.tombstoned and not self._valid(r))
            return replace(self.settings, coordinators=coordinators)

    def request_scan(self):
        with self.lock:
            started = self.discovery.request_scan()
            if started:
                self._event("setup_discovery")
            return started

    def _adopt_discovery(self):
        catalog = self.store.catalog()
        if catalog.revision == self.last_catalog:
            return
        self.last_catalog = catalog.revision
        snapshot = self.store.snapshot()
        connection = self.discovery.connection
        broker = snapshot.broker
        if connection and not broker:
            broker = connection.record
        records = []
        for record in snapshot.networks:
            if record.tombstoned or "record_corrupt" in record.issues:
                records.append(record)
                continue
            matches = [c for c in catalog.candidates if any(c.fields.get(k) and record.fields.get(k) and c.fields[k].value == record.fields[k].value
                       for k in ("coordinator_ieee", "addon_slug"))]
            records.append(merge_suggestions(record, matches[0]) if len(matches) == 1 else record)
        changed = replace(snapshot, broker=broker, networks=tuple(records))
        if changed != snapshot and not self._frozen():
            self.store.save(changed, expected_revision=snapshot.revision)
            self._event("setup_discovery", source="auto")

    def _apply(self):
        config = self.configuration()
        if self.applied_config == config:
            return
        from ..recovery.mqtt import MqttMonitor
        from ..recovery.supervisor import SupervisorClient
        from ..recovery.service import RecoveryService
        broker_changed = self.applied_config is not None and self.applied_config.mqtt != config.mqtt
        if self.service and (broker_changed or not config.bindings or not config.mqtt):
            self.service.close(close_store=False)
            self.service = None
        if self.service:
            self.service.reconfigure(config)
        elif config.bindings and config.mqtt and self.probe is not None and self.identity is not None:
            supervisor = SupervisorClient(os.environ.get("SUPERVISOR_TOKEN", ""), bindings=config.bindings, network_settings=self.settings,
                                          clock=self.clock.monotonic, controls_reader=self.controls_for, command_guard=self.guard_command)
            mqtt = MqttMonitor(config.mqtt, config.bindings, clock=self.clock.monotonic)
            targets = lambda ips: self.probe.probe_targets("zigbee0", self.identity.mac, self.settings.address.ip, ips)
            self.service = RecoveryService(config, self.recovery_store, supervisor, mqtt, targets, self.journal,
                                           clock=self.clock, cancelled=self.stopped.is_set)
            mqtt.start()
        self.applied_config = config

    def tick(self, network_status):
        with self.lock:
            if self.closed:
                return
            self.network_status = network_status
            try:
                self.discovery.tick()
                self._adopt_discovery()
                if self.clock.monotonic() >= self.next_capabilities:
                    self.capabilities = self.reader.capabilities()
                    self.next_capabilities = self.clock.monotonic() + 300
                self.last_error = ""
            except (OSError, ValueError, RuntimeError):
                self.last_error = "setup_unavailable"
        try:
            self._apply()
        except (OSError, ValueError, RuntimeError):
            self.last_error = "recovery_unavailable"
        service = self.service
        if not self.web and self.capabilities.ingress_port and self.clock.monotonic() >= self.next_web:
            try:
                from ..web.server import IngressServer
                from ..web.security import IngressSecurity
                web_server = IngressServer(self, self.capabilities.ingress_port, IngressSecurity())
                web_server.start()
                self.web = web_server
            except (OSError, ValueError, RuntimeError):
                self.next_web = self.clock.monotonic() + 60
                self.last_error = "ingress_unavailable"
        # Workers acquire the controller lock for permissions; do not join them under it.
        if service:
            try:
                service.tick(network_status)
            except (OSError, ValueError, RuntimeError):
                self.last_error = "recovery_unavailable"

    def view(self):
        with self.lock:
            snapshot = self.store.snapshot()
            config = self.configuration()
            readiness = configuration_readiness(config.enabled, config.mqtt is not None, len(config.bindings),
                                                  sum(c.managed and not c.paused for c in config.controls.values()),
                                                  ("transition_pending",) if self._frozen() else ((self.last_error,) if self.last_error else ()))
            networks = []
            for record in snapshot.networks:
                if record.tombstoned:
                    continue
                row = asdict(record)
                row["issues"] = self._valid(record)
                row["phase"] = "observing"
                row["radio"] = "unconfirmed"
                if self.service and record.state_key in self.service.runtimes:
                    state = self.recovery_store.load(record.state_key)
                    row["phase"] = state.phase
                    row["radio"] = "confirmed" if state.phase == "confirmed" else "application_only"
                networks.append(row)
            status = self.network_status
            network = {"address": str(self.settings.address), "parent": status.parent if status and hasattr(status, "parent") else self.settings.parent,
                       "state": status.state if status else "unknown"}
            broker = None if not snapshot.broker else {"mode": snapshot.broker.mode, "server": snapshot.broker.server,
                "provider_slug": snapshot.broker.provider_slug, "configured": config.mqtt is not None,
                "credentials_saved": bool(snapshot.broker.secret_ref)}
            return RuntimeView(snapshot.revision, self.mode, readiness, self.store.catalog(), tuple(networks), self.capabilities, network, broker)

    def diagnostics(self):
        view = asdict(self.view())
        view["format_version"] = 1
        return view

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            service, self.service = self.service, None
            web_server, self.web = self.web, None
        # Stop all users before closing databases or the owning network interface.
        if web_server:
            web_server.close()
        self.discovery.close()
        if service:
            service.close(close_store=False)
        self.reader.close()
        self.recovery_store.close()
        self.store.close()

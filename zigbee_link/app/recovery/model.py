from dataclasses import dataclass, field


@dataclass(frozen=True)
class Reference:
    ieee: str
    endpoint: int
    cluster: str
    attribute: str


@dataclass(frozen=True)
class Binding:
    key: str
    ip: str
    addon_slug: str
    base_topic: str
    coordinator_ieee: str
    references: tuple[Reference, ...] = ()


@dataclass(frozen=True)
class Controls:
    managed: bool = False
    paused: bool = False
    revision: str = ""
    observed_at: float = 0


@dataclass(frozen=True)
class AppObservation:
    available: bool = False
    state: str = "unknown"
    run_id: str | None = None
    busy: bool = True
    binding_valid: bool = False


@dataclass(frozen=True)
class Observation:
    at: float
    network_ready: bool = False
    present: bool | None = None
    conflict: bool = False
    supervisor: AppObservation = field(default_factory=AppObservation)
    controls: Controls | None = None
    mqtt_connected: bool = False
    mqtt_health: bool | None = None
    identity_match: bool | None = None
    radio: bool | None = None
    generation: str = ""
    configuration_error: bool = False
    health_sequence: int = 0


@dataclass(frozen=True)
class Action:
    kind: str
    binding_key: str
    generation: str


@dataclass(frozen=True)
class RecoveryState:
    phase: str = "observing"
    misses: int = 0
    successes: int = 0
    return_since: float | None = None
    stable_since: float | None = None
    next_attempt: float = 0
    attempt_stage: int = 0
    incident_id: str = ""
    pending_action: str | None = None
    generation: str = ""
    health_misses: int = 0
    last_observation: float = -1
    last_health_sequence: int = -1
    run_seen_at: float | None = None


@dataclass(frozen=True)
class Budget:
    hour_count: int = 0
    day_count: int = 0
    clock_trusted: bool = True


@dataclass(frozen=True)
class Decision:
    state: RecoveryState
    action: Action | None = None
    reason: str = "observing"
    events: tuple[str, ...] = ()

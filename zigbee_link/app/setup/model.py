from dataclasses import dataclass, field
from ..recovery.settings import MqttSettings


@dataclass(frozen=True)
class FieldValue:
    mode: str
    value: object
    source: str
    observed_at: float
    status: str
    proposal: object = None


@dataclass(frozen=True)
class BrokerRecord:
    identity: str
    mode: str
    server: str
    provider_slug: str = ""
    aliases: tuple[str, ...] = ()
    secret_ref: str = ""


@dataclass(frozen=True)
class BrokerConnection:
    record: BrokerRecord
    settings: MqttSettings = field(repr=False)


@dataclass(frozen=True)
class AppMetadata:
    slug: str
    name: str
    version: str
    state: str
    serial_ip: str | None = None
    serial_port: int | None = None
    adapter: str | None = None
    base_topic: str | None = None
    broker_server: str | None = None


@dataclass(frozen=True)
class BridgeMetadata:
    base_topic: str
    ip: str | None
    port: int | None
    coordinator_ieee: str
    broker_server: str | None
    retained: bool
    observed_at: float


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    fields: dict[str, FieldValue]
    issues: tuple[str, ...]
    match_kind: str


@dataclass(frozen=True)
class NetworkRecord:
    network_id: str
    state_key: str
    fields: dict[str, FieldValue]
    managed: bool
    paused: bool
    accepted: bool
    tombstoned: bool = False
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class SetupSnapshot:
    revision: int = 0
    enabled: bool = False
    broker: BrokerRecord | None = None
    networks: tuple[NetworkRecord, ...] = ()


@dataclass(frozen=True)
class Catalog:
    revision: int = 0
    candidates: tuple[Candidate, ...] = ()
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class Readiness:
    enabled: bool
    configured: bool
    managed_count: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Transition:
    receipt: str
    source_mode: str
    target_mode: str
    source_digest: str
    setup_revision: int
    phase: str


@dataclass(frozen=True)
class SupervisorCapabilities:
    version: str = "unknown"
    ingress_port: int | None = None
    web_write_allowed: bool = False


@dataclass(frozen=True)
class RuntimeView:
    revision: int
    mode: str
    readiness: Readiness
    catalog: Catalog
    networks: tuple[dict, ...]
    capabilities: SupervisorCapabilities
    network: dict
    broker: dict | None

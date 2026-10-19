import json
import logging
import os
from pathlib import Path
import signal
import threading

from .arp import ArpProbe
from .config import parse_settings
from .manager import Identity, InterfaceManager
from .network import CommandRunner, NetworkError, read_snapshot


class InstanceLock:
    def __init__(self, directory):
        self.path = directory / "instance.lock"
        self.file = None

    def __enter__(self):
        import fcntl
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            self.file = os.fdopen(fd, "w")
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except OSError:
            if self.file: self.file.close()
            raise NetworkError("Другой экземпляр уже работает или блокировка недоступна") from None

    def __exit__(self, *args):
        self.file.close()


def make_recovery(raw, settings, identity, probe, data_dir, stopped):
    from .recovery.settings import parse_recovery
    config = parse_recovery(raw.get("recovery", {}), settings)
    log = logging.getLogger("zigbee-link")
    for key in config.errors:
        log.warning("Привязка восстановления %s: настройка отклонена", key)
    requested = raw.get("recovery", {})
    if isinstance(requested, dict) and requested.get("enabled") is True:
        if not requested.get("networks"):
            log.warning("Восстановление не готово: Нет настроенных сетей (networks_empty)")
        if not requested.get("mqtt"):
            log.warning("Восстановление не готово: MQTT не настроен (mqtt_unconfigured)")
    if not config.bindings or config.mqtt is None:
        return None
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        log.warning("Восстановление недоступно: нет доступа к Supervisor; сетевой режим продолжает работу")
        return None
    from .recovery.journal import EventJournal
    from .recovery.mqtt import MqttMonitor
    from .recovery.service import RecoveryService
    from .recovery.store import RecoveryStore
    from .recovery.supervisor import SupervisorClient
    store = mqtt = None
    try:
        store = RecoveryStore(data_dir / "recovery.sqlite")
        supervisor = SupervisorClient(token, bindings=config.bindings, network_settings=settings)
        mqtt = MqttMonitor(config.mqtt, config.bindings)
        targets = lambda ips: probe.probe_targets("zigbee0", identity.mac, settings.address.ip, ips)
        service = RecoveryService(config, store, supervisor, mqtt, targets,
                                  EventJournal(data_dir / "diagnostics"), cancelled=stopped.is_set)
        mqtt.start()
        return service
    except Exception as exc:
        # Recovery must never take down a functioning static network path.
        log.error("Восстановление не запущено (%s); сетевой режим продолжает работу", type(exc).__name__)
        if mqtt:
            mqtt.stop()
        if store:
            store.close()
        return None


def main(options_path: Path = Path("/data/options.json"), data_dir: Path = Path("/data")) -> int:
    logging.basicConfig(level=logging.INFO, format="[Zigbee Link] %(message)s")
    log = logging.getLogger("zigbee-link")
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    manager = None
    recovery = None
    try:
        raw = json.loads(options_path.read_text(encoding="utf-8"))
        settings = parse_settings(raw)
        data_dir.mkdir(parents=True, exist_ok=True)
        with InstanceLock(data_dir):
            identity = Identity.load_or_create(data_dir)
            runner = CommandRunner()
            snapshot = read_snapshot(runner)
            for link in snapshot.links:
                log.info("Интерфейс %s: %s, %s", link["ifname"], snapshot.kinds.get(link["ifname"], "виртуальный/неподдерживаемый"), "кабель подключён" if "LOWER_UP" in link.get("flags", []) else "нет соединения")
            probe = ArpProbe(wait=stopped.wait, cancelled=stopped.is_set)
            manager = InterfaceManager(settings, identity, runner, probe)
            recovery = make_recovery(raw, settings, identity, probe, data_dir, stopped)
            last = None
            try:
                while not stopped.is_set():
                    status = manager.reconcile()
                    if recovery:
                        try:
                            recovery.tick(status)
                        except Exception as exc:
                            log.error("Контроль восстановления остановлен (%s); сетевой режим продолжает работу", type(exc).__name__)
                            recovery.close()
                            recovery = None
                    if status != last:
                        log.info("%s: %s", status.state, status.message)
                        last = status
                    stopped.wait(5 if status.state == "ready" else 15)
            finally:
                try:
                    if recovery:
                        recovery.close()
                finally:
                    manager.stop()
        return 0
    except (NetworkError, ValueError, OSError) as exc:
        log.error("Запуск остановлен: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

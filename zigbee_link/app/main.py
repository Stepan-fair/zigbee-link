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


def main(options_path: Path = Path("/data/options.json"), data_dir: Path = Path("/data")) -> int:
    logging.basicConfig(level=logging.INFO, format="[Zigbee Link] %(message)s")
    log = logging.getLogger("zigbee-link")
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    manager = None
    try:
        settings = parse_settings(json.loads(options_path.read_text(encoding="utf-8")))
        data_dir.mkdir(parents=True, exist_ok=True)
        with InstanceLock(data_dir):
            identity = Identity.load_or_create(data_dir)
            runner = CommandRunner()
            snapshot = read_snapshot(runner)
            for link in snapshot.links:
                log.info("Интерфейс %s: %s, %s", link["ifname"], snapshot.kinds.get(link["ifname"], "виртуальный/неподдерживаемый"), "кабель подключён" if "LOWER_UP" in link.get("flags", []) else "нет соединения")
            manager = InterfaceManager(settings, identity, runner, ArpProbe(wait=stopped.wait, cancelled=stopped.is_set))
            last = None
            try:
                while not stopped.is_set():
                    status = manager.reconcile()
                    if status != last:
                        log.info("%s: %s", status.state, status.message)
                        last = status
                    stopped.wait(5 if status.state == "ready" else 15)
            finally:
                manager.stop()
        return 0
    except (NetworkError, ValueError, OSError) as exc:
        log.error("Запуск остановлен: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

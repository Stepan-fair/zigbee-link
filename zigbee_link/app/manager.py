from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
import json
import logging
import os
from pathlib import Path
import secrets
import tempfile
import time
import uuid

from .config import INTERFACE, parse_settings
from .network import NetworkError, NetworkSnapshot, WaitingForLink, check_overlap, read_snapshot, select_parent

LOG = logging.getLogger("zigbee-link")


class AddressConflict(NetworkError):
    pass


@dataclass
class Identity:
    directory: Path
    token: str
    mac: str
    parent: str = ""
    address: str = ""
    pending_index: int | None = None

    @property
    def alias(self):
        return "zigbee-link:" + self.token

    @classmethod
    def load_or_create(cls, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / "identity.json"
        try:
            if path.is_symlink():
                raise ValueError("symlink")
            if path.exists():
                raw = json.loads(path.read_text(encoding="utf-8"))
                token = str(uuid.UUID(raw["token"]))
                mac = bytes.fromhex(raw["mac"].replace(":", ""))
                if token != raw["token"] or len(mac) != 6 or mac[0] & 3 != 2:
                    raise ValueError("identity")
                parent, address = raw.get("parent", ""), raw.get("address", "")
                if parent:
                    parse_settings({"parent": parent})
                if address:
                    parse_settings({"address": address})
                pending = raw.get("pending_index")
                if pending is not None and (type(pending) is not int or pending <= 0):
                    raise ValueError("invalid pending identity")
                return cls(data_dir, token, raw["mac"].lower(), parent, address, pending)
            mac = bytearray(secrets.token_bytes(6)); mac[0] = (mac[0] & 0xfc) | 2
            identity = cls(data_dir, str(uuid.uuid4()), ":".join(f"{b:02x}" for b in mac))
            identity.save()
            return identity
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise NetworkError("Не удалось прочитать identity.json; существующее состояние не заменено") from exc

    def save(self):
        fd, temp = tempfile.mkstemp(prefix=".identity-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"token": self.token, "mac": self.mac, "parent": self.parent, "address": self.address, "pending_index": self.pending_index}, f)
                f.flush(); os.fsync(f.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, self.directory / "identity.json")
        finally:
            if os.path.exists(temp):
                os.unlink(temp)


@dataclass(frozen=True)
class Status:
    state: str
    message: str
    parent: str | None = None


class InterfaceManager:
    def __init__(self, settings, identity: Identity, runner, probe):
        self.settings, self.identity, self.runner, self.probe = settings, identity, runner, probe
        self.verified = None
        self.verified_at = 0.0
        self.scanned = None
        self.blocked = False

    def _matches(self, snapshot, link):
        if not link or not self.identity.parent:
            return False
        parent = snapshot.link(self.identity.parent)
        info = link.get("linkinfo", {})
        return bool(parent and link.get("address", "").lower() == self.identity.mac and info.get("info_kind") == "macvlan" and info.get("info_data", {}).get("mode") == "bridge" and (link.get("link_index") == parent["ifindex"] or link.get("link") == parent["ifname"]))

    def _owned(self, snapshot, link):
        return self._matches(snapshot, link) and link.get("ifalias") == self.identity.alias

    def _finish_pending(self):
        if self.identity.pending_index is None:
            return
        snapshot = read_snapshot(self.runner)
        link = snapshot.link(INTERFACE)
        if link is None:
            # A reboot or parent removal can discard the unconfigured candidate.
            # No network mutation is needed to discard its stale creation receipt.
            self.identity.pending_index = None
            self.identity.save()
            return
        if not self._matches(snapshot, link) or link["ifindex"] != self.identity.pending_index or link.get("ifalias", "") not in ("", self.identity.alias):
            raise NetworkError("Не удалось подтвердить незавершённое создание zigbee0")
        self._validate_extras(snapshot)
        self.runner.run(["ip", "link", "set", "dev", INTERFACE, "alias", self.identity.alias])
        self._guard(self.identity.pending_index)
        self.identity.pending_index = None
        self.identity.save()

    def _guard(self, expected_index=None):
        snapshot = read_snapshot(self.runner)
        link = snapshot.link(INTERFACE)
        if not self._owned(snapshot, link) or (expected_index is not None and link["ifindex"] != expected_index):
            raise NetworkError("Принадлежность zigbee0 изменилась; изменение запрещено")
        self._validate_extras(snapshot)
        return snapshot, link

    def _validate_extras(self, snapshot):
        expected = IPv4Interface(self.identity.address) if self.identity.address else None
        for record in snapshot.addresses:
            if record.get("ifname") == INTERFACE:
                for addr in record.get("addr_info", []):
                    if addr.get("family") == "inet" and (expected is None or IPv4Interface(f"{addr['local']}/{addr['prefixlen']}") != expected):
                        raise NetworkError("На zigbee0 обнаружен чужой адрес; изменение запрещено")
        for route in snapshot.routes:
            if route.get("dev") == INTERFACE and (not expected or route["dst"] == "default" or not IPv4Network(route["dst"], strict=False).subnet_of(expected.network)):
                raise NetworkError("На zigbee0 обнаружен чужой маршрут; изменение запрещено")

    def _command(self, args, index):
        self._guard(index)
        self.runner.run(args)

    def _delete(self):
        snapshot = read_snapshot(self.runner)
        link = snapshot.link(INTERFACE)
        if link is None:
            return
        _, link = self._guard(link["ifindex"])
        self._command(["ip", "link", "delete", "dev", INTERFACE], link["ifindex"])
        self.verified = self.scanned = None

    def _ipv4_only(self, index):
        self._guard(index)
        try:
            qdiscs = json.loads(self.runner.run(["tc", "-j", "qdisc", "show", "dev", INTERFACE]))
            filters = json.loads(self.runner.run(["tc", "-j", "filter", "show", "dev", INTERFACE, "ingress"]))
            if not isinstance(qdiscs, list) or not isinstance(filters, list):
                raise ValueError("invalid tc state")
            valid = bool(filters) and all(f.get("protocol") == "ipv6" and f.get("pref") == 49151 and f.get("kind") == "matchall" for f in filters) and any(a.get("kind") == "gact" and a.get("control_action", {}).get("type") == "drop" for f in filters for a in f.get("options", {}).get("actions", []))
            if filters and not valid:
                raise NetworkError("Чужой ingress-фильтр на zigbee0; изменение запрещено")
            if not valid:
                _, link = self._guard(index)
                if "UP" in link.get("flags", []):
                    self._command(["ip", "link", "set", "dev", INTERFACE, "down"], index)
                if not any(q.get("kind") == "clsact" for q in qdiscs):
                    self._command(["tc", "qdisc", "add", "dev", INTERFACE, "clsact"], index)
                self._command(["tc", "filter", "add", "dev", INTERFACE, "ingress", "protocol", "ipv6", "pref", "49151", "handle", "1", "matchall", "action", "drop"], index)
            _, link = self._guard(index)
            if link.get("inet6_addr_gen_mode") != "none":
                self._command(["ip", "link", "set", "dev", INTERFACE, "addrgenmode", "none"], index)
        except (ValueError, TypeError, AttributeError) as exc:
            raise NetworkError("Не удалось проверить IPv4-защиту zigbee0") from exc

    def _has_address(self, snapshot, value):
        return any(r.get("ifname") == INTERFACE and any(a.get("family") == "inet" and f"{a['local']}/{a['prefixlen']}" == value for a in r.get("addr_info", [])) for r in snapshot.addresses)

    def _prepare(self, settings, parent):
        snapshot = read_snapshot(self.runner)
        link = snapshot.link(INTERFACE)
        if link and not self._owned(snapshot, link):
            raise NetworkError("Имя zigbee0 занято чужим интерфейсом")
        if link:
            self._validate_extras(snapshot)
            filtered = NetworkSnapshot(snapshot.links, [a for a in snapshot.addresses if a.get("ifname") != INTERFACE], [r for r in snapshot.routes if r.get("dev") != INTERFACE], snapshot.kinds)
        else:
            filtered = snapshot
        check_overlap(settings, filtered, None)
        old_address = self.identity.address
        if link and self.identity.parent != parent:
            self._delete()
            link = None
        if link is None:
            self.identity.parent = parent
            self.identity.address = ""
            self.identity.save()
            # Kernel creation does not preserve ifalias on every iproute2/kernel combination.
            self.runner.run(["ip", "link", "add", "name", INTERFACE, "link", parent, "address", self.identity.mac, "type", "macvlan", "mode", "bridge"])
            snapshot = read_snapshot(self.runner)
            link = snapshot.link(INTERFACE)
            if not self._matches(snapshot, link) or link.get("ifalias"):
                raise NetworkError("Не удалось подтвердить созданный zigbee0")
            self.identity.pending_index = link["ifindex"]
            self.identity.save()
            self._finish_pending()
            snapshot, link = self._guard()
            old_address = ""
        index = link["ifindex"]
        value = str(settings.address)
        self._ipv4_only(index)
        snapshot, link = self._guard(index)
        if "UP" not in link.get("flags", []):
            self._command(["ip", "link", "set", "dev", INTERFACE, "up"], index)
        snapshot, link = self._guard(index)
        key = (index, parent, value)
        missing = not self._has_address(snapshot, value)
        if self.verified != key or missing or time.monotonic() - self.verified_at >= 60:
            result = self.probe.check_address(INTERFACE, self.identity.mac, settings.address.ip)
            if not result.complete:
                raise NetworkError("ARP-проверка адреса HA не завершена")
            if result.responders.get(settings.address.ip):
                raise AddressConflict("Адрес HA занят другим устройством; выберите другую подсеть")
            self.verified_at = time.monotonic()
        if old_address and old_address != value and self._has_address(snapshot, old_address):
            self._command(["ip", "addr", "del", old_address, "dev", INTERFACE], index)
        # Persist intended address before mutation so crash recovery can validate it.
        self.identity.address = value
        self.identity.save()
        snapshot, _ = self._guard(index)
        if not self._has_address(snapshot, value):
            self._command(["ip", "addr", "add", value, "dev", INTERFACE], index)
        snapshot, _ = self._guard(index)
        if not any(r.get("dst") == str(settings.address.network) and r.get("dev") == INTERFACE and r.get("table", "main") in ("main", 254) and r.get("type", "unicast") == "unicast" for r in snapshot.routes):
            self._command(["ip", "route", "add", str(settings.address.network), "dev", INTERFACE, "src", str(settings.address.ip)], index)
        snapshot, link = self._guard(index)
        check_overlap(settings, snapshot, INTERFACE)
        if not self._has_address(snapshot, value) or "UP" not in link.get("flags", []):
            raise NetworkError("Подготовка интерфейса не подтверждена")
        self.verified = key
        if settings.scan_enabled and self.scanned != key:
            self.scanned = key
            try:
                result = self.probe.scan(INTERFACE, self.identity.mac, settings.address.ip, settings.address.network)
                for ip in sorted(result.responders):
                    LOG.info("%s — %s", ip, result.describe(ip))
                for device in settings.coordinators:
                    LOG.info("%s (%s) — %s", device.name, device.address, result.describe(device.address))
                LOG.info("ARP-обзор: %s; молчание не гарантирует свободный адрес", "завершён" if result.complete else "не завершён")
            except NetworkError as exc:
                LOG.warning("Обзор устройств не проверен: %s", exc)
        return Status("ready", f"Готов: {INTERFACE} = {value}, порт {parent}", parent)

    def reconcile(self):
        if self.blocked:
            return Status("error", "Откат не подтверждён; требуется проверка журнала и перезапуск приложения")
        previous = (self.identity.parent, self.identity.address)
        had_owned = False
        try:
            self._finish_pending()
            snapshot = read_snapshot(self.runner)
            link = snapshot.link(INTERFACE)
            had_owned = self._owned(snapshot, link)
            if link and not had_owned:
                raise NetworkError("Имя zigbee0 занято чужим интерфейсом; остановите старое приложение")
            parent = select_parent(self.settings, snapshot)
            return self._prepare(self.settings, parent)
        except WaitingForLink as exc:
            self.verified = self.scanned = None
            return Status("waiting", str(exc))
        except (NetworkError, OSError, ValueError) as exc:
            self.verified = self.scanned = None
            try:
                if isinstance(exc, AddressConflict) and had_owned and str(self.settings.address) == previous[1]:
                    self._delete()
                elif previous[1] and had_owned and previous != (self.identity.parent, self.identity.address):
                    # Remove only the failed owned candidate, then rebuild the old configuration.
                    self._delete()
                    self._prepare(parse_settings({"parent": previous[0], "address": previous[1], "scan_enabled": False}), previous[0])
                elif not had_owned:
                    s = read_snapshot(self.runner)
                    if self._owned(s, s.link(INTERFACE)):
                        self._delete()
            except (NetworkError, OSError, ValueError):
                self.blocked = True
                LOG.error("Не удалось подтвердить откат собственного интерфейса; дальнейшие изменения остановлены")
            return Status("error", str(exc))

    def stop(self):
        try:
            snapshot = read_snapshot(self.runner)
            if self._owned(snapshot, snapshot.link(INTERFACE)):
                self._delete()
        except (NetworkError, OSError, ValueError) as exc:
            LOG.error("Очистка не выполнена: %s", exc)

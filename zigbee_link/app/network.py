from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
import json
from pathlib import Path
import subprocess


class NetworkError(RuntimeError):
    pass


class WaitingForLink(NetworkError):
    pass


@dataclass
class NetworkSnapshot:
    links: list[dict]
    addresses: list[dict]
    routes: list[dict]
    kinds: dict[str, str]

    def link(self, name):
        return next((l for l in self.links if l.get("ifname") == name), None)


class CommandRunner:
    def run(self, argv: list[str]) -> str:
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=True)
            return result.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            # Don't include command output; only our command names are logged.
            raise NetworkError(f"Ошибка выполнения {argv[0]} ({type(exc).__name__})") from None

    def classify(self, links: list[dict]) -> dict[str, str]:
        kinds = {}
        for link in links:
            name = link.get("ifname", "")
            base = Path("/sys/class/net") / name
            if (base / "wireless").exists() or (base / "phy80211").exists():
                kinds[name] = "wifi"
            elif (base / "device").exists() and link.get("link_type") == "ether" and not link.get("linkinfo", {}).get("info_kind"):
                kinds[name] = "ethernet"
        return kinds


def read_snapshot(runner: CommandRunner) -> NetworkSnapshot:
    try:
        links = json.loads(runner.run(["ip", "-j", "-d", "link", "show"]))
        addresses = json.loads(runner.run(["ip", "-j", "-4", "addr", "show"]))
        routes = json.loads(runner.run(["ip", "-j", "-4", "route", "show", "table", "all"]))
        if any(not isinstance(records, list) or any(not isinstance(r, dict) for r in records) for records in (links, addresses, routes)):
            raise ValueError("invalid network records")
        # iproute2 JSON may omit dst for an all-zero route. Only explicit default is exempt.
        for link in links:
            if not isinstance(link.get("ifname"), str) or not isinstance(link.get("ifindex"), int):
                raise ValueError("invalid link record")
        for addr in addresses:
            if not isinstance(addr.get("ifname"), str) or not isinstance(addr.get("addr_info"), list):
                raise ValueError("invalid address record")
            for entry in addr["addr_info"]:
                if not isinstance(entry, dict) or entry.get("family") != "inet" or not isinstance(entry.get("local"), str) or type(entry.get("prefixlen")) is not int:
                    raise ValueError("invalid nested IPv4 record")
                IPv4Interface(f"{entry['local']}/{entry['prefixlen']}")
        for route in routes:
            if not isinstance(route.get("dst"), str):
                raise ValueError("missing route destination")
        return NetworkSnapshot(links, addresses, routes, runner.classify(links))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise NetworkError("Не удалось прочитать полное состояние сети") from exc


def select_parent(settings, snapshot: NetworkSnapshot) -> str:
    eligible = {l["ifname"] for l in snapshot.links if snapshot.kinds.get(l["ifname"]) == "ethernet" and not l.get("linkinfo", {}).get("info_kind")}
    active = {l["ifname"] for l in snapshot.links if l["ifname"] in eligible and "LOWER_UP" in l.get("flags", [])}
    if settings.parent != "auto":
        if settings.parent not in eligible:
            raise NetworkError("Выбранный порт не является физическим Ethernet-интерфейсом")
        if settings.parent not in active:
            raise WaitingForLink("Ожидание Ethernet-кабеля")
        return settings.parent
    defaults = [r for r in snapshot.routes if r.get("dst") == "default" and r.get("dev") in active and r.get("table", "main") in ("main", 254)]
    if defaults:
        metric = min(int(r.get("metric", 0)) for r in defaults)
        choices = {r["dev"] for r in defaults if int(r.get("metric", 0)) == metric}
    else:
        choices = active
    if len(choices) == 1:
        return choices.pop()
    if not active:
        raise WaitingForLink("Ожидание физического Ethernet-соединения")
    raise NetworkError("Несколько Ethernet-портов: выберите parent в настройках")


def check_overlap(settings, snapshot: NetworkSnapshot, owned_interface: str | None) -> None:
    target = settings.address.network
    try:
        for record in snapshot.addresses:
            if record.get("ifname") == owned_interface:
                continue
            for addr in record.get("addr_info", []):
                if addr.get("family") == "inet":
                    current = IPv4Interface(f"{addr['local']}/{addr['prefixlen']}").network
                    if target.overlaps(current):
                        raise NetworkError(f"Подсеть Zigbee пересекается с адресами {record['ifname']}")
        for route in snapshot.routes:
            if route.get("dst") == "default":
                continue
            current = IPv4Network(route["dst"], strict=False)
            if owned_interface and route.get("dev") == owned_interface and current.subnet_of(target):
                continue
            if target.overlaps(current):
                raise NetworkError(f"Подсеть Zigbee пересекается с маршрутом {current}")
    except (ValueError, KeyError, TypeError) as exc:
        raise NetworkError("Не удалось проверить пересечение адресов и маршрутов") from exc

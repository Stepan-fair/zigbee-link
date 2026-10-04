from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_interface
import re

INTERFACE = "zigbee0"
PRIVATE = tuple(IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


@dataclass(frozen=True)
class Coordinator:
    name: str
    address: IPv4Address


@dataclass(frozen=True)
class Settings:
    parent: str
    address: IPv4Interface
    coordinators: tuple[Coordinator, ...]
    scan_enabled: bool


def parse_settings(raw: dict) -> Settings:
    if not isinstance(raw, dict):
        raise ValueError("Настройки должны быть объектом")
    parent = raw.get("parent", "auto")
    if not isinstance(parent, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", parent) or parent == INTERFACE:
        raise ValueError("Некорректное имя физического интерфейса")
    try:
        address = ip_interface(raw.get("address", "172.31.254.1/24"))
    except (ValueError, TypeError):
        raise ValueError("Нужен частный IPv4-адрес с маской /24") from None
    if not isinstance(address, IPv4Interface) or address.network.prefixlen != 24 or not any(address.network.subnet_of(n) for n in PRIVATE):
        raise ValueError("Нужен частный IPv4-адрес с маской /24")
    if address.ip in (address.network.network_address, address.network.broadcast_address):
        raise ValueError("Адрес HA не может быть адресом сети или broadcast")
    scan = raw.get("scan_enabled", True)
    if not isinstance(scan, bool):
        raise ValueError("scan_enabled должен быть true или false")
    records = raw.get("coordinators", [])
    if not isinstance(records, list) or len(records) > 253:
        raise ValueError("Некорректный список координаторов")
    seen = {address.ip}
    devices = []
    for entry in records:
        if not isinstance(entry, dict):
            raise ValueError("Некорректный координатор")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError("Нужное понятное имя координатора без управляющих символов")
        try:
            ip = IPv4Address(entry.get("ip"))
        except (ValueError, TypeError):
            raise ValueError("Некорректный IP координатора") from None
        if ip in seen or ip not in address.network or ip in (address.network.network_address, address.network.broadcast_address):
            raise ValueError("IP координатора должен быть уникальным адресом выбранной подсети")
        seen.add(ip)
        devices.append(Coordinator(name.strip(), ip))
    return Settings(parent, address, tuple(devices), scan)

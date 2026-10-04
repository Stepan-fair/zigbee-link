"""Bounded ARP diagnostics. No TCP connection to coordinator radios."""
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
import socket
import struct
import time

from .network import NetworkError


@dataclass(frozen=True)
class ArpReply:
    sender_ip: IPv4Address
    sender_mac: str
    target_ip: IPv4Address | None = None
    operation: int = 2


@dataclass
class ProbeResult:
    responders: dict[IPv4Address, set[str]]
    complete: bool

    def add(self, reply: ArpReply):
        self.responders.setdefault(reply.sender_ip, set()).add(reply.sender_mac)

    def describe(self, ip: IPv4Address) -> str:
        macs = self.responders.get(ip, set())
        if not macs:
            return "ответ не получен"
        if len(macs) > 1:
            return "возможный конфликт: " + ", ".join(sorted(macs))
        return "обнаружен: " + next(iter(macs))


def encode_probe(source_mac: str, target: IPv4Address, source_ip: IPv4Address) -> bytes:
    mac = bytes.fromhex(source_mac.replace(":", ""))
    if len(mac) != 6:
        raise ValueError("Invalid MAC")
    return b"\xff" * 6 + mac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, 1) + mac + source_ip.packed + b"\x00" * 6 + target.packed


def parse_reply(frame: bytes) -> ArpReply | None:
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    hw, proto, hlen, plen, op = struct.unpack("!HHBBH", frame[14:22])
    if (hw, proto, hlen, plen) != (1, 0x800, 6, 4) or op not in (1, 2):
        return None
    sender = frame[22:28]
    if sender != frame[6:12] or sender == b"\x00" * 6 or sender[0] & 1:
        return None
    return ArpReply(IPv4Address(frame[28:32]), ":".join(f"{b:02x}" for b in sender), IPv4Address(frame[38:42]), op)


class ArpProbe:
    def __init__(self, socket_factory=socket.socket, clock=time.monotonic, wait=time.sleep, cancelled=lambda: False):
        self.socket_factory = socket_factory
        self.clock = clock
        self.wait = wait
        self.cancelled = cancelled

    def _open(self, interface):
        sock = None
        try:
            sock = self.socket_factory(getattr(socket, "AF_PACKET", 17), socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((interface, 0))
            sock.setblocking(False)
            return sock
        except OSError as exc:
            if sock:
                sock.close()
            raise NetworkError(f"ARP-проверка недоступна ({type(exc).__name__})") from None

    def _receive(self, sock, result, own_mac, allowed, detect_probes=False):
        # Bound work even under an ARP storm.
        for _ in range(256):
            try:
                reply = parse_reply(sock.recv(2048))
            except BlockingIOError:
                break
            if reply and reply.sender_mac != own_mac:
                if reply.sender_ip in allowed:
                    result.add(reply)
                elif detect_probes and reply.operation == 1 and reply.sender_ip == IPv4Address("0.0.0.0") and reply.target_ip in allowed:
                    result.add(ArpReply(reply.target_ip, reply.sender_mac))

    def check_address(self, interface: str, source_mac: str, address: IPv4Address) -> ProbeResult:
        sock = self._open(interface)
        result = ProbeResult({}, False)
        try:
            for _ in range(3):
                if self.cancelled():
                    return result
                sock.send(encode_probe(source_mac, address, IPv4Address("0.0.0.0")))
                end = self.clock() + 0.4
                while self.clock() < end:
                    if self.cancelled():
                        return result
                    self._receive(sock, result, source_mac, {address}, detect_probes=True)
                    if result.responders:
                        result.complete = True
                        return result
                    self.wait(0.02)
            self._receive(sock, result, source_mac, {address}, detect_probes=True)
            result.complete = True
            return result
        except OSError as exc:
            raise NetworkError(f"Ошибка ARP-проверки ({type(exc).__name__})") from None
        finally:
            sock.close()

    def scan(self, interface: str, source_mac: str, source_ip: IPv4Address, network: IPv4Network) -> ProbeResult:
        if network.prefixlen != 24 or source_ip not in network:
            raise ValueError("ARP-обзор ограничен своей /24 подсетью")
        sock = self._open(interface)
        result = ProbeResult({}, False)
        started = self.clock()
        try:
            for target in network.hosts():
                if target == source_ip:
                    continue
                if self.cancelled() or self.clock() - started >= 30:
                    return result
                sock.send(encode_probe(source_mac, target, source_ip))
                end = self.clock() + 0.1
                while self.clock() < end:
                    if self.cancelled():
                        return result
                    self._receive(sock, result, source_mac, network)
                    self.wait(0.01)
            end = min(started + 30, self.clock() + 0.5)
            while self.clock() < end and not self.cancelled():
                self._receive(sock, result, source_mac, network)
                self.wait(0.01)
            result.complete = not self.cancelled()
            return result
        except OSError as exc:
            raise NetworkError(f"Ошибка ARP-обзора ({type(exc).__name__})") from None
        finally:
            sock.close()

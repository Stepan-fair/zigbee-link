from ipaddress import IPv4Address, IPv4Network
import struct
import pytest
from app.arp import encode_probe, parse_reply, ArpProbe, ProbeResult
from app.network import NetworkError

MAC = "02:00:00:00:00:01"


def frame(ip="172.31.254.2", mac="02:00:00:00:00:02", op=2):
    m = bytes.fromhex(mac.replace(":", ""))
    return bytes.fromhex(MAC.replace(":", "")) + m + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, op) + m + IPv4Address(ip).packed + bytes.fromhex(MAC.replace(":", "")) + IPv4Address("172.31.254.1").packed


def test_probe_encoding_and_valid_reply():
    p = encode_probe(MAC, IPv4Address("172.31.254.1"), IPv4Address("0.0.0.0"))
    assert len(p) >= 42
    assert p[:6] == b"\xff" * 6
    assert p[28:32] == b"\x00" * 4
    assert p[38:42] == IPv4Address("172.31.254.1").packed
    assert str(parse_reply(frame()).sender_ip) == "172.31.254.2"
    assert parse_reply(frame()).sender_mac == "02:00:00:00:00:02"


def test_truncated_and_unrelated_frames_ignored():
    for data in (b"", frame()[:30], frame()[:12] + b"\x08\x00" + frame()[14:], frame(op=5)):
        assert parse_reply(data) is None
    data = bytearray(frame()); data[6] = 4
    assert parse_reply(bytes(data)) is None


def test_request_claiming_address_detected():
    assert str(parse_reply(frame(ip="172.31.254.1", op=1)).sender_ip) == "172.31.254.1"


def test_two_macs_report_possible_conflict():
    r = ProbeResult({}, True)
    r.add(parse_reply(frame()))
    r.add(parse_reply(frame(mac="02:00:00:00:00:03")))
    assert len(r.responders[IPv4Address("172.31.254.2")]) == 2


def test_silence_not_labeled_free():
    assert ProbeResult({}, True).describe(IPv4Address("172.31.254.2")) == "ответ не получен"


def test_raw_socket_failure_blocks_address():
    def denied(*args):
        raise PermissionError("raw socket")
    with pytest.raises(NetworkError):
        ArpProbe(socket_factory=denied).check_address("zigbee0", MAC, IPv4Address("172.31.254.1"))


def test_scan_is_bounded_and_cancellable():
    class Socket:
        def bind(self, addr): pass
        def setblocking(self, value): pass
        def close(self): pass
        def send(self, packet):
            sent.append(packet)
        def recv(self, size): raise BlockingIOError
    now = [0.0]; sent = []
    def wait(seconds): now[0] += seconds
    p = ArpProbe(socket_factory=lambda *a: Socket(), clock=lambda: now[0], wait=wait, cancelled=lambda: now[0] >= 0.5)
    r = p.scan("zigbee0", MAC, IPv4Address("172.31.254.1"), IPv4Network("172.31.254.0/24"))
    assert len(sent) <= 6
    assert r.complete is False
    assert now[0] <= 0.6


def test_scan_rejects_large_network():
    with pytest.raises(ValueError):
        ArpProbe().scan("zigbee0", MAC, IPv4Address("172.31.254.1"), IPv4Network("172.31.0.0/16"))

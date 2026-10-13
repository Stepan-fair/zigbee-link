from ipaddress import IPv4Address
import pytest
from app.arp import ArpProbe,encode_probe
from test_arp import MAC,frame

class Sock:
    def __init__(self,frames=()): self.frames=list(frames); self.sent=[]; self.closed=False
    def bind(self,a): pass
    def setblocking(self,a): pass
    def close(self): self.closed=True
    def send(self,p): self.sent.append(p)
    def recv(self,n):
        if self.frames: return self.frames.pop(0)
        raise BlockingIOError


def test_targets_only_and_multiple_macs():
    sock=Sock([frame(),frame(mac="02:00:00:00:00:03"),frame(ip="172.31.254.99")])
    now=[0.0]
    p=ArpProbe(socket_factory=lambda *a:sock,clock=lambda:now[0],wait=lambda s:now.__setitem__(0,now[0]+s))
    r=p.probe_targets("zigbee0",MAC,IPv4Address("172.31.254.1"),(IPv4Address("172.31.254.2"),IPv4Address("172.31.254.3")))
    assert r.complete and len(r.responders[IPv4Address("172.31.254.2")])==2
    assert IPv4Address("172.31.254.99") not in r.responders
    assert len(sock.sent)==2 and sock.sent[0][28:32]==IPv4Address("172.31.254.1").packed
    assert sock.closed


def test_shared_send_budget_and_cancellation():
    sock=Sock(); now=[0.0]; sent_at=[]
    sock.send=lambda p:sent_at.append(now[0])
    p=ArpProbe(socket_factory=lambda *a:sock,clock=lambda:now[0],wait=lambda s:now.__setitem__(0,now[0]+s),cancelled=lambda:now[0]>=0.35)
    r=p.probe_targets("zigbee0",MAC,IPv4Address("172.31.254.1"),tuple(IPv4Address(f"172.31.254.{n}") for n in range(2,20)))
    assert not r.complete and len(sent_at)<=4
    assert all(b-a>=0.099 for a,b in zip(sent_at,sent_at[1:]))


def test_empty_targets_do_not_open_socket():
    p=ArpProbe(socket_factory=lambda *a:pytest.fail("socket unnecessary"))
    assert p.probe_targets("zigbee0",MAC,IPv4Address("172.31.254.1"),()).complete

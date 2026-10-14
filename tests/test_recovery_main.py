import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import app.main as main
from app.config import parse_settings
from app.manager import Status


def test_legacy_options_do_not_construct_recovery(tmp_path):
    assert main.make_recovery({},parse_settings({}),None,None,tmp_path,None) is None


def test_recovery_tick_and_shutdown_precede_interface_cleanup(tmp_path,monkeypatch):
    events=[]
    class Event:
        done=False
        def set(self): self.done=True
        def is_set(self): return self.done
        def wait(self,seconds): self.done=True
    class Manager:
        def __init__(self,*a): pass
        def reconcile(self): return Status("ready","ready","eth0")
        def stop(self): events.append("interface_stop")
    class Recovery:
        def tick(self,status): events.append("recovery_tick")
        def close(self): events.append("recovery_stop")
    monkeypatch.setattr(main.threading,"Event",Event)
    monkeypatch.setattr(main.signal,"signal",lambda *a:None)
    monkeypatch.setattr(main,"InstanceLock",lambda *a:nullcontext())
    monkeypatch.setattr(main.Identity,"load_or_create",lambda *a:SimpleNamespace(mac="02:00:00:00:00:01"))
    monkeypatch.setattr(main,"read_snapshot",lambda *a:SimpleNamespace(links=[],kinds={}))
    monkeypatch.setattr(main,"InterfaceManager",Manager)
    monkeypatch.setattr(main,"make_recovery",lambda *a:Recovery())
    options=tmp_path/"options.json"; options.write_text(json.dumps({}))
    assert main.main(options,tmp_path)==0
    assert events==["recovery_tick","recovery_stop","interface_stop"]

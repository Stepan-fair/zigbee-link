from dataclasses import replace
from ipaddress import IPv4Address
import threading
import time
import pytest
from app.arp import ProbeResult
from app.config import parse_settings
from app.manager import Status
from app.recovery.settings import parse_recovery
from app.recovery.model import AppObservation,Controls
from app.recovery.mqtt import MqttObservation
from app.recovery.store import RecoveryStore,StoreError
from app.recovery.journal import EventJournal
from app.recovery.supervisor import CommandOutcome
from app.recovery.service import RecoveryService
from test_recovery_settings import raw_record,config,settings

class Clock:
    def __init__(self): self.t=0.; self.utc=1000.
    def monotonic(self): return self.t
    def time(self): return self.utc
    def advance(self,n): self.t+=n; self.utc+=n

class Supervisor:
    def __init__(self,cfg,clock): self.cfg=cfg; self.clock=clock; self.states={b.key:"stopped" for b in cfg.bindings}; self.commands=[]; self.paused=set(); self.available=True; self.after_check=None
    def self_controls(self):
        if not self.available: return {}
        return {k:replace(v,observed_at=self.clock.t,paused=k in self.paused) for k,v in self.cfg.controls.items()}
    def observe(self,b): return AppObservation(self.available,self.states[b.key],None,False,True)
    def diagnose(self,b,limit=200):
        if self.after_check: self.after_check()
        return []
    def command(self,b,kind):
        self.commands.append((b.key,kind)); self.states[b.key]="started"
        return CommandOutcome(True,"accepted")

class Mqtt:
    def __init__(self,s,c): self.s=s; self.c=c; self.epochs={k:"g" for k in s.states}; self.seq={k:0 for k in s.states}; self.health={k:None for k in s.states}; self.connected=True
    def invalidate(self,k): self.epochs[k]+="x"; self.health[k]=None; return self.epochs[k]
    def invalidate_health(self,k): self.health[k]=None
    def request_health(self,k,now): self.health[k]=self.s.states[k]=="started"; self.seq[k]+=1; return "tx"
    def request_reporting_read(self,*a): return "radio"
    def snapshot(self,k,now): return MqttObservation(self.connected,self.epochs[k],self.health[k],self.seq[k],True,())
    def stop(self): pass

class Probe:
    def __init__(self): self.present={"172.31.254.2","172.31.254.3"}
    def __call__(self,targets): return ProbeResult({ip:{"02:00:00:00:00:02"} for ip in targets if str(ip) in self.present},True)


def setup(tmp_path):
    cfg=parse_recovery(config([raw_record(),raw_record("172.31.254.3","def_zigbee2mqtt","zigbee2mqtt/second")]),settings())
    c=Clock(); s=Supervisor(cfg,c); m=Mqtt(s,c); p=Probe(); store=RecoveryStore(tmp_path/"state.sqlite")
    svc=RecoveryService(cfg,store,s,m,p,EventJournal(tmp_path/"logs",clock=c.time),clock=c)
    return svc,c,s,m,p,store


def pump(svc,c,seconds=240):
    for _ in range(int(seconds/5)):
        svc.tick(Status("ready","ready","eth0"))
        for future in list(svc.futures.values()):
            if future[1]!="blocked": future[0].result(timeout=2)
        svc.tick(Status("ready","ready","eth0")); c.advance(5)


def test_multiple_coordinators_recover_only_the_returned_one(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path); p.present={"172.31.254.3"}
    pump(svc,c,240)
    assert s.commands==[("172.31.254.3","start")]
    p.present.add("172.31.254.2"); pump(svc,c,240)
    assert s.commands==[("172.31.254.3","start"),("172.31.254.2","start")]
    svc.close()


def test_pause_between_diagnosis_and_send_cancels_command(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path)
    s.after_check=lambda:s.paused.update(s.states)
    pump(svc,c,240)
    assert s.commands==[]
    assert all(store.load(k).pending_action is None for k in s.states)
    svc.close()


def test_missing_mqtt_never_restarts_apps(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path); m.connected=False
    pump(svc,c,240)
    assert not s.commands
    svc.close()


def test_unknown_http_outcome_is_reconciled_without_duplicate_start(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path); original=s.command
    def lost(b,kind): original(b,kind); return CommandOutcome(False,"outcome_unknown")
    s.command=lost
    pump(svc,c,600)
    assert len(s.commands)==2 and all(store.load(k).pending_action is None for k in s.states)
    svc.close()


def test_no_network_readiness_means_no_action(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path)
    for _ in range(60): svc.tick(Status("error","conflict")); c.advance(5)
    assert not s.commands
    svc.close()


def test_budgets_persist_and_live_pause_does_not_stop_interface(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path); pump(svc,c,240)
    assert all(store.command_count(k,0)==1 for k in s.states)
    s.paused.update(s.states); pump(svc,c,60)
    assert all(store.load(k).phase=="paused" for k in s.states)
    assert len(s.commands)==2
    svc.close()


def test_clock_jump_cannot_expire_command_budget(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path)
    for k in s.states:
        for n in range(4):
            r=store.reserve(__import__("app.recovery.model",fromlist=["Action"]).Action("start",k,"g"),1000,"r"); store.resolve(r,"failed",None)
    c.utc+=30*86400
    pump(svc,c,240)
    assert not s.commands
    svc.close()


def test_slow_network_does_not_block_other_network(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path); release=threading.Event(); original=s.observe
    def observe(b):
        if b.ip=="172.31.254.2": release.wait(5)
        return original(b)
    s.observe=observe
    try:
        for _ in range(100):
            svc.tick(Status("ready","ready","eth0")); c.advance(5); time.sleep(.003)
        assert ("172.31.254.3","start") in s.commands
        assert not any(k=="172.31.254.2" for k,kind in s.commands)
    finally:
        release.set(); svc.close()


def test_radio_success_does_not_postpone_next_check_forever(tmp_path):
    from app.recovery.mqtt import ReportingReply
    svc,c,s,m,p,store=setup(tmp_path); pump(svc,c,240)
    original=m.snapshot; ref=svc.config.bindings[0].references[0]
    generation=m.epochs["172.31.254.2"]
    reply=ReportingReply(ref,generation,"tx",240,"ok",{"id":ref.ieee,"endpoint":1,"cluster":"genOnOff","configs":[{"status":0,"direction":0,"attrId":0}]})
    m.snapshot=lambda k,now:replace(original(k,now),radio_replies=(reply,)) if k=="172.31.254.2" else original(k,now)
    pump(svc,c,300)
    assert svc.runtimes["172.31.254.2"].next_radio<=1140
    svc.close()


def test_busy_observer_does_not_consume_attempt_stage(tmp_path):
    from concurrent.futures import Future
    from app.recovery.model import RecoveryState
    svc,c,s,m,p,store=setup(tmp_path); c.advance(60); key="172.31.254.2"
    rt=svc.runtimes[key]; rt.controls=s.self_controls()[key]; rt.app=s.observe(rt.binding)
    svc.arp_at=60; svc.arp[key]={"02:00:00:00:00:02"}
    store.save(key,RecoveryState(successes=3,return_since=0,last_observation=60,generation="g"))
    svc.futures[key]=(Future(),"observe")
    svc._process(rt,60,True)
    assert store.load(key).attempt_stage==0
    assert not s.commands
    svc.close()


def test_mqtt_failure_between_diagnosis_and_send_cancels_command(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path)
    s.after_check=lambda:setattr(m,"connected",False)
    pump(svc,c,240)
    assert not s.commands
    svc.close()


def test_coordinator_disappearing_before_command_is_not_started(tmp_path):
    svc,c,s,m,p,store=setup(tmp_path)
    s.after_check=p.present.clear
    pump(svc,c,240)
    assert not s.commands
    svc.close()

import json
from dataclasses import replace
import pytest
from app.recovery.model import Binding,Reference
from app.recovery.settings import MqttSettings
from app.recovery.mqtt import MqttMonitor
B=Binding("a","172.31.254.2","abc_zigbee2mqtt","z2m/a","0x00124b0000000001")
R=Reference("0x00124b0000000010",1,"genOnOff","onOff")
class Client:
    def __init__(self): self.messages=[]
    def username_pw_set(self,*a): pass
    def reconnect_delay_set(self,*a,**k): pass
    def max_queued_messages_set(self,*a): pass
    def max_inflight_messages_set(self,*a): pass
    def publish(self,*a,**k): self.messages.append((a,k)); return type("Sent",(),{"rc":0})()
    def subscribe(self,*a,**k): return (0,1)
    def disconnect(self): pass
    def loop_stop(self): pass


def monitor():
    m=MqttMonitor(MqttSettings("mqtt://broker:1883"),(B,),client=Client(),clock=lambda:0)
    m.on_connected(); return m


def health(m,tx,now=1,retained=False,topic=None):
    m.receive(topic or "z2m/a/bridge/response/health_check",json.dumps({"transaction":tx,"status":"ok","data":{"healthy":True}}).encode(),retained,now)


def test_only_matching_fresh_health_response_passes():
    m=monitor(); tx=m.request_health("a",0)
    health(m,"other"); assert m.snapshot("a",1).health is None
    health(m,tx,retained=True); assert m.snapshot("a",1).health is None
    health(m,tx,topic="z2m/b/bridge/response/health_check"); assert m.snapshot("a",1).health is None
    health(m,tx); assert m.snapshot("a",1).health is True
    health(m,tx,now=2); assert m.snapshot("a",2).health_sequence==1
    assert m.client.messages[0][1]["retain"] is False


def test_reconnection_and_command_invalidation_reject_old_responses():
    m=monitor(); tx=m.request_health("a",0); generation=m.snapshot("a",0).generation
    m.on_connected(); health(m,tx)
    assert m.snapshot("a",1).health is None and m.snapshot("a",1).generation!=generation
    tx=m.request_health("a",1); m.invalidate("a"); health(m,tx,2)
    assert m.snapshot("a",2).health is None


def test_health_timeout_counts_once_and_late_response_is_rejected():
    m=monitor(); tx=m.request_health("a",0)
    assert m.snapshot("a",16).health is False
    assert m.snapshot("a",17).health_sequence==1
    health(m,tx,18); assert m.snapshot("a",18).health is False


def test_retained_identity_is_not_live_proof():
    m=monitor(); payload=json.dumps({"coordinator":{"ieee_address":B.coordinator_ieee},"config":{"serial":{"port":"tcp://172.31.254.2:6638"}}}).encode()
    m.receive("z2m/a/bridge/info",payload,True,1)
    assert m.snapshot("a",1).identity_match is None
    m.receive("z2m/a/bridge/info",payload,False,2)
    assert m.snapshot("a",2).identity_match is True


def test_wrong_coordinator_or_serial_ip_blocks_identity():
    m=monitor()
    m.receive("z2m/a/bridge/info",json.dumps({"coordinator":{"ieee_address":"0x00124b0000000099"},"config":{"serial":{"port":"tcp://172.31.254.2:6638"}}}).encode(),False,1)
    assert m.snapshot("a",1).identity_match is False


def test_radio_replies_are_not_health_and_are_correlated():
    m=monitor(); tx=m.request_reporting_read("a",R,0)
    data={"id":R.ieee,"endpoint":1,"cluster":"genOnOff","configs":[{"attribute":"onOff","minimumReportInterval":1,"maximumReportInterval":300}]}
    m.receive("z2m/a/bridge/response/device/reporting/read",json.dumps({"transaction":tx,"status":"ok","data":data}).encode(),False,1)
    s=m.snapshot("a",1)
    assert s.health is None and len(s.radio_replies)==1
    assert s.radio_replies[0].reference==R


def test_oversized_or_malformed_input_does_not_break_other_network():
    other=replace(B,key="b",ip="172.31.254.3",addon_slug="def_zigbee2mqtt",base_topic="z2m/b")
    m=MqttMonitor(MqttSettings("mqtt://broker"),(B,other),client=Client()); m.on_connected()
    m.receive("z2m/a/bridge/info",b"{"*1048577,False,1)
    m.receive("z2m/a/bridge/info",b"not json",False,1)
    tx=m.request_health("b",0)
    health(m,tx,topic="z2m/b/bridge/response/health_check")
    assert m.snapshot("b",1).health is True and m.snapshot("a",1).health is None


def test_one_pending_health_request_per_network():
    m=monitor(); tx=m.request_health("a",0)
    assert m.request_health("a",1)==tx
    assert len(m.client.messages)==1

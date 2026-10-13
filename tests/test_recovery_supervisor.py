from dataclasses import replace
import json
import pytest
from app.recovery.model import Binding, Reference
from app.recovery.settings import parse_recovery
from app.config import parse_settings
from app.recovery.supervisor import SupervisorClient, HttpResult
from test_recovery_settings import raw_record,config,settings

B=Binding("172.31.254.2","172.31.254.2","abc_zigbee2mqtt","zigbee2mqtt/first","0x00124b0000000001",(Reference("0x00124b0000000010",1,"genOnOff","onOff"),))

class Transport:
    def __init__(self): self.calls=[]; self.status=200; self.bad=False; self.busy=False; self.paused=False
    def request(self,method,path,body=None,timeout=5):
        self.calls.append((method,path))
        if self.bad: return HttpResult(200,b"not json")
        if path=="/addons/self/info":
            record=raw_record(); record["paused"]=self.paused
            data={"options": {"coordinators":[{"name":"First","ip":"172.31.254.2"}],"recovery":config([record])}}
        elif path=="/jobs/info": data={"jobs":[{"reference":B.addon_slug,"done":False,"name":"addon_update","child_jobs":[]}] if self.busy else []}
        else: data={"name":"Zigbee2MQTT","slug":B.addon_slug,"state":"started","version":"2.14.2-1","run_id":"run1"}
        return HttpResult(self.status,json.dumps({"result":"ok","data":data}).encode())


def client(t): return SupervisorClient("private-example",t,(B,),settings())


def test_observe_and_only_fixed_commands_allowed():
    t=Transport(); c=client(t)
    assert c.observe(B).state=="started" and not c.observe(B).busy
    assert c.command(B,"restart").accepted
    assert ("POST","/addons/abc_zigbee2mqtt/restart") in t.calls
    with pytest.raises(ValueError): c.command(B,"stop")
    with pytest.raises(ValueError): c.command(replace(B,addon_slug="core"),"restart")


@pytest.mark.parametrize("status,bad",[(401,False),(403,False),(500,False),(200,True)])
def test_api_failure_is_unknown_and_does_not_disclose_token(status,bad):
    t=Transport(); t.status=status; t.bad=bad; c=client(t)
    assert not c.observe(B).available and c.self_controls()=={}
    result=c.command(B,"start")
    assert not result.accepted and "private-example" not in repr(result)


def test_hot_pause_comes_from_current_self_options():
    t=Transport(); c=client(t)
    assert not c.self_controls()[B.key].paused
    t.paused=True
    assert c.self_controls()[B.key].paused
    assert all(method=="GET" for method,path in t.calls)


def test_active_job_blocks_recovery():
    t=Transport(); t.busy=True
    assert client(t).observe(B).busy


def test_malformed_jobs_cannot_mean_idle():
    t=Transport(); original=t.request
    t.request=lambda method,path,body=None,timeout=5: HttpResult(200,b'{"result":"ok","data":{"bad":[]}}') if path=="/jobs/info" else original(method,path,body,timeout)
    assert client(t).observe(B).busy


def test_changed_live_binding_cannot_authorize_old_binding():
    t=Transport(); original=t.request
    def request(method,path,body=None,timeout=5):
        r=original(method,path,body,timeout)
        if path=="/addons/self/info":
            data=json.loads(r.body); data["data"]["options"]["recovery"]["networks"][0]["base_topic"]="different"
            return HttpResult(200,json.dumps(data).encode())
        return r
    t.request=request
    assert client(t).self_controls()=={}

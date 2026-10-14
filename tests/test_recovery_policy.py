from dataclasses import replace
import pytest
from app.recovery.model import *
from app.recovery.policy import evaluate

B=Binding("a","172.31.254.2","abc_zigbee2mqtt","z2m/a","0x00124b0000000001")
C=Controls(True,False,"revision",0)
A=AppObservation(True,"stopped","old",False,True)

def observation(t,**kwargs):
    return Observation(t,network_ready=True,present=True,supervisor=A,controls=replace(C,observed_at=t),
                       mqtt_connected=True,generation="g",**kwargs)

def ready_state():
    state=RecoveryState()
    for t in (0,30,60):
        d=evaluate(B,state,observation(t),Budget(),t); state=d.state
    return d

def test_only_three_successes_and_sixty_seconds_allow_start():
    d=ready_state()
    assert d.action and d.action.kind=="start"
    state=RecoveryState()
    for t in (0,1,2): state=evaluate(B,state,observation(t),Budget(),t).state
    assert evaluate(B,state,observation(3),Budget(),3).action is None


def test_same_observation_cannot_count_three_times():
    state=RecoveryState(); obs=observation(0)
    for t in (0,30,60): state=evaluate(B,state,obs,Budget(),t).state
    assert state.successes==1


def test_month_absence_does_not_cancel_observation():
    state=RecoveryState()
    for t in (0,30,60,30*86400):
        d=evaluate(B,state,replace(observation(t),present=False),Budget(),t); state=d.state
    assert d.action is None and state.phase=="absent"
    for t in (30*86400+30,30*86400+60,30*86400+90):
        d=evaluate(B,state,observation(t),Budget(),t); state=d.state
    assert d.action and d.action.kind=="start"


@pytest.mark.parametrize("change,reason", [({"present":None},"measurement_unknown"),
 ({"network_ready":False},"network_unavailable"),({"conflict":True},"address_conflict"),
 ({"mqtt_connected":False},"mqtt_unavailable"),({"identity_match":False},"identity_mismatch"),
 ({"controls":None},"permission_unknown"),({"controls":Controls(False,False,"r",100)},"disabled"),
 ({"controls":Controls(True,True,"r",100)},"maintenance"),
 ({"supervisor":AppObservation()},"supervisor_unavailable"),
 ({"supervisor":replace(A,busy=True)},"app_busy"),
 ({"supervisor":replace(A,binding_valid=False)},"binding_invalid")])
def test_unsafe_conditions_never_command(change,reason):
    d=evaluate(B,ready_state().state,replace(observation(100),**change),Budget(),100)
    assert d.action is None and d.reason==reason


@pytest.mark.parametrize("budget",[Budget(4,4),Budget(0,10),Budget(0,0,False)])
def test_budgets_and_untrusted_clock_block_actions(budget):
    assert evaluate(B,ready_state().state,observation(100),budget,100).action is None


def test_pending_outcome_blocks_duplicate_command():
    state=replace(ready_state().state,pending_action="receipt")
    assert evaluate(B,state,observation(100),Budget(),100).reason=="command_pending"


def test_radio_failure_alone_never_restarts_healthy_app():
    obs=replace(observation(100,mqtt_health=True,identity_match=True,radio=False),supervisor=replace(A,state="started"))
    d=evaluate(B,ready_state().state,obs,Budget(),100)
    assert d.action is None and d.state.phase=="degraded"


def test_started_application_gets_startup_grace_before_restart():
    state=RecoveryState(); actions=[]
    for n,t in enumerate((0,30,60,120,180,210)):
        obs=replace(observation(t,mqtt_health=False),supervisor=replace(A,state="started"),health_sequence=n)
        d=evaluate(B,state,obs,Budget(),t); state=d.state
        if t<180: assert d.action is None
        if d.action: actions.append((t,d.action.kind))
    assert actions==[(180,"restart")]


def test_generation_change_invalidates_radio_and_return_stability():
    state=ready_state().state
    d=evaluate(B,state,replace(observation(100),generation="new"),Budget(),100)
    assert d.action is None and d.state.successes==1


def test_flap_does_not_reset_attempt_stage_or_deadline():
    state=replace(ready_state().state,attempt_stage=3,next_attempt=4000)
    state=evaluate(B,state,replace(observation(100),present=False),Budget(),100).state
    d=evaluate(B,state,observation(130),Budget(),130)
    assert d.state.attempt_stage==3 and d.state.next_attempt==4000 and d.action is None


def test_stale_permission_cannot_authorize_command():
    assert evaluate(B,ready_state().state,replace(observation(100),controls=C),Budget(),100).reason=="permission_unknown"

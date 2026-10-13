from dataclasses import replace
import sqlite3
import pytest
from app.recovery.model import Action, RecoveryState
from app.recovery.store import RecoveryStore, StoreError


def test_pending_command_survives_reopen(tmp_path):
    path=tmp_path/"state.sqlite"; s=RecoveryStore(path)
    receipt=s.reserve(Action("start","net1","generation1"),1000,"r1",run_id="before")
    s.close(); again=RecoveryStore(path)
    assert again.load("net1").pending_action==receipt
    assert again.pending("net1")["run_id"]=="before"
    assert again.command_count("net1",0)==1
    with pytest.raises(StoreError): again.reserve(Action("start","net1","g"),1001,"r1")
    again.resolve(receipt,"confirmed","after")
    assert again.load("net1").pending_action is None
    assert again.command_count("net1",0)==1


def test_networks_have_independent_states_and_budgets(tmp_path):
    s=RecoveryStore(tmp_path/"state.sqlite")
    s.save("a",RecoveryState(phase="paused",incident_id="incident"))
    s.reserve(Action("start","b","g"),10,"r")
    assert s.load("a").phase=="paused" and s.load("a").pending_action is None
    assert s.command_count("a",0)==0 and s.command_count("b",0)==1


def test_state_save_cannot_overwrite_pending_receipt(tmp_path):
    s=RecoveryStore(tmp_path/"state.sqlite")
    receipt=s.reserve(Action("restart","a","g"),10,"r")
    s.save("a",RecoveryState(phase="checking"))
    assert s.load("a").pending_action==receipt


def test_cancelled_reservation_still_counts_and_does_not_erase_other_network(tmp_path):
    s=RecoveryStore(tmp_path/"state.sqlite")
    receipt=s.reserve(Action("start","a","g"),1000,"r")
    s.resolve(receipt,"cancelled",None)
    assert s.command_count("a",999)==1
    assert s.command_count("a",1001)==0
    assert s.load("a").pending_action is None


def test_corruption_is_never_replaced(tmp_path):
    path=tmp_path/"state.sqlite"; path.write_bytes(b"broken database")
    with pytest.raises(StoreError): RecoveryStore(path)
    assert path.read_bytes()==b"broken database"


def test_invalid_state_fails_closed(tmp_path):
    path=tmp_path/"state.sqlite"; s=RecoveryStore(path)
    s.save("a",RecoveryState()); s.close()
    conn=sqlite3.connect(path); conn.execute("UPDATE states SET payload='{}'"); conn.commit(); conn.close()
    with pytest.raises(StoreError): RecoveryStore(path).load("a")


def test_receipt_resolution_cannot_target_another_network(tmp_path):
    s=RecoveryStore(tmp_path/"state.sqlite")
    a=s.reserve(Action("start","a","g"),1,"r"); b=s.reserve(Action("start","b","g"),1,"r")
    s.resolve(a,"confirmed","new")
    assert s.load("b").pending_action==b
    with pytest.raises(StoreError): s.resolve("missing","confirmed",None)


def test_store_exception_does_not_include_database_content(tmp_path):
    s=RecoveryStore(tmp_path/"state.sqlite"); s.close()
    with pytest.raises(StoreError) as error: s.load("private-example")
    assert "private-example" not in str(error.value)

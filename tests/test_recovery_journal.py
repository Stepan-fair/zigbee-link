import json
from pathlib import Path
import pytest
from app.recovery.journal import EventJournal,SafeEvent


def test_safe_fields_only_no_secret_payloads(tmp_path):
    j=EventJournal(tmp_path,clock=lambda:1000)
    j.emit(SafeEvent("coordinator_absent","172.31.254.2",phase="absent",facts={"misses":3,"password":"private-example"}))
    text=(tmp_path/"events.0.jsonl").read_text()
    assert "private-example" not in text and "password" not in text
    assert json.loads(text)["facts"]=={"misses":3}
    with pytest.raises(ValueError): j.emit({"code":"coordinator_absent","token":"private-example"})


def test_control_characters_cannot_inject_log_entries(tmp_path):
    j=EventJournal(tmp_path,clock=lambda:1000)
    with pytest.raises(ValueError): j.emit(SafeEvent("coordinator_absent\nforged","172.31.254.2"))
    assert not list(tmp_path.glob("*.jsonl"))


def test_rotation_is_bounded_and_repeated_waiting_is_summarized(tmp_path):
    now=[1000.0]; j=EventJournal(tmp_path,max_bytes=4096,clock=lambda:now[0])
    for n in range(100):
        now[0]+=301
        j.emit(SafeEvent("coordinator_absent","172.31.254.2",phase="absent",facts={"misses":n}))
    assert sum(p.stat().st_size for p in tmp_path.glob("events.*.jsonl"))<=4096
    before=sum(p.stat().st_size for p in tmp_path.glob("events.*.jsonl"))
    j.emit(SafeEvent("coordinator_absent","172.31.254.2",phase="absent"))
    assert sum(p.stat().st_size for p in tmp_path.glob("events.*.jsonl"))==before


def test_full_disk_does_not_raise_into_recovery(tmp_path,monkeypatch):
    j=EventJournal(tmp_path)
    monkeypatch.setattr(Path,"open",lambda *a,**k: (_ for _ in ()).throw(OSError("disk full")))
    assert j.emit(SafeEvent("coordinator_absent","172.31.254.2")) is False


def test_debug_expires_and_old_details_are_removed(tmp_path):
    now=[1000.0]; j=EventJournal(tmp_path,clock=lambda:now[0]); j.enable_debug()
    assert j.debug_enabled
    j.emit(SafeEvent("coordinator_absent","172.31.254.2"))
    now[0]+=31*86400
    assert not j.debug_enabled
    j.emit(SafeEvent("coordinator_absent","172.31.254.2"))
    assert all(json.loads(line)["utc"]>=1000+31*86400 for p in tmp_path.glob("*.jsonl") for line in p.read_text().splitlines())

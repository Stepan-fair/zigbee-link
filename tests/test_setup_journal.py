import json
from app.recovery.journal import EventJournal, SafeEvent


def test_setup_events_enumerate_source_mode_revision_and_drop_raw_facts(tmp_path):
    journal = EventJournal(tmp_path)
    journal.emit(SafeEvent("setup_edit", "setup", action="source_manual", outcome="mode_guided",
                           facts={"revision": 7, "candidate_count": 2, "network_count": 2,
                                  "username": "private-marker", "payload": "private-marker"}))
    raw = (tmp_path / "events.0.jsonl").read_text()
    event = json.loads(raw)
    assert event["facts"] == {"revision": 7, "candidate_count": 2, "network_count": 2}
    assert "private-marker" not in raw

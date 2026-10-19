from dataclasses import replace
import sqlite3
import pytest
from app.setup.model import SetupSnapshot, NetworkRecord, FieldValue, Catalog, Candidate, Transition


def record(name="a"):
    return NetworkRecord(name, "network:" + name,
                         {"name": FieldValue("manual", name, "user", 1, "verified")}, True, True, True)


def test_manual_value_survives_reopen_and_catalog_refresh(tmp_path):
    from app.setup.store import SetupStore
    path = tmp_path / "setup.sqlite"
    store = SetupStore(path)
    saved = store.save(SetupSnapshot(networks=(record(),)), expected_revision=0)
    assert saved.revision == 1
    store.save_catalog(Catalog(candidates=(Candidate("c", {}, (), "proposed"),)), expected_revision=0)
    store.close()
    with SetupStore(path) as reopened:
        assert reopened.snapshot().networks[0].fields["name"].value == "a"
        assert reopened.snapshot().networks[0].paused is True
        assert reopened.catalog().candidates[0].candidate_id == "c"
        assert reopened.snapshot().revision == 1


def test_stale_editor_cannot_unpause(tmp_path):
    from app.setup.store import SetupStore, RevisionConflict
    with SetupStore(tmp_path / "setup.sqlite") as store:
        stale = store.snapshot()
        store.save(replace(stale, networks=(record(),)), expected_revision=0)
        with pytest.raises(RevisionConflict):
            store.save(replace(stale, networks=(replace(record(), paused=False),)), expected_revision=0)
        assert store.snapshot().networks[0].paused


def test_identity_alias_reuses_legacy_budget_key(tmp_path):
    from app.setup.store import SetupStore
    path = tmp_path / "setup.sqlite"
    with SetupStore(path) as store:
        first = store.state_key(("broker-a", "0x0000000000000001"), legacy_key="172.31.254.2",
                                addon_slug="a_zigbee2mqtt")
    with SetupStore(path) as store:
        assert first[1] == "172.31.254.2"
        assert store.state_key(("broker-a", "0x0000000000000001")) == first
        assert store.state_key(("broker-a", "0x0000000000000002"), addon_slug="a_zigbee2mqtt") == first


def test_tombstone_readd_preserves_key(tmp_path):
    from app.setup.store import SetupStore
    with SetupStore(tmp_path / "setup.sqlite") as store:
        identity = ("b", "0x0000000000000001")
        network_id, key = store.state_key(identity)
        row = replace(record(), network_id=network_id, state_key=key)
        store.save(SetupSnapshot(networks=(row,)), expected_revision=0)
        store.tombstone(network_id, expected_revision=1)
        assert store.state_key(identity) == (network_id, key)
        assert store.snapshot().networks[0].tombstoned
        assert not store.snapshot().networks[0].managed


def test_corrupt_record_isolated_and_original_preserved(tmp_path):
    from app.setup.store import SetupStore
    with SetupStore(tmp_path / "setup.sqlite") as store:
        store.save(SetupSnapshot(networks=(record("a"), record("b"))), expected_revision=0)
        store.db.execute("UPDATE networks SET payload=? WHERE network_id=?", ("broken{", "a"))
        store.db.commit()
        snapshot = store.snapshot()
        rows = {n.network_id: n for n in snapshot.networks}
        assert not rows["a"].managed and rows["a"].paused
        assert rows["a"].issues == ("record_corrupt",)
        assert rows["b"].managed
        store.save(replace(snapshot, enabled=True), expected_revision=1)
        assert store.db.execute("SELECT payload FROM networks WHERE network_id='a'").fetchone()[0] == "broken{"


def test_failed_transaction_does_not_advance_revision(tmp_path):
    from app.setup.store import SetupStore, SetupStoreError
    with SetupStore(tmp_path / "setup.sqlite") as store:
        store.db.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK)
        with pytest.raises(SetupStoreError):
            store.save(SetupSnapshot(networks=(record(),)), expected_revision=0)
        store.db.set_authorizer(None)
        assert store.snapshot() == SetupSnapshot()


def test_unknown_schema_and_corrupt_database_fail_closed(tmp_path):
    from app.setup.store import SetupStore, SetupStoreError
    path = tmp_path / "future.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(SetupStoreError):
        SetupStore(path)
    path = tmp_path / "corrupt.sqlite"
    path.write_bytes(b'corrupt database')
    with pytest.raises(SetupStoreError):
        SetupStore(path)


def test_transition_survives_reopen(tmp_path):
    from app.setup.store import SetupStore
    transition = Transition("receipt", "legacy", "guided", "digest", 0, "prepared")
    with SetupStore(tmp_path / "setup.sqlite") as store:
        store.save_transition(transition)
    with SetupStore(tmp_path / "setup.sqlite") as store:
        assert store.transition() == transition


def test_actual_sqlite_full_rolls_back_the_entire_save(tmp_path):
    from app.setup.store import SetupStore, SetupStoreError
    with SetupStore(tmp_path / "setup.sqlite") as store:
        pages = store.db.execute("PRAGMA page_count").fetchone()[0]
        store.db.execute(f"PRAGMA max_page_count={pages}")
        rows = tuple(replace(record(str(i)), managed=False, accepted=False,
                     fields={"name": FieldValue("manual", "a" * 100, "user", 0, "verified")}) for i in range(253))
        with pytest.raises(SetupStoreError):
            store.save(SetupSnapshot(networks=rows), expected_revision=0)
        assert store.snapshot() == SetupSnapshot()


def test_replacement_alias_conflict_does_not_move_other_network(tmp_path):
    from app.setup.store import SetupStore, SetupStoreError
    with SetupStore(tmp_path / "setup.sqlite") as store:
        first = store.state_key(("b", "0x0000000000000001"), addon_slug="a_zigbee2mqtt")
        second = store.state_key(("b", "0x0000000000000002"), addon_slug="b_zigbee2mqtt")
        with pytest.raises(SetupStoreError):
            store.bind_alias(first[0], ("b", "0x0000000000000002"), expected_revision=0)
        assert store.state_key(("b", "0x0000000000000002")) == second
        assert store.snapshot().revision == 0

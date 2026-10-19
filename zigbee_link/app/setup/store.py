"""Accepted configuration and identity history; never rewrites recovery quotas."""
from contextlib import contextmanager
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import uuid
from .model import (SetupSnapshot, NetworkRecord, FieldValue, BrokerRecord, Catalog, Candidate, Transition)
from .validation import decode_metadata, FIELDS


class SetupStoreError(RuntimeError):
    pass


class RevisionConflict(SetupStoreError):
    pass


class SetupRecordCorrupt(SetupStoreError):
    pass


def _encode(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    decode_metadata(raw.encode())
    return raw


def _fields(raw):
    if not isinstance(raw, dict) or set(raw) - FIELDS:
        raise ValueError("invalid_fields")
    fields = {k: FieldValue(**v) for k, v in raw.items()}
    if any(f.mode not in ("auto", "manual") or not isinstance(f.source, str) or not isinstance(f.status, str)
           or type(f.observed_at) not in (int, float) for f in fields.values()):
        raise ValueError("invalid_fields")
    return fields


def _network(raw):
    row = NetworkRecord(**{**raw, "fields": _fields(raw["fields"]), "issues": tuple(raw.get("issues", ()))})
    if any(type(v) is not bool for v in (row.managed, row.paused, row.accepted, row.tombstoned)):
        raise ValueError("invalid_controls")
    for value in (row.network_id, row.state_key):
        if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,100}", value):
            raise ValueError("invalid_identity")
    return row


def _broker(raw):
    if raw is None:
        return None
    return BrokerRecord(**{**raw, "aliases": tuple(raw.get("aliases", ()))})


class SetupStore:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise ValueError("unsafe_state")
            self.db = sqlite3.connect(path, timeout=5, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            os.chmod(path, 0o600)
            with self.transaction():
                if self.db.execute("PRAGMA user_version").fetchone()[0] not in (0, 1):
                    raise SetupStoreError("setup_schema_unsupported")
                self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,payload TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS networks (network_id TEXT PRIMARY KEY,state_key TEXT NOT NULL,payload TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS identities (network_id TEXT PRIMARY KEY,state_key TEXT NOT NULL UNIQUE)")
                self.db.execute("CREATE TABLE IF NOT EXISTS aliases (kind TEXT NOT NULL,value TEXT NOT NULL,network_id TEXT NOT NULL,PRIMARY KEY(kind,value))")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES ('setup',?)", (_encode({"revision": 0, "enabled": False, "broker": None}),))
                self.db.execute("PRAGMA user_version=1")
        except (sqlite3.Error, OSError, ValueError, SetupStoreError):
            if hasattr(self, "db"):
                self.db.close()
            raise SetupStoreError("setup_store_unavailable") from None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def transaction(self):
        with self.lock:
            outer = not self.db.in_transaction
            try:
                if outer:
                    self.db.execute("BEGIN IMMEDIATE")
                yield
                if outer:
                    self.db.commit()
            except Exception as exc:
                if outer:
                    self.db.rollback()
                if isinstance(exc, (sqlite3.Error, OSError, ValueError, TypeError, KeyError)):
                    raise SetupStoreError("setup_store_unavailable") from None
                raise

    def _meta(self, key):
        row = self.db.execute("SELECT payload FROM meta WHERE key=?", (key,)).fetchone()
        return decode_metadata(row[0].encode()) if row else None

    def _put(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, _encode(value)))

    def _revision(self, expected):
        if type(expected) is not int or self._meta("setup")["revision"] != expected:
            raise RevisionConflict("setup_revision_conflict")

    def snapshot(self):
        with self.transaction():
            meta = self._meta("setup")
            if type(meta["revision"]) is not int or meta["revision"] < 0 or type(meta["enabled"]) is not bool:
                raise SetupStoreError("setup_state_corrupt")
            records = []
            for row in self.db.execute("SELECT * FROM networks ORDER BY network_id"):
                try:
                    record = _network(decode_metadata(row["payload"].encode()))
                    if record.network_id != row["network_id"] or record.state_key != row["state_key"]:
                        raise ValueError("identity_changed")
                except (ValueError, TypeError, KeyError, AttributeError):
                    record = NetworkRecord(row["network_id"], row["state_key"], {}, False, True, False,
                                           issues=("record_corrupt",))
                records.append(record)
            return SetupSnapshot(meta["revision"], meta["enabled"], _broker(meta["broker"]), tuple(records))

    def save(self, snapshot, *, expected_revision):
        with self.transaction():
            self._revision(expected_revision)
            if type(snapshot.enabled) is not bool or len(snapshot.networks) > 253:
                raise ValueError("invalid_snapshot")
            if len({r.network_id for r in snapshot.networks}) != len(snapshot.networks):
                raise ValueError("duplicate_network")
            incoming = {r.network_id for r in snapshot.networks}
            for old in self.snapshot().networks:
                if old.network_id not in incoming:
                    tomb = replace(old, managed=False, paused=True, tombstoned=True)
                    self.db.execute("UPDATE networks SET payload=? WHERE network_id=?", (_encode(asdict(tomb)), old.network_id))
            for record in snapshot.networks:
                _network(asdict(record))
                old = self.db.execute("SELECT state_key FROM identities WHERE network_id=?", (record.network_id,)).fetchone()
                if old and old[0] != record.state_key:
                    raise ValueError("state_key_pinned")
                self.db.execute("INSERT OR IGNORE INTO identities VALUES (?,?)", (record.network_id, record.state_key))
                if "record_corrupt" in record.issues:
                    continue
                self.db.execute("INSERT OR REPLACE INTO networks VALUES (?,?,?)",
                                (record.network_id, record.state_key, _encode(asdict(record))))
            self._put("setup", {"revision": expected_revision + 1, "enabled": snapshot.enabled,
                                "broker": asdict(snapshot.broker) if snapshot.broker else None})
            return self.snapshot()

    def state_key(self, identity, *, legacy_key=None, addon_slug=None):
        if not isinstance(identity, tuple) or len(identity) != 2 or any(not isinstance(v, str) or not 0 < len(v) <= 300 for v in identity):
            raise SetupStoreError("invalid_identity")
        aliases = [("identity", _encode(identity))]
        if addon_slug:
            aliases.append(("addon", addon_slug))
        if legacy_key:
            aliases.append(("state", legacy_key))
        with self.transaction():
            owners = {r[0] for kind, value in aliases for r in self.db.execute(
                "SELECT network_id FROM aliases WHERE kind=? AND value=?", (kind, value))}
            if len(owners) > 1:
                raise SetupStoreError("identity_conflict")
            if owners:
                network_id = owners.pop()
                key = self.db.execute("SELECT state_key FROM identities WHERE network_id=?", (network_id,)).fetchone()[0]
            else:
                network_id = str(uuid.uuid4())
                key = legacy_key or "network:" + network_id
                self.db.execute("INSERT INTO identities VALUES (?,?)", (network_id, key))
            for kind, value in aliases:
                self.db.execute("INSERT OR IGNORE INTO aliases VALUES (?,?,?)", (kind, value, network_id))
            return network_id, key

    def bind_alias(self, network_id, identity, *, addon_slug=None, expected_revision):
        with self.transaction():
            self._revision(expected_revision)
            if not self.db.execute("SELECT 1 FROM identities WHERE network_id=?", (network_id,)).fetchone():
                raise SetupStoreError("unknown_network")
            aliases = [("identity", _encode(identity))] + ([("addon", addon_slug)] if addon_slug else [])
            for kind, value in aliases:
                old = self.db.execute("SELECT network_id FROM aliases WHERE kind=? AND value=?", (kind, value)).fetchone()
                if old and old[0] != network_id:
                    raise SetupStoreError("identity_conflict")
                self.db.execute("INSERT OR IGNORE INTO aliases VALUES (?,?,?)", (kind, value, network_id))
            return self.save(self.snapshot(), expected_revision=expected_revision)

    def tombstone(self, network_id, *, expected_revision):
        with self.transaction():
            snapshot = self.snapshot()
            records = tuple(replace(r, tombstoned=True, managed=False, paused=True) if r.network_id == network_id else r
                            for r in snapshot.networks)
            return self.save(replace(snapshot, networks=records), expected_revision=expected_revision)

    def catalog(self):
        with self.transaction():
            raw = self._meta("catalog")
            if raw is None:
                return Catalog()
            return Catalog(raw["revision"], tuple(Candidate(v["candidate_id"], _fields(v["fields"]),
                           tuple(v["issues"]), v["match_kind"]) for v in raw["candidates"]), tuple(raw["issues"]))

    def save_catalog(self, catalog, *, expected_revision):
        with self.transaction():
            if self.catalog().revision != expected_revision:
                raise RevisionConflict("catalog_revision_conflict")
            if len(catalog.candidates) > 253:
                raise ValueError("catalog_limit")
            self._put("catalog", asdict(replace(catalog, revision=expected_revision + 1)))
            return self.catalog()

    def transition(self):
        with self.transaction():
            raw = self._meta("transition")
            return Transition(**raw) if raw else None

    def save_transition(self, value):
        with self.transaction():
            if value.source_mode not in ("legacy", "guided") or value.target_mode not in ("legacy", "guided") or value.phase not in ("prepared", "options_written", "verified", "blocked"):
                raise ValueError("transition_invalid")
            self._put("transition", asdict(value))

    def close(self):
        with self.lock:
            self.db.close()

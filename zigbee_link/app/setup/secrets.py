"""Immutable local credentials. Call collection with configuration writers stopped."""
import json
import os
from pathlib import Path
import re
import threading
import uuid
from .validation import decode_metadata

REFERENCE = re.compile(r"s-[0-9a-f]{32}\.json")


class SecretStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.lock = threading.RLock()
        if directory.is_symlink():
            raise OSError("secret_store_unsafe")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)

    def _path(self, ref):
        if not isinstance(ref, str) or not REFERENCE.fullmatch(ref):
            raise ValueError("invalid_secret_reference")
        path = self.directory / ref
        if self.directory.is_symlink() or path.is_symlink():
            raise OSError("secret_store_unsafe")
        return path

    def write(self, username, password):
        if any(not isinstance(v, str) or len(v) > 1024 for v in (username, password)):
            raise ValueError("invalid_credentials")
        with self.lock:
            ref = "s-" + uuid.uuid4().hex + ".json"
            path = self._path(ref)
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(json.dumps({"username": username, "password": password}).encode())
                target.flush()
                os.fsync(target.fileno())
            if os.name == "posix":
                descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            return ref

    def read(self, secret_ref):
        with self.lock:
            path = self._path(secret_ref)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                payload = source.read(16385)
            if len(payload) > 16384:
                raise ValueError("secret_invalid")
            raw = decode_metadata(payload)
            if not isinstance(raw, dict) or set(raw) != {"username", "password"} or any(not isinstance(v, str) or len(v) > 1024 for v in raw.values()):
                raise ValueError("secret_invalid")
            return raw["username"], raw["password"]

    def collect(self, referenced):
        with self.lock:
            for path in self.directory.glob("s-*.json"):
                if REFERENCE.fullmatch(path.name) and path.name not in referenced:
                    self._path(path.name).unlink()

import os
import stat
import pytest


def test_secret_roundtrip_and_unused_blob_collection(tmp_path):
    from app.setup.secrets import SecretStore
    store = SecretStore(tmp_path / "secrets")
    old = store.write("user", "private-marker")
    orphan = store.write("user2", "orphan-marker")
    store.collect({old})
    assert store.read(old) == ("user", "private-marker")
    assert not (tmp_path / "secrets" / orphan).exists()
    assert "private-marker" not in repr(store)


@pytest.mark.parametrize("ref", ["../options.json", "x/y", "/etc/passwd", "", "s-../../a.json"])
def test_secret_path_traversal_rejected(tmp_path, ref):
    from app.setup.secrets import SecretStore
    with pytest.raises(ValueError):
        SecretStore(tmp_path / "secrets").read(ref)


def test_missing_secret_does_not_become_empty_credentials(tmp_path):
    from app.setup.secrets import SecretStore
    with pytest.raises(OSError):
        SecretStore(tmp_path / "secrets").read("s-" + "0" * 32 + ".json")


@pytest.mark.skipif(os.name != "posix", reason="actual POSIX modes and symlink boundary")
def test_actual_posix_secret_permissions_and_symlink_denial(tmp_path):
    from app.setup.secrets import SecretStore
    store = SecretStore(tmp_path / "secrets")
    ref = store.write("u", "p")
    assert stat.S_IMODE((tmp_path / "secrets" / ref).stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "secrets").stat().st_mode) == 0o700
    (tmp_path / "secrets" / ref).unlink()
    (tmp_path / "secrets" / ref).symlink_to(tmp_path / "other")
    with pytest.raises(OSError):
        store.read(ref)

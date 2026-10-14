import importlib.util
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_manifest_clean_defaults_and_required_caps():
    m = yaml.safe_load((ROOT / "zigbee_link/config.yaml").read_text())
    assert m["options"] == {"parent": "auto", "address": "172.31.254.1/24", "coordinators": [], "scan_enabled": True, "recovery": {"enabled": False, "mqtt": {}, "networks": []}}
    assert set(m["privileged"]) == {"NET_ADMIN", "NET_RAW"}
    assert set(m["arch"]) == {"amd64", "aarch64"}
    assert m["host_network"] is True


def test_apparmor_enabled_no_full_access_or_host_pid():
    m = yaml.safe_load((ROOT / "zigbee_link/config.yaml").read_text())
    assert m.get("apparmor", True) is True
    for key in ("full_access", "host_pid", "docker_api", "homeassistant_api"):
        assert not m.get(key)
    assert not m.get("map")
    assert m["hassio_api"] is True and m["hassio_role"] == "manager"
    assert "capability net_admin" in (ROOT / "zigbee_link/apparmor.txt").read_text()


def test_package_rejects_nonempty_destination_and_symlinks(tmp_path):
    pack = load_tool("package").package
    dst = tmp_path / "dist"; dst.mkdir(); (dst / "old").write_text("old")
    with pytest.raises(ValueError): pack(ROOT, dst)
    (dst / "old").unlink()
    fake = tmp_path / "fake"; fake.mkdir()
    # Missing allowlisted files must fail before any copy.
    with pytest.raises(ValueError): pack(fake, dst)
    assert not list(dst.iterdir())


def test_distribution_contains_no_runtime_or_infrastructure(tmp_path):
    files = load_tool("package").package(ROOT, tmp_path / "dist")
    assert "repository.yaml" in [str(p).replace("\\", "/") for p in files]
    assert not any("PROGRESS" in str(p) or ".tools" in p.parts or "identity.json" in str(p) for p in files)
    assert load_tool("check_distribution").check_distribution(tmp_path / "dist") == []


def test_checker_rejects_unlisted_file_and_secret(tmp_path):
    load_tool("package").package(ROOT, tmp_path / "dist")
    (tmp_path / "dist" / "leak.key").write_text("-----BEGIN" + " PRIVATE KEY-----")
    assert load_tool("check_distribution").check_distribution(tmp_path / "dist")


def test_recovery_release_manifest_and_files_are_complete(tmp_path):
    m=yaml.safe_load((ROOT/"zigbee_link/config.yaml").read_text())
    assert m["version"]=="1.2.0"
    assert m["hassio_api"] is True and m["hassio_role"]=="manager"
    assert m["options"]["recovery"]=={"enabled":False,"mqtt":{},"networks":[]}
    pack=load_tool("package")
    for p in (ROOT/"zigbee_link/app/recovery").glob("*.py"):
        assert p.relative_to(ROOT).as_posix() in pack.ALLOWLIST
    for p in (ROOT/"tests").glob("test_recovery_*.py"):
        assert p.relative_to(ROOT).as_posix() in pack.ALLOWLIST
    assert "docs/superpowers/specs/2026-10-13-zigbee-link-recovery-design.md" not in pack.ALLOWLIST
    docker=(ROOT/"zigbee_link/Dockerfile").read_text()
    assert "paho-mqtt==2.1.0" in docker

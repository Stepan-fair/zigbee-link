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
    assert m["options"] == {"configuration_mode": "legacy", "parent": "auto", "address": "172.31.254.1/24", "coordinators": [], "scan_enabled": True, "recovery": {"enabled": False, "mqtt": {}, "networks": []}}
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
    assert m["version"]=="1.3.1"
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


def test_setup_ingress_manifest_dependencies_and_allowlist():
    manifest = yaml.safe_load((ROOT / "zigbee_link/config.yaml").read_text())
    assert manifest.get("ingress") is True and manifest.get("ingress_port") == 0
    assert manifest.get("panel_admin") is True
    assert manifest.get("services") == ["mqtt:want"]
    assert manifest["options"].get("configuration_mode") == "legacy"
    assert manifest["schema"].get("configuration_mode") == "list(legacy|guided)"
    assert "aiohttp==3.14.5" in (ROOT / "zigbee_link/Dockerfile").read_text()
    assert "/opt/zigbee-deps/**/*.so mr," in (ROOT / "zigbee_link/apparmor.txt").read_text()
    for directory in (ROOT / "zigbee_link/app/setup", ROOT / "zigbee_link/app/web"):
        for path in directory.glob("*.py"):
            assert path.relative_to(ROOT).as_posix() in load_tool("package").ALLOWLIST


def test_ci_workflow_is_valid_yaml():
    workflow = yaml.safe_load((ROOT / ".github/workflows/verify.yml").read_text())
    assert {"linux", "arm64-build"} <= workflow["jobs"].keys()


def test_automatic_setup_release_manifest_and_neutral_defaults():
    manifest = yaml.safe_load((ROOT / "zigbee_link/config.yaml").read_text())
    assert manifest["version"] == "1.3.1"
    assert manifest["options"]["configuration_mode"] == "legacy"
    assert manifest["options"]["recovery"] == {"enabled": False, "mqtt": {}, "networks": []}
    assert manifest["options"]["coordinators"] == []
    assert manifest["ingress"] is True and manifest["panel_admin"] is True
    assert manifest["ingress_port"] == 0 and manifest["services"] == ["mqtt:want"]


def test_all_new_runtime_and_static_files_are_allowlisted():
    allowed = set(load_tool("package").ALLOWLIST)
    paths = list((ROOT / "zigbee_link/app/setup").glob("*.py"))
    paths += list((ROOT / "zigbee_link/app/web").glob("*.py"))
    paths += list((ROOT / "zigbee_link/app/web/static").glob("*"))
    assert all(path.relative_to(ROOT).as_posix() in allowed for path in paths if path.is_file())
    assert len(allowed) == len(load_tool("package").ALLOWLIST)


def test_package_excludes_setup_state_credentials_and_private_docs(tmp_path):
    import shutil
    source = tmp_path / "source"
    allowed = load_tool("package").ALLOWLIST
    for relative in allowed:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    import uuid
    marker = "SYNTHETIC-PRIVATE-" + uuid.uuid4().hex
    for relative in ("data/setup.sqlite", "data/recovery.sqlite", "data/setup-secrets/s-test.json", ".tools/local.txt", "docs/superpowers/private.md", "Инструкция.md"):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(marker, encoding="utf-8")
    destination = tmp_path / "clean"
    load_tool("package").package(source, destination)
    files = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
    assert files == set(allowed)
    assert all(marker.encode() not in (destination / relative).read_bytes() for relative in files)
    assert load_tool("check_distribution").check_distribution(destination) == []

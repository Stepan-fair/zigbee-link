"""Copy only audited, neutral distribution files into a new directory."""
import argparse
from pathlib import Path
import shutil

ALLOWLIST = (
    "repository.yaml", "README.md", ".gitignore", ".gitattributes", "pytest.ini",
    "zigbee_link/config.yaml", "zigbee_link/Dockerfile", "zigbee_link/run.sh",
    "zigbee_link/apparmor.txt", "zigbee_link/translations/ru.yaml",
    "zigbee_link/DOCS.md", "zigbee_link/CHANGELOG.md",
    "zigbee_link/app/__init__.py", "zigbee_link/app/config.py",
    "zigbee_link/app/network.py", "zigbee_link/app/arp.py",
    "zigbee_link/app/manager.py", "zigbee_link/app/main.py",
    "tools/package.py", "tools/check_distribution.py",
    "tests/conftest.py", "tests/test_config.py", "tests/test_network.py",
    "tests/test_arp.py", "tests/test_manager.py", "tests/test_lifecycle.py",
    "tests/test_package.py",
    "tests/linux/test_macvlan.py", ".github/workflows/verify.yml",
    "zigbee_link/app/recovery/__init__.py", "zigbee_link/app/recovery/model.py",
    "zigbee_link/app/recovery/settings.py", "zigbee_link/app/recovery/store.py",
    "zigbee_link/app/recovery/policy.py", "zigbee_link/app/recovery/supervisor.py",
    "zigbee_link/app/recovery/mqtt.py", "zigbee_link/app/recovery/radio.py",
    "zigbee_link/app/recovery/journal.py", "zigbee_link/app/recovery/service.py",
    "tests/test_recovery_settings.py", "tests/test_recovery_store.py",
    "tests/test_recovery_policy.py", "tests/test_target_probe.py",
    "tests/test_recovery_supervisor.py", "tests/test_recovery_mqtt.py",
    "tests/test_recovery_radio.py", "tests/test_recovery_journal.py",
    "tests/test_recovery_service.py", "tests/test_recovery_main.py",
    "tests/linux/test_recovery_runtime.py",
    "tests/linux/recovery_fixture.py",
)


def package(source: Path, destination: Path) -> list[Path]:
    source = source.resolve()
    if destination.exists() and (destination.is_symlink() or not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("Output must be a new empty directory")
    target = destination.resolve()
    if target == source or source in target.parents:
        raise ValueError("Output cannot be inside the source directory")
    for relative in ALLOWLIST:
        path = source / relative
        if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents) if p != source.parent and source in (p, *p.parents)):
            raise ValueError(f"Missing or unsafe distribution file: {relative}")
    destination.mkdir(parents=True, exist_ok=True)
    for relative in ALLOWLIST:
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        # Normalize all shipped text so scripts also work when developed on Windows.
        path.write_bytes((source / relative).read_bytes().replace(b"\r\n", b"\n"))
    return [Path(p) for p in ALLOWLIST]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    files = package(Path(__file__).resolve().parents[1], args.output)
    print(f"Packaged {len(files)} allowlisted files")

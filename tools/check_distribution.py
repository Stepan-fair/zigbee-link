import argparse
from pathlib import Path
import re
import yaml
from package import ALLOWLIST


def check_distribution(root: Path, forbidden: tuple[str, ...] = ()) -> list[str]:
    errors = []
    actual = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if ".git" in path.relative_to(root).parts or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
            continue
        if path.is_symlink():
            errors.append(f"Symlink: {relative}")
        elif path.is_file():
            actual.add(relative)
            try:
                text = path.read_text(encoding="utf-8")
                if any(value and value in text for value in forbidden):
                    errors.append(f"Private context detected in {relative}")
                if ("-----BEGIN" + " PRIVATE KEY-----") in text or ("-----BEGIN" + " OPENSSH PRIVATE KEY-----") in text or re.search(r"gh[pousr]_[A-Za-z0-9]{36,}", text):
                    errors.append(f"Credential marker detected in {relative}")
                if "\r" in text:
                    errors.append(f"Non-LF text: {relative}")
            except UnicodeError:
                errors.append(f"Unexpected binary file: {relative}")
    if actual != set(ALLOWLIST):
        errors.append("File list does not match allowlist")
    try:
        repo = yaml.safe_load((root / "repository.yaml").read_text(encoding="utf-8"))
        m = yaml.safe_load((root / "zigbee_link/config.yaml").read_text(encoding="utf-8"))
        if repo.get("name") != "Zigbee Link" or m.get("slug") != "zigbee_link":
            errors.append("Invalid repository/app identity")
        if m.get("options") != {"parent": "auto", "address": "172.31.254.1/24", "coordinators": [], "scan_enabled": True}:
            errors.append("Non-neutral defaults")
        if m.get("apparmor") is not True or set(m.get("privileged", [])) != {"NET_ADMIN", "NET_RAW"} or any(m.get(k) for k in ("full_access", "host_pid", "docker_api", "map", "hassio_api", "homeassistant_api")):
            errors.append("Unexpected permissions")
    except (OSError, ValueError, AttributeError, yaml.YAMLError):
        errors.append("Invalid manifest")
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--forbidden-file", type=Path)
    args = parser.parse_args()
    values = tuple(args.forbidden_file.read_text(encoding="utf-8").splitlines()) if args.forbidden_file else ()
    errors = check_distribution(args.root, values)
    for error in errors: print(error)
    print("Distribution check: " + ("FAILED" if errors else "PASS"))
    raise SystemExit(bool(errors))

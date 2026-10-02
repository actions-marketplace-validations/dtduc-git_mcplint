"""Lockfile support: pin server fingerprints and detect drift (rug pulls)."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Finding, MCPConfigFile, Severity
from .packages import package_display, package_specs
from .rules.model import Rule

LOCKFILE_NAME = ".mcplint.lock.json"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _secret_hash(salt: str, value: str) -> str:
    # The salt is stored in the lockfile, so this is change detection, not a
    # secret store: it only makes casual eyeballing of env values harder. The
    # rest of the fingerprint (command, url) is hashed without a salt — treat a
    # committed lockfile as sensitive when configs may embed credentials.
    return _sha256_text(f"{salt}:{value}")[:16]


def rel_to(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _server_fingerprint(server: Any, salt: str) -> dict[str, Any]:
    specs = package_specs(server)
    payload = {
        "name": server.name,
        "transport": server.transport,
        "command": server.command,
        "url": server.url,
        "headers": sorted(server.headers),
        "env": {key: _secret_hash(salt, value) for key, value in sorted(server.env.items())},
    }
    return {
        "fingerprint": _sha256_text(json.dumps(payload, sort_keys=True)),
        "transport": server.transport,
        "package": package_display(specs[0]) if specs else None,
    }


def build_lock(configs: list[MCPConfigFile], root: Path) -> dict[str, Any]:
    salt = secrets.token_hex(16)
    files: dict[str, Any] = {}
    for config in configs:
        files[rel_to(config.path, root)] = {
            "sha256": _sha256_file(config.path),
            "servers": {
                server.name: _server_fingerprint(server, salt) for server in config.servers
            },
        }
    return {
        "lockfileVersion": 1,
        "generatedAt": datetime.now(UTC).isoformat(),
        "salt": salt,
        "files": files,
    }


def load_lock(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _finding(rule: Rule, path: Any, message: str, severity: Severity | None = None) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        title=rule.title,
        message=message,
        file=str(path),
        line=1,
        owasp=rule.owasp or None,
        remediation=rule.remediation or None,
    )


def verify_lock(
    lock: dict[str, Any], configs: list[MCPConfigFile], root: Path, rule: Rule
) -> list[Finding]:
    findings: list[Finding] = []
    locked_files: dict[str, Any] = lock.get("files", {})
    salt = str(lock.get("salt", ""))
    seen: set[str] = set()

    for config in configs:
        rel = rel_to(config.path, root)
        seen.add(rel)
        entry = locked_files.get(rel)
        if entry is None:
            findings.append(
                _finding(
                    rule,
                    config.path,
                    f"'{rel}' is not covered by {LOCKFILE_NAME} — run 'mcplint lock' to pin it",
                    severity=Severity.MEDIUM,
                )
            )
            continue

        locked_servers: dict[str, Any] = entry.get("servers", {})
        current_names = {server.name for server in config.servers}
        for server in config.servers:
            locked = locked_servers.get(server.name)
            if locked is None:
                findings.append(
                    _finding(
                        rule,
                        config.path,
                        f"server '{server.name}' is new — not covered by the lockfile",
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if _server_fingerprint(server, salt)["fingerprint"] != locked.get("fingerprint"):
                findings.append(
                    _finding(
                        rule,
                        config.path,
                        f"server '{server.name}' changed since it was locked — possible rug pull "
                        "(review the diff, then re-run 'mcplint lock')",
                        severity=Severity.HIGH,
                    )
                )
        for locked_name in locked_servers:
            if locked_name not in current_names:
                findings.append(
                    _finding(
                        rule,
                        config.path,
                        f"locked server '{locked_name}' was removed",
                        severity=Severity.MEDIUM,
                    )
                )

    for rel in locked_files:
        if rel not in seen:
            findings.append(
                _finding(
                    rule,
                    root / rel,
                    f"locked file '{rel}' is missing from the current scan",
                    severity=Severity.HIGH,
                )
            )
    return findings

"""Built-in check implementations, dispatched by ``rule.check``."""

from __future__ import annotations

import json
import re
import stat
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from .lockfile import verify_lock
from .models import (
    Finding,
    InstructionFile,
    MCPConfigFile,
    ScanContext,
    Severity,
)
from .packages import (
    endpoint_display as _safe_endpoint,
)
from .packages import (
    normalize_package,
    package_display,
    package_specs,
)
from .packages import (
    parse_url as _parse_url,
)
from .rules.model import Rule

CheckFn = Callable[[Rule, Any, ScanContext], list[Finding]]
CHECKS: dict[str, CheckFn] = {}


def check(name: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        CHECKS[name] = fn
        return fn

    return decorator


def _finding(
    rule: Rule,
    path: Any,
    message: str,
    server: str | None = None,
    line: int = 1,
    severity: Severity | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        title=rule.title,
        message=message,
        file=str(path),
        server=server,
        line=max(1, line),
        owasp=rule.owasp or None,
        remediation=rule.remediation or None,
    )


def _line_of(text: str, needle: str) -> int:
    if not needle:
        return 1
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _is_env_ref(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if "${" in stripped or "{env:" in stripped or "{file:" in stripped:
        return True
    prefix, _, rest = stripped.partition(" ")
    if rest and prefix.lower() in ("bearer", "basic", "token"):
        return _is_env_ref(rest)
    return stripped.startswith("$") and " " not in stripped


def _looks_placeholder(value: str) -> bool:
    placeholders = {
        "changeme",
        "change-me",
        "your-key-here",
        "your_api_key",
        "your-api-key",
        "placeholder",
        "example",
        "todo",
        "none",
        "null",
    }
    lowered = value.strip().lower()
    if lowered in placeholders:
        return True
    markers = (
        "your_",
        "your-",
        "xxx",
        "dummy",
        "placeholder",
        "example",
        "sample",
        "fake",
        "changeme",
        "change-me",
        "insert_",
        "replace_",
        "todo",
        "<",
        ">",
    )
    return any(marker in lowered for marker in markers)


def _first_matching_pattern(value: str, patterns: list[dict[str, Any]]) -> str | None:
    for pattern in patterns:
        try:
            if re.search(pattern["regex"], value):
                return str(pattern["name"])
        except re.error:
            continue
    return None


def _is_local_host(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_internal_host(hostname: str | None) -> bool:
    """Private, loopback, link-local and dev TLDs: unencrypted transport is
    less exposed than on the public internet, so findings rank lower."""
    import ipaddress

    if not hostname:
        return False
    lowered = hostname.lower()
    if "." not in lowered:
        return True
    if lowered == "localhost" or lowered.endswith(
        (".local", ".internal", ".test", ".docker.internal", ".localhost")
    ):
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


@check("secrets_in_config")
def secrets_in_config(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    patterns = rule.params.get("patterns", [])
    suspicious_key = rule.params.get("suspicious_env_key", "")
    suspicious_header_key = rule.params.get("suspicious_header_key") or suspicious_key
    min_len = int(rule.params.get("min_len", 12))

    def scan_value(server_name: str, key: str, value: str) -> None:
        if _is_env_ref(value) or _looks_placeholder(value):
            return
        matched = _first_matching_pattern(value, patterns)
        line = _line_of(target.raw_text, key)
        if matched:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"{matched} found in env.{key}",
                    server=server_name,
                    line=line,
                )
            )
        elif suspicious_key and re.search(suspicious_key, key) and len(value) >= min_len:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"literal value for sensitive env.{key} (length {len(value)}) — "
                    "use an env reference instead",
                    server=server_name,
                    line=line,
                    severity=Severity.HIGH,
                )
            )

    for server in target.servers:
        for key, value in server.env.items():
            scan_value(server.name, key, value)
        joined = " ".join(server.command)
        matched = (
            _first_matching_pattern(joined, patterns) if not _looks_placeholder(joined) else None
        )
        if matched:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"{matched} found in args of server '{server.name}'",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
        # Scan every raw source too: a value can be hidden under a colliding
        # key after normalization (e.g. `headers` + `http_headers`). The last
        # field marks whether the sensitive-key heuristic applies — for Codex
        # `bearer_token_env_var` / `env_http_headers` the value is an env var
        # name by contract, so only recognizable token patterns count there.
        header_items: list[tuple[str, str, bool]] = [
            (header, value, True) for header, value in server.headers.items()
        ]
        seen = {(header, value) for header, value, _ in header_items}
        for source in ("headers", "http_headers"):
            raw_map = server.raw.get(source)
            if isinstance(raw_map, dict):
                for raw_key, raw_value in raw_map.items():
                    pair = (str(raw_key), str(raw_value))
                    if pair not in seen:
                        header_items.append((pair[0], pair[1], True))
                        seen.add(pair)
        bearer = server.raw.get("bearer_token_env_var")
        if isinstance(bearer, str) and bearer.strip():
            header_items.append(("bearer_token_env_var", bearer, False))
        env_headers = server.raw.get("env_http_headers")
        if isinstance(env_headers, dict):
            for raw_key, raw_value in env_headers.items():
                header_items.append((f"env_http_headers.{raw_key}", str(raw_value), False))
        for header, value, heuristic in header_items:
            if _is_env_ref(value) or _looks_placeholder(value):
                continue
            matched = _first_matching_pattern(value, patterns)
            if matched:
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"{matched} found in header '{header}' of server '{server.name}'",
                        server=server.name,
                        line=_line_of(target.raw_text, header.split(".")[-1]),
                    )
                )
            elif heuristic and suspicious_header_key and re.search(suspicious_header_key, header):
                if len(value) >= min_len:
                    findings.append(
                        _finding(
                            rule,
                            target.path,
                            f"literal value for sensitive header '{header}' (length "
                            f"{len(value)}) — reference it from the environment instead",
                            server=server.name,
                            line=_line_of(target.raw_text, header.split(".")[-1]),
                            severity=Severity.HIGH,
                        )
                    )
    return findings


@check("file_permissions")
def file_permissions(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    try:
        mode = stat.S_IMODE(target.path.stat().st_mode)
    except OSError:
        return []
    has_secrets = any(server.env for server in target.servers)
    if mode & 0o002:
        return [
            _finding(
                rule,
                target.path,
                f"config is world-writable (mode {oct(mode)}) — any local process can "
                "tamper with it (rug-pull vector)",
                severity=Severity.HIGH,
            )
        ]
    if (mode & 0o044) and has_secrets:
        return [
            _finding(
                rule,
                target.path,
                f"config is group/world-readable (mode {oct(mode)}) and contains "
                "credentials — restrict with chmod 600",
            )
        ]
    return []


@check("unpinned_package")
def unpinned_package(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            if spec.pinned:
                continue
            severity = Severity.HIGH if spec.auto_approve else rule.severity
            extra = " and auto-approved (-y/--yes)" if spec.auto_approve else ""
            display = package_display(spec)
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"'{display}' is not pinned to a version{extra} — a malicious or "
                    "broken release is picked up on every run",
                    server=server.name,
                    line=_line_of(target.raw_text, spec.raw),
                    severity=severity,
                )
            )
    return findings


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


@check("typosquat_package")
def typosquat_package(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    known = [str(k) for k in rule.params.get("known_packages", [])]
    max_distance = int(rule.params.get("max_distance", 1))

    def alpha(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    known_full = {normalize_package(k): k for k in known}
    known_alpha = {alpha(k): k for k in known}

    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            name = spec.name
            if not name or name in known_full or alpha(name) in known_alpha:
                continue
            for known_name, original in known_full.items():
                distance = _levenshtein(alpha(name), alpha(known_name))
                if 1 <= distance <= max_distance:
                    findings.append(
                        _finding(
                            rule,
                            target.path,
                            f"'{package_display(spec)}' is {distance} edit(s) away from popular "
                            "package "
                            f"'{original}' — possible typosquat",
                            server=server.name,
                            line=_line_of(target.raw_text, spec.raw),
                        )
                    )
                    break
    return findings


@check("insecure_remote_transport")
def insecure_remote_transport(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for server in target.servers:
        if not server.url:
            continue
        parsed = _parse_url(server.url)
        if parsed is not None and parsed.scheme == "http" and not _is_local_host(parsed.hostname):
            severity = Severity.LOW if _is_internal_host(parsed.hostname) else rule.severity
            scope = "internal host" if severity is Severity.LOW else "public host"
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"remote endpoint '{_safe_endpoint(server.url)}' uses plain HTTP ({scope}) — "
                    "tool calls and "
                    "results travel unencrypted",
                    server=server.name,
                    line=_line_of(target.raw_text, server.url),
                    severity=severity,
                )
            )
    return findings


@check("remote_without_auth")
def remote_without_auth(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    auth_pattern = rule.params.get("auth_env_pattern", "")
    findings: list[Finding] = []
    for server in target.servers:
        if not server.url:
            continue
        parsed = _parse_url(server.url)
        if parsed is None or _is_local_host(parsed.hostname):
            continue
        if target.client == "codex":
            header_keys = [str(key) for key in server.headers]
        else:
            raw_headers = server.raw.get("headers")
            header_keys = [str(key) for key in raw_headers] if isinstance(raw_headers, dict) else []
        has_auth = any(key.lower() == "authorization" for key in header_keys)
        if not has_auth and auth_pattern:
            has_auth = any(re.search(auth_pattern, key) for key in server.env)
            if not has_auth:
                has_auth = any(re.search(auth_pattern, key) for key in header_keys)
        if not has_auth and target.client == "codex":
            # Codex TOML conventions: the token is referenced, not literal.
            has_auth = bool(server.raw.get("bearer_token_env_var"))
            env_headers = server.raw.get("env_http_headers")
            if not has_auth and isinstance(env_headers, dict) and auth_pattern:
                has_auth = any(re.search(auth_pattern, str(key)) for key in env_headers)
        if not has_auth:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"remote endpoint '{_safe_endpoint(server.url)}' references no "
                    "authentication material "
                    "(no Authorization header, no token/key env)",
                    server=server.name,
                    line=_line_of(target.raw_text, server.url),
                )
            )
    return findings


_SSE_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)


def _looks_like_sse_url(value: str) -> bool:
    if not _SSE_URL_RE.match(value):
        return False
    parsed = _parse_url(value)
    return parsed is not None and parsed.path.rstrip("/").endswith("/sse")


@check("deprecated_sse_transport")
def deprecated_sse_transport(
    rule: Rule, target: MCPConfigFile, ctx: ScanContext
) -> list[Finding]:
    findings: list[Finding] = []
    for server in target.servers:
        declared = server.transport == "sse"
        legacy = server.url if (server.url and _looks_like_sse_url(server.url)) else None
        wrapped = None
        if not legacy:
            for index, token in enumerate(server.command):
                if _looks_like_sse_url(token):
                    legacy = token
                    break
                if token == "sse-only":
                    wrapped = "sse-only"
                    break
                if token.startswith("--transport="):
                    transport = token.split("=", 1)[1]
                    if transport in ("sse", "sse-only"):
                        wrapped = f"--transport {transport}"
                        break
                if token == "--transport" and index + 1 < len(server.command):
                    transport = server.command[index + 1]
                    if transport in ("sse", "sse-only"):
                        wrapped = f"--transport {transport}"
                        break
        if not declared and not legacy and not wrapped:
            continue
        if declared:
            message = (
                f"server '{server.name}' declares the deprecated HTTP+SSE transport "
                "(type: sse) — migrate to Streamable HTTP"
            )
        elif wrapped:
            message = (
                f"server '{server.name}' wraps a legacy SSE transport in its command "
                f"({wrapped}) — if the server still speaks it, migrate to Streamable HTTP"
            )
        else:
            message = (
                f"server '{server.name}' points at a legacy /sse endpoint "
                f"({_safe_endpoint(legacy)}) — if the server still speaks it, migrate to "
                "Streamable HTTP"
            )
        needle = legacy or (wrapped.split()[-1] if wrapped else server.name)
        findings.append(
            _finding(
                rule,
                target.path,
                message,
                server=server.name,
                line=_line_of(target.raw_text, needle),
            )
        )
    return findings


@check("filesystem_overreach")
def filesystem_overreach(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    dangerous = {str(p) for p in rule.params.get("dangerous_paths", [])}
    hints = [str(h).lower() for h in rule.params.get("filesystem_hints", [])]
    findings: list[Finding] = []
    for server in target.servers:
        haystack = " ".join(server.command).lower()
        is_filesystem = any(hint in haystack for hint in hints)
        if not is_filesystem:
            continue
        for token in server.command[1:]:
            if token in dangerous:
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"filesystem server '{server.name}' is scoped to '{token}' — "
                        "it can read and write far beyond the project workspace",
                        server=server.name,
                        line=_line_of(target.raw_text, token),
                    )
                )
    return findings


@check("shell_execution_server")
def shell_execution_server(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    bins = {str(b).lower() for b in rule.params.get("shell_bins", [])}
    hints = [str(h).lower() for h in rule.params.get("shell_hints", [])]
    findings: list[Finding] = []
    for server in target.servers:
        if not server.command:
            continue
        base = Path(server.command[0]).name.lower()
        haystack = " ".join(server.command).lower()
        if base in bins:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"server '{server.name}' spawns a shell ('{base}') — "
                    "it can execute arbitrary commands on this machine",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
        elif any(hint in haystack for hint in hints):
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"server '{server.name}' looks like a command-execution server",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
    return findings


@check("injection_markers")
def injection_markers(rule: Rule, target: Any, ctx: ScanContext) -> list[Finding]:
    if isinstance(target, InstructionFile):
        text = target.text
        path = target.path
    elif isinstance(target, MCPConfigFile):
        text = target.raw_text
        path = target.path
    else:
        return []

    patterns = rule.params.get("patterns", [])
    hits: list[tuple[str, int]] = []
    high_confidence = False
    for pattern in patterns:
        try:
            match = re.search(str(pattern["regex"]), text)
        except re.error:
            continue
        if match:
            hits.append((str(pattern["name"]), match.start()))
            high_confidence = high_confidence or bool(pattern.get("high_confidence"))

    if not hits:
        return []

    severity = Severity.HIGH if (high_confidence or len(hits) >= 2) else Severity.LOW
    findings: list[Finding] = []
    for name, position in hits[:5]:
        findings.append(
            _finding(
                rule,
                path,
                f"possible prompt-injection indicator ({name}); {len(hits)} indicator(s) found "
                "in this file",
                line=text.count("\n", 0, position) + 1,
                severity=severity,
            )
        )
    return findings


_HIDDEN_NAMES = {
    0x00AD: "soft hyphen",
    0x200B: "zero-width space",
    0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner",
    0x200E: "left-to-right mark",
    0x200F: "right-to-left mark",
    0x202A: "bidi embedding",
    0x202B: "bidi embedding",
    0x202C: "bidi pop",
    0x202D: "bidi override",
    0x202E: "bidi override",
    0x2060: "word joiner",
    0x2061: "function application",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
    0xFEFF: "byte order mark",
}


@check("hidden_unicode")
def hidden_unicode(rule: Rule, target: Any, ctx: ScanContext) -> list[Finding]:
    if isinstance(target, InstructionFile):
        text = target.text
        path = target.path
    elif isinstance(target, MCPConfigFile):
        text = target.raw_text
        path = target.path
    else:
        return []

    codepoints = {int(cp, 16) for cp in rule.params.get("codepoints", [])}
    first_seen: dict[int, int] = {}
    for index, char in enumerate(text):
        value = ord(char)
        if value in codepoints and value not in first_seen:
            first_seen[value] = index

    findings: list[Finding] = []
    for value, position in sorted(first_seen.items()):
        name = _HIDDEN_NAMES.get(value, "hidden character")
        findings.append(
            _finding(
                rule,
                path,
                f"hidden unicode U+{value:04X} ({name}) — invisible text can smuggle "
                "instructions past human review",
                line=text.count("\n", 0, position) + 1,
            )
        )
    return findings


_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)
_TOOL_TOKEN_RE = re.compile(r"(?:[^\s,(]+\([^)]*\))|[^\s,]+")
_UNRESTRICTED_TOOL_RE = re.compile(
    r"^(?:\*|mcp__\*|mcp__\*__\*|bash(?:\(\s*\*?\s*:?\s*\*?\s*\))?)$", re.IGNORECASE
)


def _split_tools(value: str) -> list[str]:
    """Split comma/space-delimited tool lists, keeping `Bash(scope *)` intact."""
    tokens = (token.strip("[]'\"") for token in _TOOL_TOKEN_RE.findall(value))
    return [token for token in tokens if token]


def _strip_yaml_comment(value: str) -> str:
    return re.split(r"(?:^|\s+)#", value, maxsplit=1)[0]


def _allowed_tools(text: str) -> list[str]:
    match = _FRONTMATTER_RE.match(text.lstrip("\ufeff"))
    if not match:
        return []
    block = match.group(1)
    value: Any = None
    try:
        data = yaml.safe_load(block)
        if isinstance(data, dict):
            value = data.get("allowed-tools")
    except (yaml.YAMLError, ValueError, RecursionError):
        # `allowed-tools: *` / `- *` / `[*, Read]` are not valid YAML aliases,
        # and PyYAML raises bare ValueError for bad timestamps (and
        # RecursionError for deep structures); recover the key line and any
        # block-list items under it (indented or not).
        line = re.search(r"(?m)^allowed-tools:[ \t]*(.*)$", block)
        if line:
            raw = [_strip_yaml_comment(line.group(1))]
            for following in block[line.end() :].splitlines():
                stripped = following.strip()
                if not stripped:
                    continue
                if stripped.startswith("- "):
                    raw.append(_strip_yaml_comment(stripped[2:]))
                    continue
                if not following[:1].isspace() and ":" in stripped:
                    break
            value = " ".join(raw)
    if isinstance(value, str):
        return _split_tools(value)
    if isinstance(value, list):
        return [token for item in value if isinstance(item, str) for token in _split_tools(item)]
    return []


@check("unrestricted_allowed_tools")
def unrestricted_allowed_tools(rule: Rule, target: Any, ctx: ScanContext) -> list[Finding]:
    if not isinstance(target, InstructionFile):
        return []
    hits = [item for item in _allowed_tools(target.text) if _UNRESTRICTED_TOOL_RE.match(item)]
    return [
        _finding(
            rule,
            target.path,
            f"frontmatter pre-approves '{item}' without a permission prompt — scope it to "
            "the exact commands this skill needs",
            line=_line_of(target.text, item),
        )
        for item in hits[:5]
    ]


@check("server_name_shadowing")
def server_name_shadowing(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    if ctx.cache.get("shadowing_done"):
        return []
    ctx.cache["shadowing_done"] = True

    by_name: dict[str, list[MCPConfigFile]] = {}
    for config in ctx.configs:
        for server in config.servers:
            by_name.setdefault(server.name.lower(), []).append(config)

    findings: list[Finding] = []
    for name, configs in by_name.items():
        files = {str(c.path) for c in configs}
        if len(files) > 1:
            findings.append(
                _finding(
                    rule,
                    configs[0].path,
                    f"server name '{name}' is defined in {len(files)} different configs "
                    "(tool shadowing risk)",
                    server=name,
                )
            )
    return findings


@check("lockfile_drift")
def lockfile_drift(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    if ctx.cache.get("lock_drift_done"):
        return []
    ctx.cache["lock_drift_done"] = True
    if not ctx.lock:
        return []
    return verify_lock(ctx.lock, ctx.configs, ctx.root, rule)


def _osv_query(kind: str, name: str, version: str) -> list[dict[str, Any]]:
    ecosystem = "npm" if kind == "npm" else "PyPI"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "mcplint"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    vulns = body.get("vulns", [])
    return vulns if isinstance(vulns, list) else []


def _osv_severity(vuln: dict[str, Any]) -> Severity:
    database_specific = vuln.get("database_specific") or {}
    label = str(database_specific.get("severity", "")).lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(label, Severity.MEDIUM)


@check("known_vulnerable_dependency")
def known_vulnerable_dependency(
    rule: Rule, target: MCPConfigFile, ctx: ScanContext
) -> list[Finding]:
    if not ctx.online:
        return []
    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            if not spec.pinned or not spec.version:
                continue
            cache_key = f"osv:{spec.kind}:{spec.name}@{spec.version}"
            if cache_key not in ctx.cache:
                ctx.cache[cache_key] = _osv_query(spec.kind, spec.name, spec.version)
            for vuln in ctx.cache[cache_key]:
                vuln_id = str(vuln.get("id", "OSV"))
                summary = str(vuln.get("summary", "")).strip()
                truncated = (summary[:120] + "...") if len(summary) > 120 else summary
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"{spec.name}@{spec.version} matches {vuln_id}"
                        + (f": {truncated}" if truncated else ""),
                        server=server.name,
                        line=_line_of(target.raw_text, spec.raw),
                        severity=_osv_severity(vuln),
                    )
                )
    return findings

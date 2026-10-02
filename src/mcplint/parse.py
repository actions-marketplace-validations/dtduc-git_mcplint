"""Parsing of MCP client configuration files (JSON, JSONC, TOML)."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .models import MCPConfigFile, MCPServer

SERVER_KEYS = ("mcpServers", "servers", "mcp", "mcp_servers")

MAX_CONFIG_BYTES = 2_000_000  # 2 MB safety limit for parsing configs


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments plus trailing commas from JSONC."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


def guess_client(path: Path) -> str:
    posix = path.as_posix()
    name = path.name.lower()
    # Precise check first: a `.codex/config.toml` under any parent directory
    # (e.g. `windsurf-demo/`) is still Codex.
    if name == "config.toml" and ".codex" in posix:
        return "codex"
    if "cline" in name or "saoudrizwan.claude-dev" in posix:
        return "cline"
    if ".cursor/" in posix:
        return "cursor"
    if "windsurf" in posix:
        return "windsurf"
    if ".vscode/" in posix:
        return "vscode"
    if "opencode" in name:
        return "opencode"
    if "gemini" in posix:
        return "gemini"
    if name == ".mcp.json" or "claude" in posix:
        return "claude-code"
    return "generic"


def _extract_server_map(data: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key in SERVER_KEYS:
        value = data.get(key)
        if not isinstance(value, dict):
            continue
        if key == "mcp" and isinstance(value.get("servers"), dict):
            value = value["servers"]
        for name, entry in value.items():
            merged.setdefault(str(name), entry)
    return merged


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def _normalize_server(name: str, entry: Any) -> MCPServer | None:
    if not isinstance(entry, dict):
        return None

    command_field = entry.get("command")
    command: list[str] = []
    if isinstance(command_field, list):
        command = [str(x) for x in command_field]
    elif isinstance(command_field, str) and command_field:
        command = [command_field]

    args = entry.get("args") or entry.get("arguments") or []
    if isinstance(args, list):
        command += [str(a) for a in args]
    elif isinstance(args, str):
        command.append(args)

    env = _string_map(entry.get("env") or entry.get("environment"))
    headers = _string_map(entry.get("headers"))
    # Codex TOML uses `http_headers` for the same thing the `headers` key
    # holds elsewhere; without this they are invisible to the rules.
    http_headers = entry.get("http_headers")
    if isinstance(http_headers, dict):
        headers.update(_string_map(http_headers))

    url_value = (
        entry.get("url")
        or entry.get("serverUrl")
        or entry.get("server_url")
        or entry.get("endpoint")
    )
    url = str(url_value) if url_value else None

    if not command and not url:
        return None

    transport = "stdio"
    if url:
        transport = "http"
    type_field = str(entry.get("type", "")).lower()
    if type_field == "sse":
        transport = "sse"
    elif type_field in ("http", "streamable-http"):
        transport = "http"

    return MCPServer(
        name=name,
        transport=transport,
        command=command,
        env=env,
        url=url,
        headers=headers,
        raw=entry,
    )


def _load_data(path: Path, text: str) -> dict[str, Any] | None:
    try:
        if path.suffix.lower() == ".toml":
            data = tomllib.loads(text)
        else:
            data = json.loads(strip_jsonc(text))
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def parse_config_file(path: Path, client: str | None = None) -> MCPConfigFile | None:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    data = _load_data(path, text)
    if data is None:
        return None

    server_map = _extract_server_map(data)
    servers: list[MCPServer] = []
    for name, entry in server_map.items():
        server = _normalize_server(name, entry)
        if server is not None:
            servers.append(server)
    if not servers:
        return None

    return MCPConfigFile(
        path=path,
        client=client or guess_client(path),
        servers=servers,
        raw_text=text,
    )

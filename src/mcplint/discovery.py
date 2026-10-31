"""Discovery of MCP configs and agent instruction files."""

from __future__ import annotations

import json
import os
from pathlib import Path

REPO_CONFIGS: list[tuple[str, str]] = [
    (".mcp.json", "claude-code"),
    ("mcp.json", "generic"),
    (".cursor/mcp.json", "cursor"),
    (".vscode/mcp.json", "vscode"),
    (".windsurf/mcp.json", "windsurf"),
    ("opencode.json", "opencode"),
    ("opencode.jsonc", "opencode"),
    (".codex/config.toml", "codex"),
]

HOME_CONFIGS: list[tuple[str, str]] = [
    ("~/.claude.json", "claude-code"),
    ("~/.cursor/mcp.json", "cursor"),
    ("~/.codeium/windsurf/mcp_config.json", "windsurf"),
    ("~/.codex/config.toml", "codex"),
    ("~/.gemini/settings.json", "gemini"),
    ("~/.config/opencode/opencode.json", "opencode"),
    (
        "~/.config/Code/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
    (
        "~/.config/Cursor/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
    (
        "~/Library/Application Support/Code/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
    (
        "~/Library/Application Support/Cursor/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
    (
        "~/AppData/Roaming/Code/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
    (
        "~/AppData/Roaming/Cursor/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "cline",
    ),
]

# Claude Code plugin installs. Installed versions live under
# cache/<marketplace>/<plugin>/<version>/; the cache also keeps orphaned copies
# of replaced versions (.orphaned_at), so it is read through
# installed_plugins.json and only walked when that manifest is unavailable.
# synced/ holds claude.ai account plugins and local/ dev plugins; both are
# walked directly. Marketplace clones under plugins/marketplaces/ are source
# checkouts, not installs, and are skipped.
PLUGIN_INSTALL_MANIFEST = "~/.claude/plugins/installed_plugins.json"
HOME_PLUGIN_WALK_ROOTS: list[str] = [
    "~/.claude/plugins/synced",
    "~/.claude/plugins/local",
]

INSTRUCTION_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
]

HOME_INSTRUCTION_GLOBS = [
    "~/.claude/skills/**/SKILL.md",
    "~/.config/opencode/skills/**/SKILL.md",
    "~/.agents/skills/**/SKILL.md",
]

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "target",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

# Installed plugins are published folders that may ship their own tests and
# fixtures — deliberately vulnerable configs must not be reported as live
# servers. Only the plugin's own top-level copies are skipped (a skill named
# `docs` or a plugin named `tests` is still scanned).
PLUGIN_SKIP_DIRS = {"tests", "test", "fixtures", "examples", "example", "docs"}

MAX_CONFIG_FILES = 500
# Plugin installs contribute many SKILL.md files; user skill globs are walked
# first so they keep priority when the cap is hit (truncation is silent today).
MAX_INSTRUCTION_FILES = 500

TEXT_SUFFIXES = {".md", ".mdc", ".txt"}

NESTED_CONFIG_PARENTS = {".cursor", ".vscode", ".windsurf"}


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def _installed_plugin_paths() -> list[Path] | None:
    """Active plugin install paths from installed_plugins.json.

    None means the manifest could not be read (fall back to walking the cache);
    an empty list means it was read and no plugin is installed.
    """
    manifest = Path(PLUGIN_INSTALL_MANIFEST).expanduser()
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, dict):
        return None
    paths: list[Path] = []
    for entries in plugins.values():
        for entry in entries if isinstance(entries, list) else [entries]:
            raw = entry.get("installPath") if isinstance(entry, dict) else None
            if isinstance(raw, str) and raw:
                path = Path(raw).expanduser()
                if path.is_absolute() and path.is_dir():
                    paths.append(path)
    return paths


def _is_config_candidate(base: Path, name: str) -> bool:
    """Strict filename rules for configs found while walking a tree."""
    if name == ".mcp.json":
        return True
    if name == "mcp.json" and base.name in NESTED_CONFIG_PARENTS:
        return True
    if name in ("opencode.json", "opencode.jsonc"):
        return True
    if name == "plugin.json" and base.name == ".claude-plugin":
        return True  # inline mcpServers in a Claude Code plugin manifest
    return name == "config.toml" and base.name == ".codex"


def _is_instruction_candidate(base: Path, name: str) -> bool:
    if name == "SKILL.md":
        return True
    return name.endswith(".mdc") and base.name == "rules" and base.parent.name == ".cursor"


def _walk_tree(
    root: Path,
    configs: list[Path],
    instructions: list[Path],
    *,
    skip_dirs: set[str] | None = None,
    skip_dirs_root_only: bool = False,
    skip_orphaned: bool = False,
) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        if skip_dirs and not (skip_dirs_root_only and base != root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if skip_orphaned and ".orphaned_at" in filenames:
            # Replaced plugin version kept in the cache: not an active install.
            dirnames[:] = []
            continue
        for name in filenames:
            if len(configs) < MAX_CONFIG_FILES and _is_config_candidate(base, name):
                configs.append(base / name)
            elif len(instructions) < MAX_INSTRUCTION_FILES and _is_instruction_candidate(
                base, name
            ):
                instructions.append(base / name)
        if len(configs) >= MAX_CONFIG_FILES and len(instructions) >= MAX_INSTRUCTION_FILES:
            break


def _discover_dir(root: Path, configs: list[Path], instructions: list[Path]) -> None:
    # Broad candidates at the scan root (includes a bare mcp.json).
    for rel, _client in REPO_CONFIGS:
        candidate = root / rel
        if candidate.is_file():
            configs.append(candidate)
    for rel in INSTRUCTION_FILES:
        candidate = root / rel
        if candidate.is_file():
            instructions.append(candidate)
    # Recursive discovery for monorepos and nested client configs.
    _walk_tree(root, configs, instructions)


def discover(
    paths: list[Path], include_home: bool = False
) -> tuple[list[Path], list[Path]]:
    """Return (config_paths, instruction_paths) for the given scan paths."""
    configs: list[Path] = []
    instructions: list[Path] = []

    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            if path.suffix.lower() in TEXT_SUFFIXES:
                instructions.append(path)
            else:
                configs.append(path)
        elif path.is_dir():
            _discover_dir(path, configs, instructions)

    if include_home:
        for pattern, _client in HOME_CONFIGS:
            candidate = Path(pattern).expanduser()
            if candidate.is_file():
                configs.append(candidate)
        for pattern in HOME_INSTRUCTION_GLOBS:
            base = Path(pattern.split("**")[0]).expanduser()
            if base.is_dir():
                _walk_tree(base, [], instructions)
        # Plugin content walks last so the user's own skills keep the
        # instruction budget first.
        install_paths = _installed_plugin_paths()
        if install_paths is None:
            # No manifest: installs are cache/<marketplace>/<plugin>/<version>.
            cache = Path("~/.claude/plugins/cache").expanduser()
            install_paths = sorted(p for p in cache.glob("*/*/*") if p.is_dir())
            if not install_paths and cache.is_dir():
                install_paths = [cache]  # unknown layout: walk as-is
        for base in install_paths:
            if base.is_dir():
                _walk_tree(
                    base,
                    configs,
                    instructions,
                    skip_dirs=PLUGIN_SKIP_DIRS,
                    skip_dirs_root_only=True,
                    skip_orphaned=True,
                )
        for pattern in HOME_PLUGIN_WALK_ROOTS:
            base = Path(pattern).expanduser()
            if base.is_dir():
                _walk_tree(base, configs, instructions, skip_orphaned=True)

    return _dedupe(configs), _dedupe(instructions)

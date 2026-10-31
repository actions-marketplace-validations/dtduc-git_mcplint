import json
from pathlib import Path

from mcplint.parse import guess_client, parse_config_file, strip_jsonc

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_parse_claude_json() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/.mcp.json")
    assert config is not None
    names = {server.name for server in config.servers}
    assert {"files", "github", "remote-legacy", "shell"} <= names
    remote = next(s for s in config.servers if s.name == "remote-legacy")
    assert remote.transport == "http"
    assert remote.url == "http://mcp.example.com/sse"
    files = next(s for s in config.servers if s.name == "files")
    assert files.transport == "stdio"
    assert files.env["LOG_LEVEL"] == "debug"


def test_parse_codex_toml() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/.codex/config.toml")
    assert config is not None
    assert len(config.servers) == 2
    server = next(s for s in config.servers if s.name == "internal-search")
    assert server.env["INTERNAL_SEARCH_TOKEN"].startswith("tok_live")
    vendor = next(s for s in config.servers if s.name == "vendor-legacy")
    assert vendor.transport == "http"
    assert vendor.headers["Authorization"].startswith("Bearer tok_live")


def test_guess_client_prefers_exact_codex_path(tmp_path: Path) -> None:
    assert guess_client(tmp_path / "windsurf-demo" / ".codex" / "config.toml") == "codex"
    assert guess_client(tmp_path / ".codex" / ".mcp.json") == "claude-code"


def test_parse_opencode_json() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/opencode.json")
    assert config is not None
    assert config.servers[0].command == ["uvx", "some-mcp-tool"]
    assert config.servers[0].env["MCP_API_KEY"]


def test_parse_vscode_servers_key(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        """
        {
          // VS Code style
          "servers": {
            "demo": { "type": "stdio", "command": "npx", "args": ["demo@1.0.0"] },
          }
        }
        """,
        encoding="utf-8",
    )
    config = parse_config_file(path)
    assert config is not None
    assert config.servers[0].name == "demo"


def test_strip_jsonc_keeps_strings() -> None:
    text = '{"a": "http://x // not a comment", /* c */ "b": 1,}'
    assert strip_jsonc(text) == '{"a": "http://x // not a comment",  "b": 1}'


def test_parse_rejects_non_mcp_json(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    path.write_text('{"name": "demo", "version": "1.0.0"}', encoding="utf-8")
    assert parse_config_file(path) is None


def test_nested_configs_are_discovered(tmp_path: Path) -> None:
    from mcplint.discovery import discover

    nested = tmp_path / "packages" / "api"
    nested.mkdir(parents=True)
    (nested / ".mcp.json").write_text(
        '{"mcpServers": {"demo": {"command": "npx", "args": ["demo@1.0.0"]}}}',
        encoding="utf-8",
    )
    cursor = tmp_path / "apps" / "web" / ".cursor"
    cursor.mkdir(parents=True)
    (cursor / "mcp.json").write_text("{}", encoding="utf-8")
    skipped = tmp_path / "node_modules" / "pkg"
    skipped.mkdir(parents=True)
    (skipped / ".mcp.json").write_text("{}", encoding="utf-8")

    configs, _ = discover([tmp_path])
    names = {path.name for path in configs}
    assert ".mcp.json" in names
    assert "mcp.json" in names
    assert all("node_modules" not in str(path) for path in configs)


def test_claude_json_user_scope_discovery(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"
    claude_json.write_text(
        """
        {
          "numCachedChunks": 12,
          "mcpServers": {
            "sqlite": { "command": "uvx", "args": ["mcp-server-sqlite"] }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    parsed = parse_config_file(claude_json)
    assert parsed is not None
    assert parsed.client == "claude-code"
    assert len(parsed.servers) == 1
    assert parsed.servers[0].name == "sqlite"
    assert parsed.servers[0].command == ["uvx", "mcp-server-sqlite"]


def test_claude_code_plugin_installs_discovered(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    plugins = home / ".claude" / "plugins"

    active = plugins / "cache" / "acme" / "deploy-tools" / "1.1.0"
    active.mkdir(parents=True)
    (active / ".mcp.json").write_text(
        '{"mcpServers": {"deploy": {"command": "npx", "args": ["deploy-mcp"]}}}',
        encoding="utf-8",
    )
    skill = active / "skills" / "deploy"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Deploy\n", encoding="utf-8")

    # Replaced versions stay in the cache with a .orphaned_at marker and are
    # not listed in installed_plugins.json: skipped.
    orphan = plugins / "cache" / "acme" / "deploy-tools" / "1.0.0"
    orphan.mkdir(parents=True)
    (orphan / ".orphaned_at").write_text("", encoding="utf-8")
    (orphan / ".mcp.json").write_text(
        '{"mcpServers": {"old": {"command": "old-server"}}}', encoding="utf-8"
    )

    (plugins / "installed_plugins.json").write_text(
        json.dumps(
            {"version": 2, "plugins": {"deploy-tools@acme": [{"installPath": str(active)}]}}
        ),
        encoding="utf-8",
    )

    synced = plugins / "synced" / "acct" / "slack"
    synced.mkdir(parents=True)
    (synced / ".mcp.json").write_text(
        '{"mcpServers": {"slack": {"type": "http", "url": "https://mcp.slack.com/mcp"}}}',
        encoding="utf-8",
    )

    local = plugins / "local" / "custom-tools" / ".claude-plugin"
    local.mkdir(parents=True)
    (local / "plugin.json").write_text(
        json.dumps({"name": "custom-tools", "mcpServers": {"custom": {"command": "custom-mcp"}}}),
        encoding="utf-8",
    )

    # A plugin's own test fixtures must not be reported as live servers.
    inside_tests = active / "tests"
    inside_tests.mkdir()
    (inside_tests / ".mcp.json").write_text(
        '{"mcpServers": {"fake": {"command": "fake"}}}', encoding="utf-8"
    )

    # Skipping is root-only: a skill directory named `docs` is real content.
    docs_skill = active / "skills" / "docs"
    docs_skill.mkdir(parents=True)
    (docs_skill / "SKILL.md").write_text("# Docs skill\n", encoding="utf-8")

    # A plugin named `docs` under a container root is a real install.
    synced_docs = plugins / "synced" / "acct" / "docs"
    synced_docs.mkdir(parents=True)
    (synced_docs / ".mcp.json").write_text(
        '{"mcpServers": {"docs": {"command": "docs-mcp"}}}', encoding="utf-8"
    )

    # Marketplace clones are sources, not installs: their fixtures stay out.
    fixture = plugins / "marketplaces" / "acme" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / ".mcp.json").write_text(
        '{"mcpServers": {"fixture": {"command": "fixture-server"}}}', encoding="utf-8"
    )

    monkeypatch.setenv("HOME", str(home))
    configs, instructions = discover([], include_home=True)

    found = {str(path) for path in configs}
    assert any(path.endswith("deploy-tools/1.1.0/.mcp.json") for path in found)
    assert not any(path.endswith("deploy-tools/1.0.0/.mcp.json") for path in found)
    assert not any("deploy-tools/1.1.0/tests/" in path for path in found)
    assert any(path.endswith("synced/acct/slack/.mcp.json") for path in found)
    assert any(path.endswith("synced/acct/docs/.mcp.json") for path in found)
    assert any(path.endswith("local/custom-tools/.claude-plugin/plugin.json") for path in found)
    assert not any("marketplaces" in path for path in found)
    assert any(str(path).endswith("skills/deploy/SKILL.md") for path in instructions)
    assert any(str(path).endswith("skills/docs/SKILL.md") for path in instructions)


def test_plugin_manifest_shapes(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    def run(home: Path) -> set[str]:
        monkeypatch.setenv("HOME", str(home))
        configs, _ = discover([], include_home=True)
        return {str(path) for path in configs}

    def cache_config(home: Path) -> Path:
        install = home / ".claude" / "plugins" / "cache" / "acme" / "tool" / "2.0.0"
        install.mkdir(parents=True)
        config = install / ".mcp.json"
        config.write_text('{"mcpServers": {"tool": {"command": "tool-mcp"}}}', encoding="utf-8")
        return install

    manifest = tmp_path / "a" / ".claude" / "plugins" / "installed_plugins.json"
    cache_config(tmp_path / "a")
    manifest.write_text(json.dumps({"version": 2, "plugins": {}}), encoding="utf-8")
    assert not any("cache/acme" in path for path in run(tmp_path / "a"))

    home_b = tmp_path / "b"
    cache_config(home_b)
    cache_b = home_b / ".claude" / "plugins" / "cache"
    # Fallback must skip the install's own fixtures...
    inside_tests = cache_b / "acme" / "tool" / "2.0.0" / "tests"
    inside_tests.mkdir()
    (inside_tests / ".mcp.json").write_text(
        '{"mcpServers": {"fake": {"command": "fake"}}}', encoding="utf-8"
    )
    # ...and must not skip a marketplace that happens to be named `docs`.
    docs_market = cache_b / "docs" / "tool" / "3.0.0"
    docs_market.mkdir(parents=True)
    (docs_market / ".mcp.json").write_text(
        '{"mcpServers": {"docs": {"command": "docs-mcp"}}}', encoding="utf-8"
    )
    orphan_b = cache_b / "acme" / "tool" / "1.9.0"
    orphan_b.mkdir(parents=True)
    (orphan_b / ".orphaned_at").write_text("", encoding="utf-8")
    (orphan_b / ".mcp.json").write_text(
        '{"mcpServers": {"old": {"command": "old-server"}}}', encoding="utf-8"
    )
    (home_b / ".claude" / "plugins" / "installed_plugins.json").write_text(
        "{broken", encoding="utf-8"
    )
    found_b = run(home_b)
    assert any("cache/acme/tool/2.0.0/.mcp.json" in path for path in found_b)
    assert not any("2.0.0/tests/" in path for path in found_b)
    assert any("cache/docs/tool/3.0.0/.mcp.json" in path for path in found_b)
    assert not any("1.9.0" in path for path in found_b)

    home_c = tmp_path / "c"
    install_c = cache_config(home_c)
    (home_c / ".claude" / "plugins" / "installed_plugins.json").write_text(
        json.dumps({"version": 1, "plugins": {"tool@acme": {"installPath": str(install_c)}}}),
        encoding="utf-8",
    )
    assert any("cache/acme/tool/2.0.0/.mcp.json" in path for path in run(home_c))


def test_plugin_cache_walked_without_manifest(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    install = home / ".claude" / "plugins" / "cache" / "acme" / "tool" / "2.0.0"
    install.mkdir(parents=True)
    (install / ".mcp.json").write_text(
        '{"mcpServers": {"tool": {"command": "tool-mcp"}}}', encoding="utf-8"
    )
    inside_tests = install / "tests"
    inside_tests.mkdir()
    (inside_tests / ".mcp.json").write_text(
        '{"mcpServers": {"fake": {"command": "fake"}}}', encoding="utf-8"
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(str(path).endswith("cache/acme/tool/2.0.0/.mcp.json") for path in configs)
    assert not any("tests/" in str(path) for path in configs)


def test_claude_json_malformed_skipped(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"
    claude_json.write_text("{invalid json", encoding="utf-8")

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    # Parsing should return None safely without crashing
    assert parse_config_file(claude_json) is None


def test_claude_json_oversized_skipped(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover
    from mcplint.parse import MAX_CONFIG_BYTES

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"

    # Write a file exceeding MAX_CONFIG_BYTES
    claude_json.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    # Parsing oversized config should safely return None without reading/crashing
    assert parse_config_file(claude_json) is None
def test_cline_linux_discovery_and_parse(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    cline_dir = (
        home
        / ".config"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    settings = cline_dir / "cline_mcp_settings.json"
    settings.write_text(
        """
        {
          "mcpServers": {
            "weather": {
              "command": "node",
              "args": ["build/index.js"],
              "env": {
                "API_KEY": "secret"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == "cline_mcp_settings.json" for c in configs)

    parsed = parse_config_file(settings)
    assert parsed is not None
    assert parsed.client == "cline"
    assert len(parsed.servers) == 1
    assert parsed.servers[0].name == "weather"
    assert parsed.servers[0].command == ["node", "build/index.js"]
    assert parsed.servers[0].env["API_KEY"] == "secret"


def test_cline_macos_discovery_with_spaces(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    cline_dir = (
        home
        / "Library"
        / "Application Support"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    settings = cline_dir / "cline_mcp_settings.json"
    settings.write_text(
        """
        {
          "mcpServers": {
            "fetch": {
              "command": "uvx",
              "args": ["mcp-server-fetch"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(
        "Application Support" in str(c) and c.name == "cline_mcp_settings.json"
        for c in configs
    )

    parsed = parse_config_file(settings)
    assert parsed is not None
    assert parsed.client == "cline"
    assert parsed.servers[0].name == "fetch"

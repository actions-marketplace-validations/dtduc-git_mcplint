import json
from pathlib import Path

import pytest

from mcplint.aibom import build_aibom
from mcplint.discovery import discover
from mcplint.lockfile import build_lock
from mcplint.parse import parse_config_file
from mcplint.rules import load_rules
from mcplint.scanner import scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EXPECTED_VULNERABLE = {
    "MCP001",  # secrets (ghp_, URL creds, generic token env, http_headers)
    "MCP003",  # unpinned npm/pypi packages
    "MCP004",  # typosquat: mcp-server-postgress
    "MCP005",  # http:// remote endpoint
    "MCP006",  # remote without auth
    "MCP007",  # filesystem server scoped to /
    "MCP008",  # bash shell server
    "MCP009",  # injection markers in AGENTS.md / SKILL.md
    "MCP010",  # zero-width space in SKILL.md
    "MCP011",  # "files" defined in two configs
    "MCP014",  # deprecated /sse endpoint in .mcp.json
    "MCP015",  # unrestricted allowed-tools in SKILL.md
}


def test_vulnerable_fixture_triggers_expected_rules() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    ids = {finding.rule_id for finding in result.findings}
    missing = EXPECTED_VULNERABLE - ids
    assert not missing, f"missing expected findings: {sorted(missing)}"


def test_clean_fixture_has_no_findings() -> None:
    result = scan([FIXTURES / "clean-repo"], load_rules())
    assert result.findings == [], [f.to_dict() for f in result.findings]


def test_secrets_are_attributed_to_server_and_line() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    secrets = [f for f in result.findings if f.rule_id == "MCP001"]
    by_server = {f.server for f in secrets}
    assert "github" in by_server
    github = next(f for f in secrets if f.server == "github")
    assert github.line > 1
    assert "GitHub token" in github.message


def test_typosquat_flags_postgress() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    typos = [f for f in result.findings if f.rule_id == "MCP004"]
    assert any("postgress" in f.message for f in typos)


def test_pinned_package_is_not_flagged() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
    assert all("memory-pinned" != f.server for f in unpinned)


def test_typosquat_ignores_separator_and_scope_variants(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "npx", "args": ["playwright-mcp@1.0.0"]},
                    "b": {"command": "npx", "args": ["mcp-server-postgresql@1.0.0"]},
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP004"]


def test_codex_bearer_env_var_counts_as_auth(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        '[mcp_servers.vendor]\n'
        'url = "https://mcp.vendor.example/mcp"\n'
        'bearer_token_env_var = "VENDOR_MCP_TOKEN"\n'
        "\n"
        "[mcp_servers.open]\n"
        'url = "https://mcp.open.example/mcp"\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert result.configs
    flagged = {f.server for f in result.findings if f.rule_id == "MCP006"}
    assert flagged == {"open"}


def test_codex_env_http_headers_counts_as_auth(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        '[mcp_servers.vendor]\n'
        'url = "https://mcp.vendor.example/mcp"\n'
        'env_http_headers = { Authorization = "VENDOR_MCP_TOKEN" }\n'
        "\n"
        "[mcp_servers.open]\n"
        'url = "https://mcp.open.example/mcp"\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert result.configs
    flagged = {f.server for f in result.findings if f.rule_id == "MCP006"}
    assert flagged == {"open"}


def test_codex_bearer_keys_do_not_suppress_other_clients(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vendor": {
                        "url": "https://mcp.vendor.example/mcp",
                        "bearer_token_env_var": "VENDOR_MCP_TOKEN",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert {f.server for f in result.findings if f.rule_id == "MCP006"} == {"vendor"}


def test_http_headers_in_json_config_does_not_suppress_mcp006(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vendor": {
                        "url": "https://mcp.vendor.example/mcp",
                        "http_headers": {"Authorization": "x"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert {f.server for f in result.findings if f.rule_id == "MCP006"} == {"vendor"}


def test_env_http_headers_env_names_are_not_secrets(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        "[mcp_servers.vendor]\n"
        'url = "https://mcp.vendor.example/mcp"\n'
        'env_http_headers = { "X-Api-Key" = "DATADOG_API_KEY" }\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP001"]


def test_authorization_header_literal_is_flagged_by_heuristic(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vendor": {
                        "url": "https://mcp.vendor.example/mcp",
                        "headers": {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    heuristic = [
        f for f in result.findings if f.rule_id == "MCP001" and "sensitive header" in f.message
    ]
    assert len(heuristic) == 1
    assert "Authorization" in heuristic[0].message
    assert heuristic[0].severity.value == "high"


def test_env_ref_header_forms_are_not_secrets(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    for value in (
        "Bearer ${TOKEN}",
        "Bearer $TOKEN",
        "Bearer {env:MY_KEY}",
        "{file:/run/secrets/mcp}",
    ):
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "vendor": {
                            "url": "https://mcp.vendor.example/mcp",
                            "headers": {"Authorization": value},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        assert not [f for f in result.findings if f.rule_id == "MCP001"], value


def test_frontmatter_value_error_does_not_crash_scan(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: demo\n"
        "description: demo\n"
        "date: 2024-99-99\n"
        "allowed-tools: Read, Bash\n"
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP015"]
    assert len(flagged) == 1
    assert flagged[0].severity.value == "medium"


def test_codex_http_headers_literal_token_is_scanned(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        '[mcp_servers.vendor]\n'
        'url = "https://mcp.vendor.example/mcp"\n'
        'http_headers = { "Authorization" = "Bearer tok_live_1234567890abcdef1234567890abcdef" }\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert result.configs
    secrets = [f for f in result.findings if f.rule_id == "MCP001"]
    assert any("Authorization" in f.message for f in secrets)
    assert not [f for f in result.findings if f.rule_id == "MCP006"]


def test_codex_literal_hidden_under_colliding_keys_is_scanned(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        "[mcp_servers.vendor]\n"
        'url = "https://mcp.vendor.example/mcp"\n'
        'headers = { "Authorization" = "Bearer tok_live_1234567890abcdef1234567890abcdef" }\n'
        'http_headers = { "Authorization" = "${VENDOR_TOKEN}" }\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    secrets = [f for f in result.findings if f.rule_id == "MCP001"]
    assert any("Authorization" in f.message for f in secrets)


def test_literals_in_bearer_and_env_http_headers_are_scanned(tmp_path: Path) -> None:
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        "[mcp_servers.a]\n"
        'url = "https://a.example/mcp"\n'
        'bearer_token_env_var = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"\n'
        "\n"
        "[mcp_servers.b]\n"
        'url = "https://b.example/mcp"\n'
        'env_http_headers = { Authorization = "Bearer tok_live_1234567890abcdef1234567890ab" }\n',
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    secrets = [f for f in result.findings if f.rule_id == "MCP001"]
    assert {"a", "b"} <= {f.server for f in secrets}


def test_header_sensitive_key_heuristic(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vendor": {
                        "url": "https://mcp.vendor.example/mcp",
                        "headers": {"X-Api-Key": "0123456789abcdef0123456789abcdef"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    heuristic = [
        f for f in result.findings if f.rule_id == "MCP001" and "sensitive header" in f.message
    ]
    assert len(heuristic) == 1
    assert heuristic[0].severity.value == "high"


def test_deprecated_sse_type_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "legacy": {
                        "type": "sse",
                        "url": "https://mcp.example.com/mcp",
                        "headers": {"Authorization": "${env:MCP_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    sse = [f for f in result.findings if f.rule_id == "MCP014"]
    assert len(sse) == 1
    assert sse[0].severity.value == "low"


def test_streamable_http_is_not_flagged_as_deprecated(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "modern": {
                        "type": "streamable-http",
                        "url": "https://mcp.example.com/mcp",
                        "headers": {"Authorization": "${env:MCP_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP014"]


def test_sse_url_suffix_boundaries(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    cases = [
        ("https://mcp.example.com/sse", True),
        ("https://mcp.example.com/sse/", True),
        ("https://mcp.example.com/v1/sse?x=1", True),
        ("https://mcp.example.com/sse-proxy", False),
        ("https://mcp.example.com/assets/ssexyz", False),
        ("https://mcp.example.com/mcp", False),
    ]
    for url, expected in cases:
        path.write_text(
            json.dumps(
                {"mcpServers": {"demo": {"url": url, "headers": {"X-Key": "${env:K}"}}}}
            ),
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        flagged = [f for f in result.findings if f.rule_id == "MCP014"]
        assert bool(flagged) is expected, url


def test_http_type_with_sse_url_is_advisory(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "atlassian": {
                        "type": "http",
                        "url": "https://mcp.atlassian.example/v1/sse",
                        "headers": {"Authorization": "${env:MCP_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    sse = [f for f in result.findings if f.rule_id == "MCP014"]
    assert len(sse) == 1
    assert "legacy /sse endpoint" in sse[0].message


def test_mcp_remote_transport_sse_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wrapped": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            "https://mcp.example.com/mcp",
                            "--transport",
                            "sse-only",
                        ],
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP014"]
    assert len(flagged) == 1
    assert "wraps a legacy SSE transport" in flagged[0].message
    assert "--transport sse-only" in flagged[0].message
    assert "mcp-remote" not in flagged[0].message
    assert "https://mcp.example.com/mcp" not in flagged[0].message
    assert flagged[0].line > 1


def test_mcp014_does_not_leak_command_secrets(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "combined": {
                        "command": "sh",
                        "args": ["-c", "API_KEY=abc123 npx mcp-remote https://mcp.example.com/sse"],
                    },
                    "userinfo": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "https://user:pass@mcp.example.com/sse"],
                    },
                    "malformed": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "https://[bad/sse"],
                    },
                    "pathtoken-args": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "https://mcp.example.com/mcp/sk-ak-SECRET/sse"],
                    },
                    "pathtoken-url": {
                        "url": "https://mcp.example.com/mcp/sk-ak-SECRET/sse",
                        "headers": {"Authorization": "${env:MCP_TOKEN}"},
                    },
                    "http-secret": {
                        "url": "http://user:pass@mcp.example.com/mcp/sk-ak-SECRET?token=abc123",
                    },
                    "unencoded-userinfo": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "https://user:Ab/Cd@host/sse"],
                    },
                    "flag-value": {
                        "command": "npx",
                        "args": ["-y", "-c", "API_KEY=abc123 mcp-server"],
                    },
                    "flag-token": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "--token",
                            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                            "pkg",
                        ],
                    },
                    "proxy-userinfo": {
                        "command": "npx",
                        "args": ["--proxy", "user:pass@proxy:8080", "pkg"],
                    },
                    "flag-before-package": {
                        "command": "npx",
                        "args": ["-y", "--prefer-offline", "@vendor/mcp", "sk-live-KEY"],
                    },
                    "shell-string": {"command": "env API_KEY=abc123 /bin/bash"},
                    "url-version": {
                        "command": "npx",
                        "args": ["mcp-server-postgress@https://dl.example.com/sk-ak-SECRET/x.tgz"],
                    },
                    "unencoded-pkg-url": {
                        "command": "npx",
                        "args": ["https://ghp_abc/def@github.com/org/repo"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    messages = " ".join(f.message for f in result.findings)
    assert "API_KEY" not in messages
    assert "abc123" not in messages
    assert "user:pass" not in messages
    assert "user:Ab" not in messages
    assert "sk-ak-SECRET" not in messages
    assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in messages
    assert "ghp_abc" not in messages
    assert any("<malformed URL>" in f.message for f in result.findings)
    configs = [c for p in discover([tmp_path])[0] if (c := parse_config_file(p)) is not None]
    artifacts = json.dumps(build_lock(configs, tmp_path)) + json.dumps(
        build_aibom(configs, tmp_path)
    )
    for secret in (
        "user:pass",
        "user:Ab",
        "sk-ak-SECRET",
        "abc123",
        "API_KEY",
        "ghp_",
        "ghp_abc",
        "sk-live-KEY",
    ):
        assert secret not in artifacts, secret
    userinfo = [f for f in result.findings if f.rule_id == "MCP014" and f.server == "userinfo"]
    assert len(userinfo) == 1
    assert "https://mcp.example.com" in userinfo[0].message
    assert "/mcp/sk-ak-SECRET" not in userinfo[0].message
    assert not [f for f in result.findings if f.rule_id == "MCP014" and f.server == "combined"]
    for server in ("pathtoken-args", "pathtoken-url"):
        assert [f for f in result.findings if f.rule_id == "MCP014" and f.server == server]


def test_online_lookup_uses_only_parsed_package_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str, str]] = []

    def fake_osv(kind: str, name: str, version: str) -> list[dict]:
        calls.append((kind, name, version))
        return []

    monkeypatch.setattr("mcplint.checks._osv_query", fake_osv)
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "unknown-flag": {
                        "command": "npx",
                        "args": [
                            "--token",
                            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                            "vendor-pkg@1.2.3",
                        ],
                    },
                    "pinned-uvx": {
                        "command": "uvx",
                        "args": ["--from", "mcplint-sec==0.6.0", "mcplint"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    scan([tmp_path], load_rules(), online=True)
    assert calls == [("pypi", "mcplint-sec", "0.6.0")]


def test_uvx_from_is_the_package_not_the_command(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "pinned-uvx": {
                        "command": "uvx",
                        "args": ["--from", "mcplint-sec==0.6.0", "mcplint"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP003"]


def test_unknown_flag_stops_package_extraction(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vendor": {
                        "command": "npx",
                        "args": [
                            "--token",
                            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                            "vendor-pkg@1.2.3",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP003"]


def test_runner_specific_flag_tables(tmp_path: Path) -> None:
    sha = "a" * 40
    cases = [
        ({"command": "uvx", "args": ["-p", "3.12", "pkg"]}, "pkg"),
        ({"command": "uvx", "args": ["-f", "./wheels", "pkg"]}, "pkg"),
        (
            {"command": "uvx", "args": ["--extra-index-url", "https://idx.example/simple", "pkg"]},
            "pkg",
        ),
        ({"command": "uvx", "args": ["--prerelease", "allow", "pkg"]}, "pkg"),
        ({"command": "uvx", "args": ["--upgrade", "pkg"]}, "pkg"),
        ({"command": "uvx", "args": ["--offline", "pkg"]}, "pkg"),
        ({"command": "uvx", "args": ["--env-file", ".env", "pkg"]}, "pkg"),
        ({"command": "npx", "args": ["--loglevel", "silent", "pkg"]}, "pkg"),
        ({"command": "pipx", "args": ["run", "--no-cache", "pkg"]}, "pkg"),
        ({"command": "pipx", "args": ["run", "--spec", "pkg==2.0.0", "app"]}, None),
        ({"command": "pipx", "args": ["runpip", "venv", "list"]}, None),
        ({"command": "pnpx", "args": ["-c", "cowsay", "hi"]}, "cowsay"),
        (
            {"command": "uvx", "args": ["--from", f"git+https://github.com/org/repo@{sha}", "cmd"]},
            None,
        ),
        (
            {"command": "uvx", "args": ["--from", "git+https://github.com/org/repo", "cmd"]},
            "git+https://github.com",
        ),
        (
            {
                "command": "uvx",
                "args": ["--from", "git+https://github.com/org/repo@deadbee", "cmd"],
            },
            "<git URL>",
        ),
        ({"command": "npx", "args": [f"git+https://github.com/org/repo.git#{sha}"]}, None),
        ({"command": "npx", "args": ["https://dl.example.com/pkg.tgz"]}, "https://dl.example.com"),
        ({"command": "npx", "args": ["pkg@^1.2.0"]}, "pkg@^1.2.0"),
        ({"command": "npx", "args": ["pkg@>=1.2.3"]}, "pkg@>=1.2.3"),
        ({"command": "uvx", "args": ["pkg>=1.0"]}, "pkg>=1.0"),
        ({"command": "uvx", "args": ["pkg>=1.0,<=2"]}, "pkg>=1.0,<=2"),
        ({"command": "npx", "args": ["pkg@1.2.3-rc.1+build.5"]}, None),
        ({"command": "uvx", "args": ["pkg==1.2.3.post1"]}, None),
        ({"command": "uvx", "args": ["pkg==1.0rc1.post1"]}, None),
        ({"command": "uvx", "args": ["pkg==1!1.0"]}, None),
        ({"command": "pipx", "args": ["install", "foo"]}, None),
    ]
    path = tmp_path / ".mcp.json"
    messages: list[str] = []
    for server, expected in cases:
        path.write_text(
            json.dumps({"mcpServers": {"demo": server}}),
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
        messages.extend(f.message for f in result.findings)
        if expected is None:
            assert not unpinned, server
        else:
            assert len(unpinned) == 1, server
            assert f"'{expected}'" in unpinned[0].message, server
    joined = " ".join(messages)
    assert "3.12" not in joined
    assert "./wheels" not in joined
    assert "idx.example" not in joined


def test_auto_approve_only_counts_flags_before_package(tmp_path: Path) -> None:
    cases = [
        (["-y", "app-pkg"], True),
        (["app-pkg", "-y"], False),
        (["-yq", "app-pkg"], True),
        (["-y", "--package=app-pkg", "cmd"], True),
        (["--package=app-pkg", "-y", "cmd"], True),
        (["-p", "app-pkg", "-y", "cmd"], True),
        (["-p", "app-pkg", "cmd", "-y"], False),
        (["-p", "a", "-p", "b", "-y", "cmd"], True),
    ]
    path = tmp_path / ".mcp.json"
    for args, expected in cases:
        path.write_text(
            json.dumps({"mcpServers": {"demo": {"command": "npx", "args": args}}}),
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
        assert len(unpinned) == 1, args
        assert ("auto-approved" in unpinned[0].message) is expected, args
        assert (unpinned[0].severity.value == "high") is expected, args


def test_non_registry_package_uses_placeholder(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "gh": {"command": "npx", "args": ["github:org/repo"]},
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
    assert len(unpinned) == 1
    assert "<package spec>" in unpinned[0].message
    assert "github:org/repo" not in unpinned[0].message


def test_mcp003_url_package_secret_not_echoed(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetched": {
                        "command": "npx",
                        "args": ["-y", "https://dl.example.com/dl/sk-ak-SECRET/pkg.tgz"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
    assert unpinned
    assert all("sk-ak-SECRET" not in f.message for f in unpinned)
    assert any("https://dl.example.com" in f.message for f in unpinned)


def test_malformed_server_url_does_not_crash_scan(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "broken": {
                        "url": "https://[bad/sse",
                        "headers": {"Authorization": "${env:MCP_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id in ("MCP005", "MCP014")]


def test_mcp_remote_url_in_args_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wrapped": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "https://mcp.example.com/sse"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP014"]
    assert len(flagged) == 1
    assert "legacy /sse endpoint" in flagged[0].message


def test_transport_equals_form_is_flagged(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wrapped": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            "https://mcp.example.com/mcp",
                            "--transport=sse",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP014"]
    assert len(flagged) == 1
    assert "--transport sse" in flagged[0].message


def test_bom_prefixed_frontmatter_is_parsed(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "\ufeff---\nname: demo\ndescription: demo\nallowed-tools: Read, Bash\n---\n\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP015"]
    assert len(flagged) == 1
    assert flagged[0].severity.value == "medium"


def test_other_transports_are_not_flagged_as_deprecated(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    for transport in ("http-only", "streamable-http"):
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "wrapped": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "mcp-remote",
                                "https://mcp.example.com/mcp",
                                "--transport",
                                transport,
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        assert not [f for f in result.findings if f.rule_id == "MCP014"], transport


def test_unrestricted_allowed_tools_flagged(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: risky\n"
        "description: demo\n"
        'allowed-tools: ["*", "Read"]\n'
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP015"]
    assert len(flagged) == 1
    assert "'*'" in flagged[0].message
    assert flagged[0].severity.value == "medium"


def test_bare_bash_allowed_tool_ranks_medium(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: shellish\n"
        "description: demo\n"
        "allowed-tools: Read, Bash\n"
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    flagged = [f for f in result.findings if f.rule_id == "MCP015"]
    assert len(flagged) == 1
    assert "Bash" in flagged[0].message
    assert flagged[0].severity.value == "medium"


def test_allowed_tools_parsing_forms(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("placeholder", encoding="utf-8")
    cases = [
        ('allowed-tools: "*"\n', "medium"),  # quoted wildcard
        ("allowed-tools: *\n", "medium"),  # bare alias, invalid YAML
        ("allowed-tools:\n  - *\n", "medium"),  # block-list alias, invalid YAML
        ("allowed-tools:\n- *\n", "medium"),  # unindented alias item
        ("allowed-tools: [*, Read]\n", "medium"),  # flow list alias
        ("allowed-tools:  # never Bash\n  - *\n", "medium"),  # leading comment
        ("allowed-tools: Read, Bash\n", "medium"),  # comma string
        ("allowed-tools: Read Bash\n", "medium"),  # space-delimited list
        ("allowed-tools:\n  - Bash(*)\n", "medium"),  # explicit shell wildcard
        ("allowed-tools:\n  - Bash(:*)\n", "medium"),  # explicit shell wildcard
        ("allowed-tools:\n  - Bash(*:*)\n", "medium"),  # explicit shell wildcard
        ("allowed-tools:\n  - Bash(* *)\n", "medium"),  # explicit shell wildcard
        ("allowed-tools:\n  - mcp__*\n", "medium"),  # every MCP tool
        ("allowed-tools:\n  - mcp__*__*\n", "medium"),  # every MCP tool on any server
    ]
    for frontmatter, expected in cases:
        (tmp_path / "SKILL.md").write_text(
            "---\nname: demo\ndescription: demo\n" + frontmatter + "---\n\nhelp\n",
            encoding="utf-8",
        )
        result = scan([tmp_path], load_rules())
        flagged = [f for f in result.findings if f.rule_id == "MCP015"]
        assert len(flagged) == 1, frontmatter
        assert flagged[0].severity.value == expected, frontmatter


def test_scoped_tools_with_spaces_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: scoped\n"
        "description: demo\n"
        "allowed-tools: Read, Bash(git * --dry-run), Bash(aws *)\n"
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP015"]


def test_allowed_tools_fallback_ignores_comments(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        'description: "unclosed\n'
        "allowed-tools: Read  # never Bash\n"
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP015"]


def test_scoped_allowed_tools_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: careful\n"
        "description: demo\n"
        "allowed-tools:\n"
        "  - Read\n"
        "  - Bash(git status:*)\n"
        "---\n"
        "\nhelp\n",
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP015"]


def test_private_http_host_ranks_lower_than_public(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "internal": {"url": "http://agent-gateway:8787/mcp"},
                    "public": {"url": "http://mcp.example.com/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    http = [f for f in result.findings if f.rule_id == "MCP005"]
    internal = next(f for f in http if "agent-gateway" in f.message)
    public = next(f for f in http if "mcp.example.com" in f.message)
    assert internal.severity.value == "low"
    assert public.severity.value == "high"

import json
import shutil
from pathlib import Path

from mcplint.discovery import discover
from mcplint.lockfile import LOCKFILE_NAME, build_lock, load_lock, verify_lock, write_lock
from mcplint.parse import parse_config_file
from mcplint.rules import load_rules
from mcplint.scanner import scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _configs(root: Path) -> list:
    paths, _ = discover([root], include_home=False)
    return [c for p in paths if (c := parse_config_file(p)) is not None]


def _lock_rule():
    return next(rule for rule in load_rules() if rule.id == "MCP012")


def test_lock_roundtrip_is_stable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "clean-repo", repo)
    configs = _configs(repo)
    lock = build_lock(configs, repo)
    path = repo / LOCKFILE_NAME
    write_lock(path, lock)
    assert load_lock(path) is not None
    assert verify_lock(lock, configs, repo, _lock_rule()) == []


def test_lock_does_not_store_url_package_secrets(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetched": {
                        "command": "npx",
                        "args": ["https://dl.example.com/dl/sk-ak-SECRET/pkg.tgz"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    lock = build_lock(_configs(repo), repo)
    text = json.dumps(lock)
    assert "sk-ak-SECRET" not in text
    assert "https://dl.example.com" in text


def test_lock_detects_tampering(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "clean-repo", repo)
    configs = _configs(repo)
    lock = build_lock(configs, repo)

    config_path = repo / ".mcp.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["mcpServers"]["files"]["args"][1] = "/tmp"
    config_path.write_text(json.dumps(data), encoding="utf-8")

    findings = verify_lock(lock, _configs(repo), repo, _lock_rule())
    assert any(f.severity.value == "high" for f in findings)
    assert any("changed since it was locked" in f.message for f in findings)


def test_lock_detects_env_secret_change(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "clean-repo", repo)
    config_path = repo / ".mcp.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["mcpServers"]["local"]["env"] = {"MCP_TOKEN": "${env:MCP_TOKEN}"}
    config_path.write_text(json.dumps(data), encoding="utf-8")

    configs = _configs(repo)
    lock = build_lock(configs, repo)
    assert verify_lock(lock, configs, repo, _lock_rule()) == []

    data["mcpServers"]["local"]["env"]["MCP_TOKEN"] = "${env:OTHER_TOKEN}"
    config_path.write_text(json.dumps(data), encoding="utf-8")
    findings = verify_lock(lock, _configs(repo), repo, _lock_rule())
    assert any("changed since it was locked" in f.message for f in findings)


def test_scan_surfaces_lock_drift(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "clean-repo", repo)
    write_lock(repo / LOCKFILE_NAME, build_lock(_configs(repo), repo))

    config_path = repo / ".mcp.json"
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["mcpServers"]["files"]["args"] = ["@modelcontextprotocol/server-filesystem@0.6.2", "/"]
    config_path.write_text(json.dumps(data), encoding="utf-8")

    result = scan([repo], load_rules())
    assert "MCP012" in {f.rule_id for f in result.findings}

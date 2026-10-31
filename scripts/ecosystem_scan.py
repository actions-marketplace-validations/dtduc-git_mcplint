#!/usr/bin/env python3
"""Ecosystem scan: sample real-world MCP configs from public GitHub repos.

Fetches config files via GitHub code search, runs the mcplint rule engine over
them, and aggregates findings into a report. Repo names are kept only in the
private raw dataset; the generated report contains aggregates only.

Usage:
    uv run python scripts/ecosystem_scan.py --out research/data --per-query 100
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcplint.checks import CHECKS
from mcplint.models import MCPConfigFile, ScanContext
from mcplint.packages import package_specs
from mcplint.parse import parse_config_file
from mcplint.rules import load_rules

QUERIES: list[tuple[str, str]] = [
    ("claude", "filename:.mcp.json"),
    ("cursor", "filename:mcp.json path:.cursor"),
    ("vscode", "filename:mcp.json path:.vscode"),
    ("opencode", "filename:opencode.json"),
    ("codex", "filename:config.toml path:.codex"),
]

# Rules that make no sense on a corpus of isolated, freshly downloaded files.
SKIP_RULES = {"MCP002", "MCP011", "MCP012"}

MAX_FILE_BYTES = 200_000
SEARCH_SLEEP_SECONDS = 7.0
FETCH_SLEEP_SECONDS = 0.05
OWN_REPO = "dtduc-git/mcplint"


def path_matches(client: str, path: str) -> bool:
    """Code search matches substrings; keep only exact, live config paths."""
    parts = path.split("/")
    base = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else ""
    if client == "claude":
        return base == ".mcp.json"
    if client == "cursor":
        return base == "mcp.json" and parent == ".cursor"
    if client == "vscode":
        return base == "mcp.json" and parent == ".vscode"
    if client == "opencode":
        return base in ("opencode.json", "opencode.jsonc")
    if client == "codex":
        return base == "config.toml" and parent == ".codex"
    return False


def search(query: str, per_query: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    pages = max(1, (per_query + 99) // 100)
    for page in range(1, pages + 1):
        url = (
            f"search/code?q={urllib.parse.quote_plus(query)}"
            f"&per_page=100&page={page}"
        )
        proc = subprocess.run(["gh", "api", url], capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"warn: search failed ({query}): {proc.stderr.strip()[:200]}", file=sys.stderr)
            break
        payload = json.loads(proc.stdout)
        items.extend(payload.get("items", []))
        time.sleep(SEARCH_SLEEP_SECONDS)
    return items[:per_query]


def fetch_raw(item: dict[str, Any]) -> str | None:
    repo = item["repository"]
    branch = repo.get("default_branch") or "HEAD"
    path = urllib.parse.quote(item["path"], safe="/")
    url = f"https://raw.githubusercontent.com/{repo['full_name']}/{branch}/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "mcplint-ecosystem-scan"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(MAX_FILE_BYTES + 1)
    except Exception:  # noqa: BLE001 - best effort over hundreds of URLs
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def run_engine(
    configs: list[MCPConfigFile], rules: list, online: bool, root: Path
) -> list[dict[str, Any]]:
    ctx = ScanContext(
        configs=configs,
        instructions=[],
        lock=None,
        lock_path=None,
        root=root,
        online=online,
    )
    records: list[dict[str, Any]] = []
    for rule in rules:
        if rule.id in SKIP_RULES or rule.once or "config" not in rule.targets:
            continue
        check_fn = CHECKS.get(rule.check)
        if check_fn is None:
            continue
        for config in configs:
            for finding in check_fn(rule, config, ctx):
                records.append(
                    {
                        "file": str(config.path),
                        "rule": finding.rule_id,
                        "severity": finding.severity.value,
                        "server": finding.server,
                        "message": finding.message,
                    }
                )
    return records


def build_report(
    sample: dict[str, Any],
    configs: list[MCPConfigFile],
    findings: list[dict[str, Any]],
    generated_at: str,
    online: bool,
) -> str:
    files_parsed = sample["filesParsed"]
    rule_files: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        rule_files[finding["rule"]].add(finding["file"])
    files_with_findings = len({finding["file"] for finding in findings})

    package_refs: Counter[str] = Counter()
    package_pinned: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    servers_total = 0
    for config in configs:
        for server in config.servers:
            servers_total += 1
            transport_counts[server.transport] += 1
            for spec in package_specs(server):
                if not spec.name:
                    continue
                package_refs[spec.name] += 1
                if spec.pinned:
                    package_pinned[spec.name] += 1

    refs_total = sum(package_refs.values())

    def pct(part: int, whole: int) -> str:
        return f"{(100.0 * part / whole):.1f}%" if whole else "n/a"

    lines: list[str] = []
    lines.append("# State of MCP configs in the wild")
    lines.append("")
    lines.append(f"_Generated {generated_at} with mcplint 0.1.0._")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Public MCP client configs were sampled via the GitHub code search API "
        "(queries below, first pages of best-match results), filtered to exact "
        "live config filenames (template/sample/backup copies excluded), "
        "downloaded from raw.githubusercontent.com, and scanned with the mcplint "
        "rule engine. Placeholder credentials (\"your-key-here\", \"dummy\", ...) "
        "are not counted. All stats are aggregate; no repository is named in "
        "this report. Cross-file rules (shadowing, lockfile drift) and "
        "file-permission checks are excluded. OSV advisory lookups for pinned "
        f"packages: {'enabled' if online else 'disabled'}."
    )
    lines.append("")
    lines.append("| Query | Files requested |")
    lines.append("| --- | --- |")
    for client, query in QUERIES:
        lines.append(f"| `{query}` | {sample['perQuery'][client]} |")
    lines.append("")
    lines.append("## Headline")
    lines.append("")

    def rule_pct(rule_id: str) -> str:
        return pct(len(rule_files.get(rule_id, set())), files_parsed)

    lines.append(
        f"- **{pct(files_with_findings, files_parsed)}** of configs have at least one finding"
    )
    lines.append(f"- **{rule_pct('MCP003')}** reference at least one unpinned package")
    lines.append(f"- **{rule_pct('MCP006')}** declare no auth material for a remote endpoint")
    lines.append(f"- **{rule_pct('MCP001')}** contain credential material in plain text")
    lines.append(f"- **{rule_pct('MCP008')}** define shell / command-execution servers")
    lines.append("")
    lines.append("## Sample")
    lines.append("")
    lines.append(f"- Files downloaded and parsed: **{files_parsed}**")
    lines.append(f"- Repositories: **{sample['repos']}**")
    lines.append(f"- Parse failures / unparseable: {sample['parseFailures']}")
    lines.append(f"- MCP servers referenced: **{servers_total}**")
    lines.append(
        f"- Files with at least one finding: **{files_with_findings}** "
        f"({pct(files_with_findings, files_parsed)})"
    )
    lines.append("")
    lines.append("### Transport mix")
    lines.append("")
    lines.append("| Transport | Servers |")
    lines.append("| --- | --- |")
    for transport, count in transport_counts.most_common():
        lines.append(f"| {transport} | {count} |")
    lines.append("")
    lines.append("## Findings by rule")
    lines.append("")
    lines.append("| Rule | Files affected | Share of files |")
    lines.append("| --- | --- | --- |")
    for rule_id, files in sorted(rule_files.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {rule_id} | {len(files)} | {pct(len(files), files_parsed)} |")
    lines.append("")
    lines.append("## Package pinning")
    lines.append("")
    lines.append(
        f"- Third-party package references found: **{refs_total}** "
        f"across **{len(package_refs)}** distinct names"
    )
    lines.append("")
    lines.append("| Package | References | Pinned |")
    lines.append("| --- | --- | --- |")
    for name, count in package_refs.most_common(15):
        pinned = package_pinned.get(name, 0)
        lines.append(f"| `{name}` | {count} | {pinned} ({pct(pinned, count)}) |")
    lines.append("")
    lines.append("## Known vulnerable packages (OSV)")
    lines.append("")
    cve_files = rule_files.get("MCP013", set())
    if not cve_files:
        lines.append("- No OSV advisories matched the pinned packages in this sample.")
    else:
        advisories: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            if finding["rule"] != "MCP013":
                continue
            match = re.match(r"^(\S+) matches ((?:GHSA|CVE)-[A-Za-z0-9-]+)", finding["message"])
            if match:
                advisories[match.group(1)].add(match.group(2))
        lines.append(
            f"- **{len(cve_files)}** config files reference a pinned package version "
            f"with a known advisory; **{len(advisories)}** distinct package versions matched."
        )
        lines.append("")
        lines.append("| Package | Advisory |")
        lines.append("| --- | --- |")
        for package, ids in sorted(advisories.items()):
            lines.append(f"| `{package}` | {', '.join(sorted(ids))} |")
    lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append(
        "- GitHub code search returns best-match results, not a uniform random "
        "sample; popularity and recency skew the corpus."
    )
    lines.append(
        "- Configs are point-in-time snapshots; a repo can fix a finding later."
    )
    lines.append(
        "- Heuristic rules trade precision for recall; counts are a lower bound "
        "on real risk signals, not a per-repo verdict."
    )
    lines.append(
        "- A remote endpoint can enforce authentication server-side even when "
        "the config declares no auth material; MCP006 measures what the config "
        "itself discloses."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("research/data"))
    parser.add_argument("--per-query", type=int, default=100)
    parser.add_argument("--online", action="store_true", help="Enable OSV CVE lookups.")
    args = parser.parse_args()

    out_dir: Path = args.out
    downloads_dir = out_dir / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    seen: set[tuple[str, str]] = set()
    selected: list[tuple[str, dict[str, Any]]] = []
    per_query_counts: dict[str, int] = {}
    for client, query in QUERIES:
        count = 0
        for item in search(query, args.per_query):
            repo = item["repository"]
            if repo["full_name"] == OWN_REPO or repo.get("fork"):
                continue
            if not path_matches(client, item["path"]):
                continue
            key = (repo["full_name"], item["path"])
            if key in seen:
                continue
            seen.add(key)
            selected.append((client, item))
            count += 1
        per_query_counts[client] = count
        print(f"{client}: selected {count}", file=sys.stderr)

    configs: list[MCPConfigFile] = []
    raw_records: list[dict[str, Any]] = []
    parse_failures = 0
    repos: set[str] = set()
    for index, (client, item) in enumerate(selected):
        repo = item["repository"]["full_name"]
        text = fetch_raw(item)
        time.sleep(FETCH_SLEEP_SECONDS)
        if text is None:
            parse_failures += 1
            continue
        suffix = ".toml" if item["path"].endswith(".toml") else ".json"
        local_path = downloads_dir / f"{client}__{index:04d}{suffix}"
        local_path.write_text(text, encoding="utf-8")
        config = parse_config_file(local_path, client=client)
        if config is None:
            parse_failures += 1
            continue
        repos.add(repo)
        configs.append(config)
        raw_records.append(
            {
                "repo": repo,
                "path": item["path"],
                "localPath": str(local_path),
                "stars": item["repository"].get("stargazers_count", 0),
                "client": client,
                "servers": [server.name for server in config.servers],
            }
        )

    print(f"downloaded: {len(selected)}, parsed: {len(configs)}", file=sys.stderr)

    rules = load_rules()
    findings = run_engine(configs, rules, args.online, out_dir)

    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_file[finding["file"]].append(finding)

    for record, config in zip(raw_records, configs, strict=False):
        record["findings"] = by_file.get(str(config.path), [])

    generated_at = datetime.now(UTC).isoformat()
    sample = {
        "generatedAt": generated_at,
        "perQuery": per_query_counts,
        "filesParsed": len(configs),
        "repos": len(repos),
        "parseFailures": parse_failures,
    }

    (out_dir / "raw.json").write_text(
        json.dumps({"sample": sample, "records": raw_records}, indent=2),
        encoding="utf-8",
    )
    (out_dir / "aggregate.json").write_text(
        json.dumps(
            {
                "sample": sample,
                "findings": len(findings),
                "ruleFiles": {
                    rule: len(files) for rule, files in _by_rule(findings).items()
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    report_dir = Path("research")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "state-of-mcp-configs.md"
    report_path.write_text(
        build_report(sample, configs, findings, generated_at, args.online) + "\n",
        encoding="utf-8",
    )
    print(f"report: {report_path}", file=sys.stderr)
    print(json.dumps(sample, indent=2))


def _by_rule(findings: list[dict[str, Any]]) -> dict[str, set[str]]:
    rule_files: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        rule_files[finding["rule"]].add(finding["file"])
    return rule_files


if __name__ == "__main__":
    main()

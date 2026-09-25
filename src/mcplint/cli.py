"""mcplint command line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from . import __version__
from .aibom import build_aibom
from .discovery import discover
from .gate import (
    GateError,
    GateResult,
    load_auth_expectations,
    load_env_file,
    load_profile,
    result_to_json,
    run_auth_gate,
    run_gate,
)
from .lockfile import LOCKFILE_NAME, build_lock, load_lock, verify_lock, write_lock
from .models import ScanResult, severity_from
from .parse import parse_config_file
from .report.pretty import render
from .report.sarif import to_sarif
from .rules import load_rules
from .rules.model import Rule
from .scanner import root_of
from .scanner import scan as run_scan

app = typer.Typer(
    name="mcplint",
    help=(
        "Local-first, CI-native security scanner for MCP servers. "
        "Never executes your MCP servers."
    ),
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect available rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)

FILE_CONFIG_NAME = ".mcplint.yaml"

WORKFLOW_TEMPLATE = """\
name: mcplint
on: [push, pull_request]

jobs:
  mcplint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: dtduc-git/mcplint@main
        with:
          fail-on: high
"""

CONFIG_TEMPLATE = """\
# mcplint configuration
fail_on: high   # critical | high | medium | low | info | none
online: false   # enable OSV CVE lookups (network); off by default
ignore: []      # rule ids to ignore, e.g. [MCP002]
"""


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcplint {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Scan MCP configurations and agent instruction files for security issues."""


def _load_file_config() -> dict:
    path = Path(FILE_CONFIG_NAME)
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        err_console.print(f"[yellow]warning:[/yellow] could not parse {FILE_CONFIG_NAME}")
        return {}
    return data if isinstance(data, dict) else {}


def _run_scan(
    paths: list[Path] | None,
    home: bool,
    online: bool,
    rules_dir: list[Path] | None,
    ignore: list[str] | None,
) -> tuple[ScanResult, dict]:
    file_config = _load_file_config()
    effective_online = online or bool(file_config.get("online", False))
    effective_ignore = set(ignore or []) | set(file_config.get("ignore", []) or [])
    scan_paths = [Path(p) for p in (paths or [])] or [
        Path(p) for p in file_config.get("paths", []) or []
    ]
    if not scan_paths:
        scan_paths = [Path(".")]

    dirs = list(rules_dir or []) + list(file_config.get("rules_dir", []) or [])
    rules = load_rules([Path(d) for d in dirs])
    result = run_scan(scan_paths, rules, include_home=home, online=effective_online)
    if effective_ignore:
        result = ScanResult(
            findings=[f for f in result.findings if f.rule_id not in effective_ignore],
            configs=result.configs,
            instructions=result.instructions,
        )
    return result, file_config


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        None, help="Files or directories to scan (default: current directory)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print findings as JSON."),
    sarif: str = typer.Option(
        None, "--sarif", help="Write a SARIF 2.1.0 report to PATH ('-' for stdout)."
    ),
    fail_on: str = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 when a finding at this severity or above exists "
        "(critical|high|medium|low|info|none).",
    ),
    home: bool = typer.Option(
        False, "--home", help="Also scan user-level client configs (~/.cursor, ~/.codex, ...)."
    ),
    online: bool = typer.Option(
        False,
        "--online",
        help="Enable online checks (OSV CVE lookups). Off by default: nothing leaves your machine.",
    ),
    rules_dir: list[Path] = typer.Option(
        None, "--rules-dir", help="Extra rule directory (repeatable)."
    ),
    ignore: list[str] = typer.Option(None, "--ignore", help="Rule id to ignore (repeatable)."),
    quiet: bool = typer.Option(False, "--quiet", help="Only print the summary."),
) -> None:
    """Scan MCP configs and agent instruction files."""
    result, file_config = _run_scan(paths, home, online, rules_dir, ignore)

    if as_json:
        console.print_json(json.dumps(result.to_dict()))
    elif not quiet:
        render(result, console)
    else:
        console.print(f"{len(result.findings)} finding(s)")

    if sarif:
        payload = json.dumps(to_sarif(result.findings), indent=2)
        if sarif == "-":
            print(payload)
        else:
            Path(sarif).write_text(payload + "\n", encoding="utf-8")
            err_console.print(f"SARIF written to {sarif}")

    threshold = fail_on or str(file_config.get("fail_on", "high"))
    if threshold.lower() != "none" and result.findings:
        limit = severity_from(threshold)
        if result.worst_rank <= limit.rank:
            raise typer.Exit(code=1)


SEVERITY_COLORS = {
    "critical": "red",
    "high": "orange1",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _render_gate(result: GateResult, console: Console) -> None:
    console.print(
        f"[bold]mcplint gate[/bold] profile={result.profile} target={result.target} "
        f"({result.probes_run} probe(s), read-only)"
    )
    if result.profile == "auth" and not result.inventory:
        console.print(
            "[yellow]test key sees 0 tool(s)[/yellow] — nothing to compare. Check the "
            "key's MCP grants (object_permission) and that the upstream token is "
            "accepted; see the AUTH000 note below."
        )
    if result.inventory:
        shown = ", ".join(result.inventory[:20])
        extra = (
            ""
            if len(result.inventory) <= 20
            else f" … (+{len(result.inventory) - 20} more)"
        )
        console.print(
            f"[dim]test key sees {len(result.inventory)} tool(s):[/dim] {shown}{extra}"
        )
    if not result.findings:
        if result.notes:
            detail = (
                f"{len(result.notes)} note(s)"
                if result.profile == "auth"
                else f"{len(result.notes)} of {result.probes_run} probe(s)"
            )
            console.print(
                f"[yellow]No findings, but {detail} to read before concluding "
                "anything — see the notes below.[/yellow]"
            )
            return
        message = (
            "No findings: the test key's visibility and access matched expectations."
            if result.profile == "auth"
            else "No findings and no inconclusive probes: every probe ended in a "
            "401/403."
        )
        console.print(f"[green]{message}[/green]")
        return
    table = Table(header_style="bold")
    table.add_column("Probe", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("HTTP", no_wrap=True)
    table.add_column("Finding")
    for finding in sorted(result.findings, key=lambda f: f.severity.rank):
        color = SEVERITY_COLORS.get(finding.severity.value, "white")
        table.add_row(
            finding.probe_id,
            f"[{color}]{finding.severity.value}[/{color}]",
            str(finding.status),
            finding.title,
        )
    console.print(table)
    for finding in sorted(result.findings, key=lambda f: f.severity.rank):
        refs = " · ".join(
            part for part in (finding.cve, finding.owasp, finding.docs) if part
        )
        console.print(f"\n[bold]{finding.probe_id}[/bold] {finding.title}")
        if refs:
            console.print(f"  [dim]{refs}[/dim]")
        console.print(f"  [dim]evidence:[/dim] {finding.evidence or '(empty body)'}")
        console.print(f"  [bold]Fix:[/bold] {finding.remediation.strip()}")


@app.command()
def gate(
    target: str = typer.Argument(
        None, help="Gateway base URL (default: the profile's, e.g. http://localhost:4000)."
    ),
    profile: str = typer.Option("litellm", "--profile", help="Probe profile to run."),
    auth: Path = typer.Option(
        None,
        "--auth",
        help="Run authenticated read-only checks using this expectations file "
        "(see gate_data/auth-expectations.example.yaml).",
    ),
    profiles_dir: list[Path] = typer.Option(
        None, "--profiles-dir", help="Extra profile directory (repeatable)."
    ),
    env_file: Path = typer.Option(
        None,
        "--env-file",
        help="Load KEY=VALUE secrets from this file (existing environment wins; "
        "keep the file out of version control).",
    ),
    allow_host: bool = typer.Option(
        False,
        "--allow-host",
        help="Confirm the target host is yours (required for anything not on loopback).",
    ),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout in seconds."),
    as_json: bool = typer.Option(False, "--json", help="Print results as JSON."),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit 1 when a finding at this severity or above exists "
        "(critical|high|medium|low|info|none).",
    ),
) -> None:
    """Probe a running MCP gateway for missing authentication (read-only).

    By default, sends a battery of unauthenticated requests and checks each one
    is denied. With --auth, uses one (test) key from an environment variable to
    verify what that key is allowed to see and reach. It never calls write
    tools and never changes state. Only loopback targets are allowed unless
    --allow-host is given.
    """
    try:
        if env_file is not None:
            for name, value in load_env_file(env_file).items():
                os.environ.setdefault(name, value)
        if auth is not None:
            expectations = load_auth_expectations(auth)
            result = run_auth_gate(
                expectations, target, allow_host=allow_host, timeout=timeout
            )
        else:
            effective_profile = load_profile(profile, extra_dirs=profiles_dir)
            result = run_gate(
                effective_profile, target, allow_host=allow_host, timeout=timeout
            )
    except GateError as exc:
        err_console.print(f"[red]gate error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if as_json:
        console.print_json(result_to_json(result))
    else:
        _render_gate(result, console)
        for note in result.notes:
            console.print(
                f"[dim]· {note.probe_id}: {note.reason} (HTTP {note.status})[/dim]"
            )

    threshold = fail_on.lower()
    if threshold != "none" and result.findings:
        limit = severity_from(threshold)
        if result.worst_rank <= limit.rank:
            raise typer.Exit(code=1)


def _lock_rule() -> Rule:
    for rule in load_rules():
        if rule.id == "MCP012":
            return rule
    return Rule(
        id="MCP012",
        title="Lockfile drift detected",
        severity="high",
        check="lockfile_drift",
    )


@app.command()
def lock(
    paths: list[Path] = typer.Argument(None, help="Files or directories to lock (default: '.')."),
    check: bool = typer.Option(
        False, "--check", help="Verify against the existing lockfile instead of writing."
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help=f"Lockfile path (default: <root>/{LOCKFILE_NAME})."
    ),
) -> None:
    """Pin server fingerprints and detect drift (rug pulls)."""
    scan_paths = [Path(p) for p in (paths or [])] or [Path(".")]
    config_paths, _ = discover(scan_paths, include_home=False)
    parsed = [c for p in config_paths if (c := parse_config_file(p)) is not None]
    if not parsed:
        err_console.print("[yellow]No MCP config files found.[/yellow]")
        raise typer.Exit(code=2)

    root = root_of(scan_paths)
    lock_path = output or (root / LOCKFILE_NAME)

    if check:
        existing = load_lock(lock_path)
        if existing is None:
            err_console.print(f"[red]No lockfile at {lock_path}[/red]")
            raise typer.Exit(code=2)
        findings = verify_lock(existing, parsed, root, _lock_rule())
        render(ScanResult(findings=findings, configs=parsed, instructions=[]), console)
        if findings:
            raise typer.Exit(code=1)
        return

    write_lock(lock_path, build_lock(parsed, root))
    server_count = sum(len(c.servers) for c in parsed)
    console.print(f"Locked {len(parsed)} file(s), {server_count} server(s) -> {lock_path}")


@app.command()
def inventory(
    paths: list[Path] = typer.Argument(
        None, help="Files or directories to inventory (default: '.')."
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Write the AIBOM to PATH."),
) -> None:
    """Export a CycloneDX AIBOM of every MCP server found."""
    scan_paths = [Path(p) for p in (paths or [])] or [Path(".")]
    config_paths, _ = discover(scan_paths, include_home=False)
    parsed = [c for p in config_paths if (c := parse_config_file(p)) is not None]
    bom = build_aibom(parsed, root_of(scan_paths))
    payload = json.dumps(bom, indent=2)
    if output:
        output.write_text(payload + "\n", encoding="utf-8")
        console.print(f"AIBOM written to {output} ({len(bom['components'])} component(s))")
    else:
        print(payload)


@rules_app.command("list")
def rules_list() -> None:
    """List all available rules."""
    table = Table(header_style="bold")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("OWASP", no_wrap=True)
    table.add_column("Title")
    for rule in load_rules():
        table.add_row(rule.id, rule.severity.value, rule.owasp, rule.title)
    console.print(table)


@rules_app.command("explain")
def rules_explain(rule_id: str = typer.Argument(..., help="Rule id, e.g. MCP001.")) -> None:
    """Explain one rule in detail."""
    for rule in load_rules():
        if rule.id.lower() == rule_id.lower():
            console.print(f"[bold]{rule.id}[/bold] - {rule.title}")
            console.print(f"Severity: {rule.severity.value}")
            if rule.owasp:
                console.print(f"OWASP: {rule.owasp}")
            if rule.description:
                console.print(f"\n{rule.description.strip()}")
            if rule.remediation:
                console.print(f"\n[bold]Remediation[/bold]\n{rule.remediation.strip()}")
            return
    err_console.print(f"[red]Unknown rule:[/red] {rule_id}")
    raise typer.Exit(code=2)


@app.command()
def init(force: bool = typer.Option(False, "--force", help="Overwrite existing files.")) -> None:
    """Write a GitHub Actions workflow and a starter config."""
    targets = (
        (Path(".github/workflows/mcplint.yml"), WORKFLOW_TEMPLATE),
        (Path(FILE_CONFIG_NAME), CONFIG_TEMPLATE),
    )
    for path, content in targets:
        if path.exists() and not force:
            err_console.print(f"[yellow]skip[/yellow] {path} (exists; use --force)")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.print(f"wrote {path}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

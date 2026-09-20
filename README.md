# mcplint

**Local-first, CI-native security scanner for MCP servers.**
OWASP MCP Top 10 rules, a lockfile for rug-pull detection, and an AIBOM export.
It never executes your MCP servers.

[![CI](https://github.com/dtduc-git/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/dtduc-git/mcplint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcplint-sec)](https://pypi.org/project/mcplint-sec/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![M8ven Live Monitored](https://m8ven.ai/badge/mcp/dtduc-git-mcplint-1qvg1q)](https://m8ven.ai/mcp/dtduc-git-mcplint-1qvg1q)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-mcplint--sec-blue?logo=github)](https://github.com/marketplace/actions/mcplint-sec)

```
uvx mcplint-sec scan
```

> PyPI distribution is `mcplint-sec` (the `mcplint` name collides with an
> existing project); it installs the **`mcplint`** command. With `uvx`, invoke
> it by distribution name: `uvx mcplint-sec …`.

---

## Why

MCP went from a few hundred servers to a 10,000+ server ecosystem — and the
security model did not keep up:

- ~40% of internet-exposed MCP servers have **no authentication** (Censys, 2026)
- A single compromised MCP server reaches a **78% attack success rate** when
  five servers share one agent (arXiv 2601.17549)
- `CVE-2025-6514` in `mcp-remote` (CVSS 9.6) affected a package with 437k+ downloads
- Registries accepted typosquatted MCP servers; tool descriptions are mutable
  after approval ("rug pulls")

Most scanners run on **your machine** and hand your tool descriptions to a
vendor API. mcplint scans the **configs in your repo**, in CI, with nothing
leaving your environment.

## Quickstart

```bash
# scan the current repo
uvx mcplint-sec scan

# also scan user-level client configs and skills
uvx mcplint-sec scan --home

# pin server fingerprints, detect drift in CI
uvx mcplint-sec lock
uvx mcplint-sec lock --check

# CycloneDX AIBOM of every MCP server
uvx mcplint-sec inventory -o aibom.json

# probe a RUNNING gateway for missing authentication (read-only, loopback by default)
uvx mcplint-sec gate
uvx mcplint-sec gate https://gateway.internal:4000 --allow-host

# what do the rules mean?
uvx mcplint-sec rules list
uvx mcplint-sec rules explain MCP004

# scaffold a GitHub Actions workflow + starter config
uvx mcplint-sec init
```

Exit code is `1` when a finding at `--fail-on` severity (default `high`)
exists — drop it into CI as-is.

## What it scans

| Input | Examples |
| --- | --- |
| MCP configs | `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `opencode.json[c]`, `.codex/config.toml`, `cline_mcp_settings.json`, `~/.claude.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json` |
| Instruction / skill files | `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`, `.cursor/rules/*.mdc` |

Scans recurse into subdirectories (`node_modules`, virtualenvs and build
outputs are skipped), so monorepos work out of the box.

## Rules

| Rule | Severity | OWASP MCP Top 10 | Checks |
| --- | --- | --- | --- |
| MCP001 | critical | MCP01 Token Mismanagement | hardcoded secrets in env/args/headers |
| MCP002 | medium | MCP01 | unsafe config file permissions |
| MCP003 | medium | MCP04 Supply Chain | unpinned `npx`/`uvx`/`pipx` packages |
| MCP004 | high | MCP04 Supply Chain | typosquat/lookalike package names |
| MCP005 | high | MCP07 Auth | remote endpoint over plain `http://` |
| MCP006 | medium | MCP07 Auth | remote endpoint with no auth material |
| MCP007 | medium | MCP02 Scope Creep | filesystem server scoped to `/`, `$HOME`, ... |
| MCP008 | high | MCP05 Command Execution | shell / command-execution servers |
| MCP009 | high | MCP03 Tool Poisoning / MCP06 Intent Flow Subversion | prompt-injection indicators in instructions |
| MCP010 | critical | MCP03 Tool Poisoning / MCP06 Intent Flow Subversion | zero-width / bidi unicode (hidden text) |
| MCP011 | medium | MCP03 Tool Poisoning | cross-config server name shadowing |
| MCP012 | high | MCP03 Tool Poisoning | lockfile drift (rug-pull detection) |
| MCP013 | high | MCP04 Supply Chain | pinned packages matching OSV advisories (`--online`) |

Rules are data: plain YAML in [`src/mcplint/rules_data/`](src/mcplint/rules_data).
Bring your own with `--rules-dir ./my-rules`.

Coverage: the 13 rules map to 7 of the 10 OWASP MCP Top 10 categories; MCP08
(audit & telemetry), MCP09 (shadow servers) and MCP10 (context over-sharing)
are runtime and operational risks outside the reach of static config scanning.

## Runtime gate

Static rules can tell you a config *looks* right. `mcplint gate` tells you
whether a gateway that is **already running** actually enforces
authentication. It sends one small, read-only request per known failure class —
derived from public CVEs and advisories — and checks that every one of them is
denied.

Why this exists, in numbers:

- **CVE-2026-59822** (LiteLLM MCP auth bypass) is the **first MCP flaw on
  CISA's Known Exploited Vulnerabilities catalog** (2026-09-02) — the "Bearer a"
  one-character token was enough to open an MCP session, and it was chained to
  command injection and cryptominers in the wild.
- Wiz Research scanned 3,074 public LiteLLM instances: **9.6% accepted the
  default master key `sk-1234` or required no authentication at all**.
- A June 2026 audit found **66% of 8,235 registered MCP servers** return a
  server-authored `instructions` blob; Censys counted **12,500+ MCP services
  reachable from the internet** in April 2026.

- **Read-only.** No tool calls, no state changes: the battery only asks
  "does this endpoint reject anonymous callers?".
- **Loopback by default.** Anything that is not `localhost`/`127.0.0.1`
  requires `--allow-host` (confirming the gateway is yours).
- **Rules as data.** Profiles live in
  [`src/mcplint/gate_data/`](src/mcplint/gate_data); bring your own with
  `--profiles-dir`.

```bash
uvx mcplint-sec gate                            # http://localhost:4000
uvx mcplint-sec gate https://gateway.internal   # + --allow-host
uvx mcplint-sec gate --json --fail-on high      # CI-friendly
```

| Probe | Severity | Derived from | Checks |
| --- | --- | --- | --- |
| GATE001 | critical | CVE-2026-59822 | MCP `/mcp` accepts a fabricated `Authorization` bearer |
| GATE002 | critical | CVE-2026-59822 | MCP `/mcp` accepts an invalid `x-litellm-api-key` |
| GATE003 | high | — | MCP `/mcp` answers anonymous callers at all |
| GATE004 | high | — | Legacy `/sse` endpoint answers anonymous callers |
| GATE005 | high | CVE-2026-42271 | `/mcp-rest/test/connection` reachable without credentials |
| GATE006 | high | — | MCP management API reachable without credentials |
| GATE007 | medium | CVE-2026-49468 | Management route authenticates from a spoofed `Host` header |
| GATE008 | high | CVE-2026-52869 | MCP `/mcp` served `tools/list` on a never-issued `Mcp-Session-Id` |

Exit codes: `0` clean, `1` finding at `--fail-on` severity or above, `2`
operational error (bad profile, unreachable target, non-loopback target
without `--allow-host`). Add it to your deploy pipeline and re-run it after
every gateway upgrade.

Lab-verified against real LiteLLM releases: patched **1.100.0** denies every
probe; pre-fix **1.83.14** errors instead of denying on the MCP routes —
see [`research/gate-lab-verification.md`](research/gate-lab-verification.md).

### Authenticated checks (`gate --auth`)

The anonymous battery answers "can strangers get in?". The authenticated mode
answers the harder question for shared gateways: **does this key get exactly
what it should?** — with a *test* key, still read-only.

```bash
export LITELLM_TEST_KEY=sk-...           # dedicated test key, not a person's
uvx mcplint-sec gate --auth expectations.yaml https://gateway.internal --allow-host

# or keep every secret in one uncommitted file instead of exporting:
uvx mcplint-sec gate --auth expectations.yaml --env-file .env.local --allow-host
```

Expectations are data (see
[`gate_data/auth-expectations.example.yaml`](src/mcplint/gate_data/auth-expectations.example.yaml)):

| Check | Configuration | Severity |
| --- | --- | --- |
| AUTH001 | tools matching `forbidden_tools` patterns are visible to the key | high |
| AUTH002 | tools outside the strict `expect_tools` allowlist are visible | medium |
| AUTH003 | `x-mcp-servers` scoping not enforced (`forbidden_servers`) | high |
| AUTH004 | opt-in `read_probe` returned data for an object the test user cannot access | critical |
| AUTH005 | an expected tool is missing (config drift) | low |
| AUTH006 | `read_probe` denied although the user should have access (`expect: allow`) | medium |

Per-user gateways (Confluence-style) can forward the test user's upstream token
with `upstream_headers` (also env-referenced, never literal):

```yaml
upstream_headers:
  x-mcp-confluence-authorization: env/ATLASSIAN_USER_TOKEN
```

If a gateway denies `/mcp` because its route patterns only match `/mcp/`, gate
retries the canonical path automatically.

Safety: the key and every `upstream_headers` value are read **from environment
variables only** (literals in the file are rejected) and are never printed; no
tool calls happen unless `read_probe` is explicitly configured; returned content
is never echoed (redacted in evidence). `--env-file FILE` is a convenience for
injecting the key and per-server tokens (existing environment variables win;
keep that file out of version control). Use a dedicated test key that maps to a
test user.

## GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: dtduc-git/mcplint@v0.2.0
    with:
      fail-on: high
```

Findings show up as annotations and in the repo's code-scanning tab (SARIF).
Or scaffold this workflow and a starter config with `uvx mcplint-sec init`.

## Design principles

1. **Never executes your MCP servers.** Scanning is static by default; running
   arbitrary server commands in CI is not acceptable. The one active command is
   `gate`: read-only HTTP probes against a target you own, no tool calls.
2. **Nothing leaves your machine** unless you opt in with `--online` (OSV CVE
   lookups only) or explicitly point `gate` at a remote host.
3. **Pin and diff.** `.mcplint.lock.json` fingerprints every server (salted
   hashes for env values) so post-approval changes are visible in `git diff`.
4. **Rules as data.** YAML + a small, tested check engine — contributions do
   not need to touch the scanner core.
5. **Non-goals:** no gateway, no proxy, no runtime traffic monitoring, no SaaS.

## Research

[**State of MCP configs in the wild**](research/state-of-mcp-configs.md) — an
aggregate scan of 1,210 public MCP configs from 1,197 repositories (56.5% have
at least one finding). Methodology and the reproducible script
([`scripts/ecosystem_scan.py`](scripts/ecosystem_scan.py)) are included.

Read the write-up: [We scanned 1,210 MCP configs on GitHub. 56% have a security finding.](blog/2026-09-13-state-of-mcp-configs.md)

## Development

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .
uv run mcplint scan fixtures/vulnerable-repo --fail-on none
```

## License

Apache-2.0

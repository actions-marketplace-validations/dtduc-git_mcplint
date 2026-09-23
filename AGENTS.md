# mcplint — agent notes

## What this is

Local-first, CI-native security scanner for MCP configs and agent skill files.
13 rules mapped to the OWASP MCP Top 10. Static only — it never executes MCP
servers; no network unless `--online`.

- GitHub: https://github.com/dtduc-git/mcplint
- PyPI: `mcplint-sec` (the command is `mcplint`)
- Install: `uvx mcplint-sec scan`

## Current state (2026-09-23)

- **v0.4.1 — GATE008 false-positive fix.** The v0.4.0 probe flagged any 2xx on
  a fabricated session id, including JSON-RPC errors and empty tools lists.
  GATE008 now sends `tools/list` twice (no session header as a negative control,
  then a never-issued `Mcp-Session-Id`) and fires only when the control is
  denied and the second response carries a real inventory (`require: tools`).
  Probe YAML validates `steps[].expect` / `require`; findings carry only the
  request trace (no response bodies); the CLI no longer claims enforcement when
  probes were inconclusive; AUTH004/AUTH006 treat 5xx as notes (81 tests).
- **v0.4.0 — `mcplint gate` + authenticated checks.** Anonymous battery
  (`gate_data/litellm.yaml`, 8 probes; 5 cite a CVE — CVE-2026-59822 ×2,
  -42271, -49468, -52869 — and GATE003/004/006 are hygiene checks) — GATE008
  (v0.4.0) sends a `tools/list` twice — once with no session
  header as a negative control, once with a never-issued
  `Mcp-Session-Id: mcp-session-<random>` — and only fires when the control is
  denied and the forged session gets a real tool inventory (`require: tools`),
  to catch the session-confusion class (CVE-2026-52869 upstream SDK; mcp-grafana
  CVE-2026-19516 chain).
  plus `gate --auth <expectations.yaml>`: with one *test* key (env-var only),
  verifies tool-list filtering (AUTH001/002/005), `x-mcp-servers` scoping
  (AUTH003) and one opt-in read probe against an object the user cannot access
  (AUTH004, content redacted) and a negative control with `expect: allow`
  (AUTH006 if the user is denied access they should have).
  `upstream_headers` forwards a test user's
  upstream token (env-referenced) for per-user gateways; `--env-file FILE`
  injects the key + tokens from one uncommitted file; `/mcp` denials retry the
  canonical `/mcp/` path. All gate requests send `User-Agent: mcplint-gate`
  (WAFs like Cloudflare block Python-urllib with Error 1010); edge/WAF blocks
  are detected and explained instead of being blamed on the key; an empty
  tool inventory is reported with the two usual causes (missing `Bearer `
  prefix, wrong `x-mcp-<alias>-*` header); responses are read up to 4 MiB so
  large tools/list bodies with JSON schemas parse correctly.
  Read-only; loopback-only unless `--allow-host`; exit 0/1/2. Tests: `tests/test_gate.py` (mock patched/vulnerable/redirect/
  erroring/overexposed/leaky-scope/leaky-read gateways).
- First production run of the anonymous battery against a live gateway: clean
  (6/7 probes denied, `/sse` absent).
- Demand signals for the gate, 2026-09: CVE-2026-59822 became the **first MCP
  flaw on CISA KEV** (2026-09-02, actively exploited, chained to command
  injection); Wiz scan of 3,074 public LiteLLM instances → 9.6% accepted the
  default master key `sk-1234` or no auth; Censys: 12,500+ internet-facing MCP
  services (April 2026). Blog: `blog/2026-09-21-gateway-auth-is-not-session-auth.md`.
- Older: **v0.1.1 released** (see below). Publishing is automated around
  `release.yml` (trusted publishing): bump `src/mcplint/__init__.py`, commit,
  `git tag vX.Y.Z`, push.
- CI (`.github/workflows/ci.yml`): ruff + pytest + self-scan on fixtures.
- Research dataset: `research/state-of-mcp-configs.md` (1,210 public configs
  from 1,197 repos, 56.5% with findings). Regenerate with
  `uv run python scripts/ecosystem_scan.py --per-query 400 --online`
  (raw per-repo data is gitignored under `research/data/` — do not publish it).
- Blog post: `blog/2026-09-13-state-of-mcp-configs.md`.
- Open PRs: `Puliczek/awesome-mcp-security#325`,
  `AIM-Intelligence/awesome-mcp-security#54`.
- Do not publish announcements or promotional content to external channels
  (Hacker News, Reddit, social media, mailing lists) without explicit user
  approval — keep changes to the repo, its docs and directory listings.

## Layout

- `src/mcplint/` — `models.py`, `discovery.py` (recursive config/skill
  discovery), `parse.py` (JSON/JSONC/TOML), `packages.py` (npm/PyPI refs),
  `checks.py` (check registry via `@check("name")`), `lockfile.py`,
  `aibom.py`, `gate.py` (runtime probe engine) + `gate_data/*.yaml`
  (per-gateway probe profiles), `report/{pretty,sarif}.py`, `rules/`
  (loader + model), `rules_data/*.yaml` (one file per rule).
- Rules are **data (YAML)** + small tested functions in `checks.py`. A rule
  declares `id`, `severity`, `owasp`, `check`, `targets`, `params`.
- Gate probes are **data (YAML)**: one or two probes per failure class; probes
  derived from a disclosure cite it (`id`, `severity`, `cve`, `steps`,
  `remediation`).
  `steps[].expect: deny` marks a negative control that must be rejected first;
  `require: tools` means a 2xx only counts when it carries a tools inventory.
  Probes must stay read-only and must never call tools.
- `gate_data/auth-expectations.example.yaml` documents authenticated checks;
  a literal key must never be accepted from a file (env var only).
- `fixtures/vulnerable-repo/` + `fixtures/clean-repo/` — every rule needs
  fixture coverage; the clean repo must stay at zero findings.

## Conventions

- Findings must carry a precise remediation message.
- Severities: `critical > high > medium > low > info`; `--fail-on` default
  `high`. When in doubt about a pattern, rank severity down, not up.
- Version is single-sourced from `src/mcplint/__init__.py`.
- Verify before claiming done:
  `uv sync --all-groups && uv run ruff check . && uv run pytest`

## Next steps

- P1 features: `--connect` sandboxed introspection, optional LLM deep pass
  (BYOK) for tool-description poisoning.
- `gate`: add a second profile (agentgateway / mcptrust) when a real target
  exists to test against; add `--sarif` only if a CI use case shows up.
- `gate --auth`: consider a `--expect-end-user` attribution check once a
  gateway exposes a read-only way to verify identity propagation.
- Grow the rule catalog; keep false-positive rate low — dogfood with
  `uv run mcplint scan --home` and on real repos before shipping rules.
- Watch the two awesome-list PRs; refresh the dataset after a few months.

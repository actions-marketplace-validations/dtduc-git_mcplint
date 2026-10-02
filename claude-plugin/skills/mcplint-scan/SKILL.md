---
name: mcplint-scan
description: Audit MCP client configurations (.mcp.json, Cursor/Windsurf/VS Code mcp.json and similar, plus user-level client configs) for OWASP MCP Top 10 risks with mcplint — offline, static, and it never executes MCP servers. Use when asked to scan, audit, or review an MCP setup; check MCP config security or supply-chain risk; detect drift between MCP server definitions and the lockfile; or produce an AIBOM of MCP servers in a project.
---

# mcplint — MCP config security

Invoke mcplint through the pinned distribution (never an unpinned one):

```bash
uvx --from mcplint-sec==0.6.0 mcplint <command>
```

If `uvx` is unavailable (for example in a hosted sandbox), fall back to
`pip install mcplint-sec==0.6.0` and run `mcplint` directly. If neither works,
tell the user this skill needs a machine where the CLI can run.

mcplint reads configuration files only. It never executes or contacts MCP
servers. The scan itself sends nothing; `uvx` fetches the pinned package from
PyPI on the first run. Online checks (OSV lookups) are off by default — but a
repository `.mcplint.yaml` with `online: true` turns them on. Before scanning,
look for `.mcplint.yaml`; if it enables `online`, tell the user (it sends MCP
package names and versions to `https://api.osv.dev`) and get confirmation
before running.

## Scan

```bash
uvx --from mcplint-sec==0.6.0 mcplint scan           # current directory
uvx --from mcplint-sec==0.6.0 mcplint scan --home    # + user-level configs and installed Claude Code plugins
uvx --from mcplint-sec==0.6.0 mcplint scan --json    # machine-readable output
```

`--home` also reads the user-level config files of the MCP clients on the
machine, plus the MCP configs and skills of installed Claude Code plugins
(`~/.claude/plugins/`). Those files can contain tokens for other services;
mcplint reads only their MCP server definitions (and flags hardcoded secrets),
never uses those credentials, and never sends file contents anywhere. Run
`--home` only when the user asks for the machine-wide scan.

Exit codes: 0 clean, 1 findings at or above the failure threshold (default
`high`), 2 usage error. Report findings grouped by rule id (MCP001, MCP002, …)
with file and line. For fix guidance use `scan --json` (each finding carries a
`remediation` field) or `rules explain <ID>` — the default pretty output has
no fix text. Summarize the result; paste the full report only when asked.

## Drift detection

```bash
uvx --from mcplint-sec==0.6.0 mcplint lock           # write or refresh the lockfile
uvx --from mcplint-sec==0.6.0 mcplint lock --check   # fail on drift (CI)
```

`lock --check` exits 0 (no drift), 1 (drift), 2 (no MCP configs found, or no
lockfile yet — run `lock` first). Use it before suggesting a commit when the
user changed MCP server definitions; a changed fingerprint (`command`, `args`,
package, url, headers, env) is the signal.

## Inventory (AIBOM)

```bash
uvx --from mcplint-sec==0.6.0 mcplint inventory -o aibom.json
```

## Explain rules

```bash
uvx --from mcplint-sec==0.6.0 mcplint rules list
uvx --from mcplint-sec==0.6.0 mcplint rules explain MCP001
```

## Boundaries

- Never run `mcplint gate` against a remote host on your own initiative.
  `gate` sends network probes (loopback by default); run it only when the
  user explicitly asks, and only against localhost or a host they named.
- Report findings before changing any config file; get confirmation first.
- Do not add `--online` unless the user asks for CVE lookups and accepts the
  network calls.

## Examples

- "Scan this repo's MCP configs for security issues."
- "Did any MCP server definition change since the lockfile was written?"
- "Give me an inventory (AIBOM) of the MCP servers this project uses."

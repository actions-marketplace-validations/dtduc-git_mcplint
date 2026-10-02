# mcplint plugin for Claude Code

Audit the MCP configuration in a project or on your machine — including the
MCP servers and skills of installed Claude Code plugins — without sending
anything off the machine. This plugin bundles one skill that teaches Claude
Code how to run [mcplint](https://github.com/dtduc-git/mcplint), the
local-first security scanner for MCP client configs: OWASP MCP Top 10 rules, a
lockfile for drift detection, and a CycloneDX AIBOM export.

## What this plugin contains

- `skills/mcplint-scan/` — instructions for scanning MCP configs, checking
  lockfile drift, exporting an inventory, and explaining individual rules.

## What it runs and connects to

- The plugin itself runs no code. The skill only tells Claude to invoke
  `uvx --from mcplint-sec==0.6.0 mcplint …` on your machine. The `uv` tool
  downloads that pinned package from PyPI the first time it runs.
- mcplint only reads configuration files, locally, to extract MCP server
  definitions and to flag secrets hardcoded in them. It never executes or
  contacts MCP servers, never uses credentials to authenticate anywhere, and
  never transmits file contents.
- Online checks (OSV CVE lookups) are off by default, but a repository-level
  `.mcplint.yaml` with `online: true` enables them; the skill asks before
  running in that case. When enabled, OSV lookups send MCP package names and
  versions to `https://api.osv.dev` — nothing else.
- No telemetry, no accounts, no hosted service.

## Requirements

- `uv` available on `PATH` (https://docs.astral.sh/uv/). Without it, install
  mcplint with `pip install mcplint-sec==0.6.0` and replace `uvx --from
  mcplint-sec==0.6.0 mcplint` with `mcplint`.

## License

Apache-2.0.

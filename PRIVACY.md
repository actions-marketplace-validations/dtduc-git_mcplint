# Privacy

mcplint is a local-first scanner. It does not collect, store, or transmit any
user data.

- **The plugin itself** runs no code and makes no network requests. It contains
  a skill that instructs Claude to run the pinned `mcplint` CLI on your machine.
- **Installing the tool** downloads the pinned package (`mcplint-sec==0.6.0`)
  from PyPI the first time, through `uvx` or `pip`.
- **mcplint scans local configuration files** to find MCP server definitions
  and to flag secrets hardcoded in them. File contents never leave the machine,
  and secret values are never printed — findings name the pattern and key, not
  the value.
- **Online checks are off by default.** If you opt in (`--online`, or
  `online: true` in `.mcplint.yaml`), mcplint sends the package name,
  ecosystem, and version of the servers it finds (only pinned package
  references carry a version) to the OSV API (`https://api.osv.dev`) for CVE
  lookups. No file contents, paths, or secrets are sent.
- **`mcplint gate`** (never run by the skill unless you ask) sends read-only
  probe requests, to localhost only unless you explicitly name another host.
- **Scan output stays in your Claude session** (server names, file paths, rule
  ids) so Claude can summarize findings for you.
- **No telemetry, no accounts, no hosted service.**

Questions: open an issue at https://github.com/dtduc-git/mcplint/issues.

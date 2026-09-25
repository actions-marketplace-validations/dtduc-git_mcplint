# The first MCP flaw on CISA's exploited list was an auth bypass. Check yours in one command.

_2026-09-21 · runtime gate_

On **2026-09-02**, CISA added **CVE-2026-59822** to its Known Exploited
Vulnerabilities catalog — the first MCP-related entry on that list. It is an
improper-authentication bug in LiteLLM's MCP endpoint: when virtual-key
validation failed, the code fell back to an empty identity instead of rejecting
the request, so a fabricated `Authorization: Bearer a` header opened a fully
authenticated MCP session. From there, public reporting has it chained to
command injection against MCP test endpoints and cryptominers staged in
directories shaped like ordinary tooling config.

This is not one vendor's typo. It is the same category error appearing across
the ecosystem in 2026:

| Disclosure | What was confused |
| --- | --- |
| [CVE-2026-59822](https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q) (LiteLLM, KEV) | failed key validation → empty identity = authenticated |
| [CVE-2026-19516](https://grafana.com/security/security-advisories/cve-2026-19516/) (mcp-grafana, CVSS 9.1) | `Mcp-Session-Id` *format* check treated as caller identity, then SSRF to cloud metadata |
| [CVE-2026-52869](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58) (MCP Python SDK) | HTTP transports routed requests to a session without checking the principal |

A **session id is a state handle, not a credential**. When a server routes on
the id alone, whoever presents it gets whatever identity that session carries —
often the server's own upstream service account. The Grafana chain is the
clean demonstration: the caller authenticated nothing, yet the request that
reached Grafana carried the server's privileged token and was audit-logged as
such.

The exposure is not theoretical. [Wiz
Research](https://www.wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
scanned 3,074 publicly reachable LiteLLM instances and found **9.6% accepted
the default master key `sk-1234` or required no authentication at all**.
[Censys](https://censys.com/blog/mcp-servers-on-the-internet/) counted
**12,500+ internet-facing MCP services** in April 2026.

## What we added

`mcplint gate` has been checking running gateways with a read-only probe
battery since v0.2.0. It now covers the session-confusion class too:

```
GATE008  high  CVE-2026-52869  MCP /mcp served tools on a never-issued Mcp-Session-Id
```

GATE008 sends the same `tools/list` twice: first with no session header as a
negative control, then with a syntactically valid session id the server never
issued — no `initialize`, no credential. It only fires when the control request
is denied *and* the forged-session request comes back with a real tool
inventory: a hardened server rejects the control with 401/403 and then refuses
the forged session too — a clean denial if it answers 401/403, an inconclusive
note (never a finding) if it answers 404 or a JSON-RPC error — while a confused
server denies the control but hands the tools to the forged session. A 2xx
carrying only a JSON-RPC error or an empty tool list is not proof, and an
endpoint that serves the control
request too is a different finding (anonymous access), so GATE008 stays quiet
and says why.

```bash
uvx mcplint-sec gate                            # http://localhost:4000
uvx mcplint-sec gate https://gateway.internal   # + --allow-host
uvx mcplint-sec gate --json --fail-on high      # CI-friendly
```

Eight probes now across six failure classes: failed key validation (GATE001
and GATE002 — same CVE-2026-59822 class, two entry points), anonymous callers,
anonymous legacy SSE, unauthenticated admin/test endpoints, Host-header
authentication, and session-id confusion. Five of the eight cite a CVE or
advisory; the other three are baseline hygiene checks. Every probe is
read-only, loopback-only unless you pass `--allow-host`, and defined in
[`src/mcplint/gate_data/`](../src/mcplint/gate_data) — editable YAML if your
gateway has quirks.

Run it after every gateway upgrade. In this class, patching is only half the
fix: mcp-grafana's authentication remained **opt-in** after v1.1.0, so an
upgraded-but-unconfigured deployment stays exposed.

## What it does not prove

The battery checks authentication only. It cannot tell you whether *this key*
has the right authorization on *that* upstream object — for shared gateways
with per-user permissions, `mcplint gate --auth expectations.yaml` does that
with a dedicated test key, still read-only.

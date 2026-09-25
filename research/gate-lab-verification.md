# Gate lab verification — real LiteLLM versions

Date: 2026-09-18 · profile: `litellm` · tool: `mcplint gate` v0.2.0

Two real LiteLLM proxies were run locally and probed with the full battery.
This is a behavioral comparison, not a vulnerability report: it documents what
`mcplint gate` observed on a patched release and on a pre-fix release.

## Setup

- LiteLLM started with
  `uvx --from 'litellm[proxy]==<version>' --with prisma litellm --config config.yaml --port <port>`
- `config.yaml`: one dummy model, `LITELLM_MASTER_KEY` set, one MCP server entry
  (`auth_type: oauth_delegate` on 1.100; `auth_type: oauth2` on 1.83 — the older
  enum does not accept `oauth_delegate`).
- Host: macOS, loopback only. No database (see limitations).

## Results

| Probe | 1.100.0 (patched) | 1.83.14 (pre-fix) |
| --- | --- | --- |
| GATE001 fabricated `Authorization` bearer | 401 (denied) | 500 * |
| GATE002 invalid `x-litellm-api-key` | 401 (denied) | 500 * |
| GATE003 anonymous MCP request | 401 (denied) | 500 * |
| GATE004 legacy `/sse` route | 404 (route absent) | 404 (route absent) |
| GATE005 `/mcp-rest/test/connection` | 401 (denied) | 401 (denied) |
| GATE006 `/v1/mcp/server` | 401 (denied) | 401 (denied) |
| GATE007 spoofed `Host` on management route | 401 (denied) | 401 (denied) |

`*` In 1.83.14 the unauthenticated request reaches the MCP streamable handler
and raises an unhandled `ProxyException` ("Malformed API Key passed in…") —
`server.py → handle_streamable_http_mcp → extract_mcp_auth_context` — returning
HTTP 500 instead of a clean denial. The patched 1.100.0 rejects the same
requests with `{"error": "authentication_required"}` (401). `mcplint gate`
reports these 5xx responses as **low** findings ("errored instead of denying"),
never as a bypass.

## What this verifies

- Probe plumbing against real software: endpoints, header conventions, the MCP
  `initialize` handshake, and the method-preserving `307 /mcp → /mcp/` redirect
  that urllib does not follow on its own.
- A patched gateway produces a clean "no findings" report, and an older release
  with broken MCP auth handling is visibly different.

## Limitations

- The lab has no database, so virtual-key validation paths that require the DB
  could not be exercised: without it they return `{"detail": "No connected
  db."}` (HTTP 400), which `mcplint gate` reports as inconclusive, never as a
  denial. The full 200-response bypass of CVE-2026-59822 needs a Postgres-backed
  deployment with an OAuth2-passthrough upstream MCP server; that reproduction
  is out of scope here.
- Loopback only. `mcplint gate` never probes third-party hosts by default.

## Reproduce

```bash
uvx --from 'litellm[proxy]==1.100.0' --with prisma litellm \
  --config config.yaml --port 4010 &
uv run mcplint gate http://127.0.0.1:4010
```

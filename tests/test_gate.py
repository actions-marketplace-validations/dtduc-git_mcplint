"""Tests for the runtime gate probes (`mcplint gate`)."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from typer.testing import CliRunner

from mcplint.cli import app
from mcplint.gate import (
    GateError,
    _render,
    load_auth_expectations,
    load_env_file,
    load_profile,
    run_auth_gate,
    run_gate,
)

runner = CliRunner()
KEY = "sk-valid-test-key"
TOOLS = ["confluence.search", "confluence.get_page"]
SEEN: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    mode = "patched"

    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, code: int, payload: dict | None = None) -> None:
        body = json.dumps(payload or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 200 and self.path == "/mcp":
            self.send_header("Mcp-Session-Id", "test-session-1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _authed(self) -> bool:
        for name in ("Authorization", "x-litellm-api-key"):
            value = (self.headers.get(name) or "").removeprefix("Bearer ")
            if value == KEY:
                return True
        return False

    def _record(self) -> None:
        if self.path == "/mcp":
            SEEN.append({"session": self.headers.get("Mcp-Session-Id")})

    def do_GET(self):  # noqa: N802
        if self.mode == "missing":
            self._send(404)
        elif self.path == "/sse":
            self._send(200 if self.mode == "vulnerable" else 401)
        elif self.path == "/v1/mcp/server":
            self._send(200 if (self.mode == "vulnerable" or self._authed()) else 401)
        else:
            self._send(404)

    def do_POST(self):  # noqa: N802
        self._record()
        if self.mode == "missing":
            self._send(404)
        elif self.path == "/mcp" and self.mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "/mcp/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path in ("/mcp", "/mcp/"):
            if self.mode == "erroring":
                self._send(500, {"detail": "Internal Server Error"})
                return
            if self.mode == "session_500" and self.headers.get("Mcp-Session-Id"):
                self._send(500, {"detail": "Internal Server Error"})
                return
            if self.mode in ("session_confused", "session_checked", "session_empty"):
                session = self.headers.get("Mcp-Session-Id")
                if not session:
                    self._send(401)
                    return
                if self.mode == "session_checked" and session != "test-session-1":
                    self._send(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": {"code": -32001, "message": "Session not found"},
                        },
                    )
                    return
                tools = [] if self.mode == "session_empty" else [
                    {"name": name} for name in TOOLS
                ]
                self._send(200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}})
                return
            if not (self.mode in ("vulnerable", "redirect") or self._authed()):
                self._send(401)
                return
            ua = self.headers.get("User-Agent", "")
            if self.mode == "big_tools":
                tools = [
                    {
                        "name": f"confluence.tool_{i:03d}",
                        "description": "A" * 120,
                        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
                    }
                    for i in range(150)
                ]
                self._send(200, {"jsonrpc": "2.0", "result": {"tools": tools}})
                return
            if self.mode == "empty_tools":
                self._send(200, {"jsonrpc": "2.0", "result": {"tools": []}})
                return
            if self.mode == "cf_block":
                self._send(
                    403,
                    {
                        "type": "https://developers.cloudflare.com/error-1010",
                        "title": "Error 1010: Access denied",
                    },
                )
                return
            if self.mode == "requires_mcplint_ua":
                if not ua.startswith("mcplint-gate"):
                    self._send(
                        403,
                        {
                            "title": "Error 1010: Access denied",
                            "detail": f"blocked user agent {ua!r}",
                        },
                    )
                    return
            if self.mode == "deny_no_slash" and self.path == "/mcp":
                self._send(
                    403,
                    {"error": {"message": "Virtual key is not allowed to call this route"}},
                )
                return
            if self.mode == "needs_upstream" and not self.headers.get(
                "x-mcp-lab-authorization"
            ):
                self._send(401)
                return
            method = self._body().get("method", "")
            if self.mode == "forbidden":
                self._send(
                    403,
                    {"error": {"message": "Key not allowed to access MCP server 'confluence'"}},
                )
            elif method == "tools/list":
                if self.headers.get("x-mcp-servers") and self.mode != "leaky_scope":
                    self._send(401)
                    return
                tools = [{"name": name} for name in TOOLS]
                if self.mode == "overexposed":
                    tools.append({"name": "confluence.delete_page"})
                self._send(200, {"jsonrpc": "2.0", "result": {"tools": tools}})
            elif method == "tools/call":
                if self.mode == "read_error":
                    self._send(500, {"detail": "Internal Server Error"})
                elif self.mode == "leaky_read":
                    self._send(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "result": {
                                "content": [{"type": "text", "text": "redacted-secret"}]
                            },
                        },
                    )
                else:
                    self._send(
                        200, {"jsonrpc": "2.0", "result": {"isError": True, "content": []}}
                    )
            else:
                self._send(200, {})
        elif self.path == "/mcp-rest/test/connection":
            self._send(401)  # admin-only in every version we support
        else:
            self._send(404)


@contextmanager
def gateway(mode: str):
    handler = type("Handler", (_Handler,), {"mode": mode})
    SEEN.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_profile_loads_with_probes() -> None:
    profile = load_profile("litellm")
    assert len(profile.probes) >= 8
    assert all(p.remediation for p in profile.probes)
    assert {p.id for p in profile.probes} >= {"GATE001", "GATE005"}


def test_render_replaces_random_token() -> None:
    assert _render("Bearer ${random}", "abc123") == "Bearer abc123"


def test_profile_rejects_unknown_probe_keys(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "id: bad\nprobes:\n"
        "  - id: X\n    title: t\n    severity: low\n    require: tool\n"
        "    steps:\n      - {method: GET, path: /}\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="unknown require"):
        load_profile("bad", extra_dirs=[tmp_path])
    path.write_text(
        "id: bad\nprobes:\n"
        "  - id: X\n    title: t\n    severity: low\n"
        "    steps:\n      - {method: GET, path: /, expect: Deny}\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="unknown step expect"):
        load_profile("bad", extra_dirs=[tmp_path])


def test_profile_errors_are_gate_errors_not_tracebacks(tmp_path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("id: [unclosed\n", encoding="utf-8")
    with pytest.raises(GateError, match="cannot read"):
        load_profile("broken", extra_dirs=[tmp_path])
    path.write_text(
        "id: broken\nprobes:\n  - id: X\n    title: t\n    severity: nope\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="invalid profile"):
        load_profile("broken", extra_dirs=[tmp_path])


def test_patched_gateway_has_no_findings() -> None:
    profile = load_profile("litellm")
    with gateway("patched") as target:
        result = run_gate(profile, target)
    assert result.findings == []
    assert result.probes_run == len(profile.probes)


def test_vulnerable_gateway_flags_auth_bypass() -> None:
    profile = load_profile("litellm")
    with gateway("vulnerable") as target:
        result = run_gate(profile, target)
    flagged = {f.probe_id for f in result.findings}
    assert {"GATE001", "GATE002", "GATE003", "GATE004", "GATE006", "GATE007"} <= flagged
    # GATE008 must not pile on: on an anonymous gateway its negative control is
    # served too, so the session-id cause cannot be isolated (GATE003 owns it).
    assert "GATE008" not in flagged
    assert any(
        note.probe_id == "GATE008" and "answers this request anonymously" in note.reason
        for note in result.notes
    )
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert gate001.severity.value == "critical"
    assert gate001.cve == "CVE-2026-59822"
    assert gate001.remediation
    assert "POST /mcp -> 200" in gate001.evidence


def test_fabricated_session_id_is_flagged() -> None:
    """A never-issued session id must not buy a tools/list on a hardened server."""
    profile = load_profile("litellm")
    with gateway("session_confused") as target:
        result = run_gate(profile, target)
    gate008 = next(f for f in result.findings if f.probe_id == "GATE008")
    assert gate008.severity.value == "high"
    assert gate008.cve == "CVE-2026-52869"
    assert gate008.owasp.startswith("MCP07")
    # The negative control (no session header) was denied, then the fabricated
    # session id was served — both steps are in the evidence.
    assert "POST /mcp -> 401" in gate008.evidence
    assert "POST /mcp -> 200" in gate008.evidence
    # Evidence counts the inventory; tool names stay out of the default output.
    assert "2 tool(s) served" in gate008.evidence
    assert not any(name in gate008.evidence for name in TOOLS)
    assert any((entry["session"] or "").startswith("mcp-session-") for entry in SEEN)


def test_5xx_on_require_probe_is_not_a_served_tools_claim() -> None:
    """A 5xx on the bypassed request must not produce a 'served tools' finding."""
    profile = load_profile("litellm")
    with gateway("session_500") as target:
        result = run_gate(profile, target)
    assert all(f.probe_id != "GATE008" for f in result.findings)
    assert any(
        note.probe_id == "GATE008" and "errored instead of denying" in note.reason
        for note in result.notes
    )


def test_session_error_body_is_not_flagged() -> None:
    """200 alone is not proof: a JSON-RPC error must not be read as served tools."""
    profile = load_profile("litellm")
    with gateway("session_checked") as target:
        result = run_gate(profile, target)
    assert all(f.probe_id != "GATE008" for f in result.findings)
    assert any(
        note.probe_id == "GATE008" and "no tools inventory" in note.reason
        for note in result.notes
    )


def test_empty_inventory_is_not_flagged() -> None:
    """A 200 with an empty tool list must not claim tools were served."""
    profile = load_profile("litellm")
    with gateway("session_empty") as target:
        result = run_gate(profile, target)
    assert all(f.probe_id != "GATE008" for f in result.findings)
    assert any(
        note.probe_id == "GATE008" and "no tools inventory" in note.reason
        for note in result.notes
    )


def test_control_rejection_is_inconclusive_not_anonymous() -> None:
    """A 404/5xx control must not be reported as 'the endpoint answers anonymously'."""
    profile = load_profile("litellm")
    with gateway("missing") as target:
        result = run_gate(profile, target)
    note = next(n for n in result.notes if n.probe_id == "GATE008")
    assert "not denied (HTTP 404)" in note.reason
    assert "anonymously" not in note.reason


def test_mcp_session_id_is_carried_between_steps() -> None:
    profile = load_profile("litellm")
    with gateway("vulnerable") as target:
        run_gate(profile, target)
    sessions = [entry["session"] for entry in SEEN]
    assert "test-session-1" in sessions


def test_method_preserving_redirect_is_followed() -> None:
    profile = load_profile("litellm")
    with gateway("redirect") as target:
        result = run_gate(profile, target)
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert "-> 200" in gate001.evidence
    assert all(note.status != 307 for note in result.notes)


def test_server_error_instead_of_denial_is_a_low_finding() -> None:
    profile = load_profile("litellm")
    with gateway("erroring") as target:
        result = run_gate(profile, target)
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert gate001.severity.value == "low"
    assert "errored instead of denying" in gate001.title
    assert "500" in gate001.evidence
    # GATE008's control also 500s: a note, never a "served tools" claim.
    assert all(f.probe_id != "GATE008" for f in result.findings)
    assert any(
        note.probe_id == "GATE008" and "not denied (HTTP 500)" in note.reason
        for note in result.notes
    )


def test_missing_routes_are_inconclusive_not_findings() -> None:
    profile = load_profile("litellm")
    with gateway("missing") as target:
        result = run_gate(profile, target)
    assert result.findings == []
    assert len(result.notes) == result.probes_run


def test_refuses_non_loopback_without_allow_host() -> None:
    profile = load_profile("litellm")
    with pytest.raises(GateError, match="allow-host"):
        run_gate(profile, "http://gateway.example.com")


def test_cli_vulnerable_exits_one_and_prints_findings() -> None:
    with gateway("vulnerable") as target:
        result = runner.invoke(app, ["gate", target, "--fail-on", "high"])
    assert result.exit_code == 1, result.output
    assert "GATE001" in result.output
    assert "Fix:" in result.output
    assert "GHSA-7488-6r32-c95q" in result.output  # advisory citation is visible


def test_cli_patched_exits_zero() -> None:
    with gateway("patched") as target:
        result = runner.invoke(app, ["gate", target, "--fail-on", "low"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output


def test_cli_all_inconclusive_does_not_claim_enforcement() -> None:
    with gateway("missing") as target:
        result = runner.invoke(app, ["gate", target, "--fail-on", "low"])
    assert result.exit_code == 0, result.output
    assert "No findings, but 8 of 8 probe(s) to read" in result.output
    assert "authentication was enforced" not in result.output


def test_cli_json_output_is_machine_readable() -> None:
    with gateway("vulnerable") as target:
        result = runner.invoke(app, ["gate", target, "--json", "--fail-on", "none"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["tool"] == "mcplint gate"
    assert payload["summary"]["total"] > 0
    assert payload["findings"][0]["probeId"].startswith("GATE")
    gate001 = next(f for f in payload["findings"] if f["probeId"] == "GATE001")
    assert gate001["docs"].startswith("https://")


def test_cli_refuses_remote_target_with_exit_code_two() -> None:
    result = runner.invoke(app, ["gate", "http://gateway.example.com"])
    assert result.exit_code == 2
    assert "allow-host" in result.output


# --- authenticated checks (mcplint gate --auth) ---


def _write_expectations(tmp_path, **overrides):
    data = {
        "target": "http://127.0.0.1:1",
        "key": "env/MCPLINT_TEST_KEY",
        "expect_tools": ["confluence.search", "confluence.get_page"],
        "forbidden_tools": ["*delete*"],
        "forbidden_servers": ["github"],
    }
    data.update(overrides)
    path = tmp_path / "auth.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_auth_mode_clean_key(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("auth") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == [], [f.to_dict() for f in result.findings]
    assert result.inventory == TOOLS


def test_auth_mode_flags_forbidden_and_extra_tools(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("overexposed") as target:
        result = run_auth_gate(expectations, target)
    flagged = {f.probe_id: f for f in result.findings}
    assert "AUTH001" in flagged and flagged["AUTH001"].severity.value == "high"
    assert "AUTH002" in flagged and flagged["AUTH002"].severity.value == "medium"


def test_auth_mode_flags_scope_leak(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("leaky_scope") as target:
        result = run_auth_gate(expectations, target)
    flagged = {f.probe_id for f in result.findings}
    assert "AUTH003" in flagged


def test_auth_mode_read_probe_leak_is_redacted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={
                "tool": "confluence.get_page",
                "args": {"page_id": "00000000"},
                "expect": "deny",
            },
        )
    )
    with gateway("leaky_read") as target:
        result = run_auth_gate(expectations, target)
    auth004 = next(f for f in result.findings if f.probe_id == "AUTH004")
    assert auth004.severity.value == "critical"
    assert "redacted-secret" not in auth004.evidence


def test_auth_mode_read_probe_5xx_is_a_note_not_a_verdict(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    for expect in ("deny", "allow"):
        expectations = load_auth_expectations(
            _write_expectations(
                tmp_path,
                read_probe={
                    "tool": "confluence.get_page",
                    "args": {},
                    "expect": expect,
                },
            )
        )
        with gateway("read_error") as target:
            result = run_auth_gate(expectations, target)
        assert all(f.probe_id not in ("AUTH004", "AUTH006") for f in result.findings)
        assert any(
            "errored instead of answering" in note.reason for note in result.notes
        )


def test_auth_mode_read_probe_denied_is_clean(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={"tool": "confluence.get_page", "args": {}, "expect": "deny"},
        )
    )
    with gateway("auth") as target:
        result = run_auth_gate(expectations, target)
    assert all(f.probe_id != "AUTH004" for f in result.findings)


def test_auth_mode_requires_key_in_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("MCPLINT_TEST_KEY", raising=False)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("auth") as target, pytest.raises(GateError, match="MCPLINT_TEST_KEY"):
        run_auth_gate(expectations, target)


def test_auth_expectations_reject_literal_key(tmp_path) -> None:
    path = _write_expectations(tmp_path, key="sk-literal-key")
    with pytest.raises(GateError, match="env/"):
        load_auth_expectations(path)


def test_auth_expectations_reject_unknown_read_probe_expect(tmp_path) -> None:
    path = _write_expectations(
        tmp_path, read_probe={"tool": "confluence.get_page", "expect": "Allow"}
    )
    with pytest.raises(GateError, match="read_probe.expect"):
        load_auth_expectations(path)


def test_auth_expectations_reject_read_probe_without_tool(tmp_path) -> None:
    for broken in ({"args": {"page_id": "1"}}, "confluence.get_page", {}):
        path = _write_expectations(tmp_path, read_probe=broken)
        with pytest.raises(GateError, match="read_probe needs a mapping"):
            load_auth_expectations(path)


def test_auth_cli_text_mode_reports_notes(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = _write_expectations(tmp_path, expect_tools=[])
    with gateway("empty_tools") as target:
        result = runner.invoke(app, ["gate", target, "--auth", str(expectations)])
    assert result.exit_code == 0, result.output
    assert "No findings, but 1 note(s) to read" in result.output
    assert KEY not in result.output


def test_auth_cli_clean_and_key_never_printed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    path = _write_expectations(tmp_path)
    with gateway("auth") as target:
        result = runner.invoke(app, ["gate", target, "--auth", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output or '"total": 0' in result.output
    assert KEY not in result.output
    assert "confluence.search" in result.output


def test_auth_403_includes_gateway_reason(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("forbidden") as target, pytest.raises(GateError) as excinfo:
        run_auth_gate(expectations, target)
    message = str(excinfo.value)
    assert "403" in message
    assert "not allowed to access MCP server" in message
    assert KEY not in message


def test_auth_mode_falls_back_to_canonical_mcp_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("deny_no_slash") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == []
    assert result.inventory == TOOLS
    assert any("canonical" in note.reason for note in result.notes)


def test_auth_mode_sends_upstream_headers_from_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    monkeypatch.setenv("LAB_UPSTREAM_TOKEN", "atlassian-user-token")
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            upstream_headers={"x-mcp-lab-authorization": "env/LAB_UPSTREAM_TOKEN"},
        )
    )
    with gateway("needs_upstream") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == []


def test_auth_mode_upstream_header_env_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    monkeypatch.delenv("LAB_UPSTREAM_TOKEN", raising=False)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            upstream_headers={"x-mcp-lab-authorization": "env/LAB_UPSTREAM_TOKEN"},
        )
    )
    with gateway("needs_upstream") as target, pytest.raises(
        GateError, match="LAB_UPSTREAM_TOKEN"
    ):
        run_auth_gate(expectations, target)


def test_auth_expectations_reject_literal_upstream_header(tmp_path) -> None:
    with pytest.raises(GateError, match="env/"):
        load_auth_expectations(
            _write_expectations(
                tmp_path,
                upstream_headers={"x-mcp-lab-authorization": "literal-token"},
            )
        )


def test_env_file_parsing(tmp_path) -> None:
    path = tmp_path / "tokens"
    path.write_text(
        "# comment\n\nexport MCPLINT_TEST_KEY='sk-quoted'\nOTHER=plain  \nEMPTY=\n",
        encoding="utf-8",
    )
    values = load_env_file(path)
    assert values == {"MCPLINT_TEST_KEY": "sk-quoted", "OTHER": "plain", "EMPTY": ""}


def test_env_file_bad_line(tmp_path) -> None:
    path = tmp_path / "tokens"
    path.write_text("NOT_A_PAIR\n", encoding="utf-8")
    with pytest.raises(GateError, match="KEY=VALUE"):
        load_env_file(path)


def test_env_file_supplies_key_and_upstream(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("MCPLINT_TEST_KEY", raising=False)
    monkeypatch.delenv("LAB_UPSTREAM_TOKEN", raising=False)
    env_path = tmp_path / "tokens"
    env_path.write_text(
        f"MCPLINT_TEST_KEY={KEY}\nLAB_UPSTREAM_TOKEN=atlassian-user-token\n",
        encoding="utf-8",
    )
    expectations = _write_expectations(
        tmp_path,
        upstream_headers={"x-mcp-lab-authorization": "env/LAB_UPSTREAM_TOKEN"},
    )
    with gateway("needs_upstream") as target:
        result = runner.invoke(
            app,
            [
                "gate",
                target,
                "--auth",
                str(expectations),
                "--env-file",
                str(env_path),
                "--json",
            ],
        )
    assert result.exit_code == 0, result.output
    assert '"total": 0' in result.output
    assert KEY not in result.output


def test_env_file_missing_is_operational_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = _write_expectations(tmp_path)
    with gateway("auth") as target:
        result = runner.invoke(
            app,
            [
                "gate",
                target,
                "--auth",
                str(expectations),
                "--env-file",
                str(tmp_path / "does-not-exist"),
            ],
        )
    assert result.exit_code == 2
    assert "cannot read env file" in result.output



def test_auth_mode_sends_mcplint_user_agent(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("requires_mcplint_ua") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == []
    assert result.inventory == TOOLS


def test_auth_mode_detects_edge_waf_block(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("cf_block") as target, pytest.raises(GateError) as excinfo:
        run_auth_gate(expectations, target)
    message = str(excinfo.value)
    assert "edge blocked" in message
    assert "Object_permission" not in message
    assert "object_permission" not in message


def test_auth_mode_empty_tool_list_is_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(tmp_path, expect_tools=[])
    )
    with gateway("empty_tools") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == []
    assert result.inventory == []
    assert any(
        note.probe_id == "AUTH000" and "empty tool list" in note.reason
        for note in result.notes
    )


def test_auth_mode_handles_large_tools_response(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(tmp_path, expect_tools=[])
    )
    with gateway("big_tools") as target:
        result = run_auth_gate(expectations, target)
    assert len(result.inventory) == 150
    assert all(note.probe_id != "AUTH000" for note in result.notes)


def test_auth_read_probe_expect_allow_passes_when_data_returned(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={"tool": "confluence.get_page", "args": {}, "expect": "allow"},
        )
    )
    with gateway("leaky_read") as target:
        result = run_auth_gate(expectations, target)
    assert all(f.probe_id != "AUTH004" for f in result.findings)
    assert all(f.probe_id != "AUTH006" for f in result.findings)


def test_auth_read_probe_expect_allow_denied_flags_auth006(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={"tool": "confluence.get_page", "args": {}, "expect": "allow"},
        )
    )
    with gateway("auth") as target:  # tools/call returns isError -> denied
        result = run_auth_gate(expectations, target)
    auth006 = next(f for f in result.findings if f.probe_id == "AUTH006")
    assert auth006.severity.value == "medium"

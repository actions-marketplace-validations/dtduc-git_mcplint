"""Package reference extraction shared by checks, lockfile and AIBOM."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from .models import MCPServer

NPM_RUNNERS = {"npx", "pnpx", "bunx"}
PYPI_RUNNERS = {"uvx", "pipx"}


@dataclass
class PackageSpec:
    """A third-party package referenced by a server command line."""

    kind: str  # "npm" | "pypi"
    raw: str  # token as written, e.g. "@scope/server@1.2.3"
    name: str  # normalized, version-less, lowercase
    version: str | None
    pinned: bool
    auto_approve: bool  # runner asked to skip confirmation (-y/--yes)


def parse_url(value: str) -> urllib.parse.SplitResult | None:
    try:
        return urllib.parse.urlsplit(value)
    except ValueError:
        return None


def endpoint_display(value: str) -> str:
    """Scheme + host only for messages/artifacts. Endpoint paths can carry
    credentials (e.g. `/mcp/sk-…/sse`), and unencoded delimiters in userinfo
    can make `urlsplit` truncate it into the netloc — so rebuild from
    `hostname`/`port` and refuse anything that still looks like credentials."""
    parsed = parse_url(value)
    if parsed is None or not parsed.hostname:
        return "<malformed URL>"
    if "@" in parsed.path or "@" in parsed.query or "@" in parsed.fragment:
        return "<malformed URL>"
    try:
        port = parsed.port
    except ValueError:
        return "<malformed URL>"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = f"{host}:{port}" if port else host
    return f"{parsed.scheme}://{netloc}"


def package_display(spec: PackageSpec) -> str:
    """Safe rendering of a package token: URLs are reduced to their endpoint,
    and anything that is not a registry name (grammar-derived `name` is empty)
    becomes a placeholder."""
    if "://" in spec.raw:
        display = endpoint_display(spec.raw)
        if display == "<malformed URL>" and "@" in spec.raw:
            # Only a commit-SHA ref is safe to strip; anything else after `@`
            # may be a credential fragment, so keep the placeholder.
            head, ref = spec.raw.rsplit("@", 1)
            parsed = parse_url(spec.raw)
            if _GIT_SHA_RE.match(ref):
                display = endpoint_display(head)
            elif parsed is not None and parsed.scheme.startswith("git+"):
                display = "<git URL>"
        return display
    if spec.name:
        return spec.raw
    return "<package spec>"


def version_of(token: str, kind: str) -> str | None:
    if kind == "npm":
        if token.startswith("@"):
            idx = token.rfind("@")
            return token[idx + 1 :] if idx > 0 else None
        idx = token.rfind("@")
        return token[idx + 1 :] if idx >= 0 else None
    for sep in ("==", "@"):
        if sep in token:
            return token.split(sep, 1)[1] or None
    return None


def normalize_package(token: str, kind: str = "npm") -> str:
    """Strip any version suffix so package names compare equal across syntaxes."""
    name = token.strip()
    if "==" in name:
        return name.split("==", 1)[0].lower()
    idx = name.rfind("@")
    if name.startswith("@"):
        if idx > 0:
            name = name[:idx]
    elif idx >= 0:
        name = name[:idx]
    return name.lower()


def _is_flag(token: str) -> bool:
    return token.startswith("-")


# Per-runner flag semantics for package extraction. Known package flags make
# their value the package; known value flags consume the next token; known
# boolean flags do not. An unknown flag stops extraction entirely — a
# positional after it may be an application argument or a flag value, and must
# never be echoed or sent to OSV as if it were a package.
_NPM_PACKAGE_FLAGS = {"-p", "--package"}
_NPM_VALUE_FLAGS = {"-c", "--call", "--registry", "--userconfig", "--cache", "--loglevel"}
_NPM_BOOLEAN_FLAGS = {
    "-y",
    "--yes",
    "-q",
    "--quiet",
    "--silent",
    "--no-color",
    "--no-install",
    "--prefer-offline",
    "--prefer-online",
    "--offline",
    "--ignore-existing",
    "--legacy-peer-deps",
    "--force",
    "-f",
    "--no",
}

_PNPX_PACKAGE_FLAGS = {"--package"}
_PNPX_BOOLEAN_FLAGS = {"-y", "--yes", "-q", "--quiet", "--silent", "--shell-mode", "-c"}

_UV_PACKAGE_FLAGS = {"--from"}
_UV_VALUE_FLAGS = {
    "-p",
    "--python",
    "-w",
    "--with",
    "--with-editable",
    "--with-requirements",
    "-c",
    "--constraints",
    "--overrides",
    "--python-platform",
    "--index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "--index-strategy",
    "-f",
    "--find-links",
    "--cache-dir",
    "--refresh-package",
    "--prerelease",
    "--exclude-newer",
    "--exclude-newer-package",
    "--default-index",
    "--allow-insecure-host",
    "--env-file",
    "--upgrade-package",
    "--reinstall-package",
}
_UV_BOOLEAN_FLAGS = {
    "--refresh",
    "--isolated",
    "--no-cache",
    "--no-config",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "-U",
    "--upgrade",
    "--offline",
    "--native-tls",
    "--no-progress",
    "-n",
    "--reinstall",
}

_PIPX_PACKAGE_FLAGS = {"--spec"}
_PIPX_VALUE_FLAGS = {"--python", "--index-url", "-i", "--pip-args"}
_PIPX_BOOLEAN_FLAGS = {
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "--force",
    "-f",
    "--editable",
    "--pypackages",
    "--no-cache",
}

_FLAG_TABLE: dict[str, tuple[set[str], set[str], set[str]]] = {
    "npx": (_NPM_PACKAGE_FLAGS, _NPM_VALUE_FLAGS, _NPM_BOOLEAN_FLAGS),
    "pnpx": (_PNPX_PACKAGE_FLAGS, set(), _PNPX_BOOLEAN_FLAGS),
    "bunx": (_NPM_PACKAGE_FLAGS, _NPM_VALUE_FLAGS, _NPM_BOOLEAN_FLAGS | {"--bun"}),
    "uvx": (_UV_PACKAGE_FLAGS, _UV_VALUE_FLAGS, _UV_BOOLEAN_FLAGS),
    "pipx": (_PIPX_PACKAGE_FLAGS, _PIPX_VALUE_FLAGS, _PIPX_BOOLEAN_FLAGS),
}


def _combined_short_flags(token: str, boolean_flags: set[str]) -> bool:
    """`-yq` is `-y -q` when every letter is a known boolean short flag."""
    if not token.startswith("-") or token.startswith("--") or len(token) < 3:
        return False
    shorts = {
        flag[1] for flag in boolean_flags if len(flag) == 2 and flag.startswith("-")
    }
    return all(char in shorts for char in token[1:])


def _is_yes(token: str) -> bool:
    return token in ("-y", "--yes")


def _scan_yes(
    tokens: list[str],
    package_flags: set[str],
    value_flags: set[str],
    boolean_flags: set[str],
) -> bool:
    """`-y` in the runner-flag region after a package flag's value; stop at the
    first positional, which is the app command and owns its own `-y`."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _is_yes(token) or (
            token.startswith("-")
            and not token.startswith("--")
            and "y" in token[1:]
            and _combined_short_flags(token, boolean_flags)
        ):
            return True
        if token in package_flags or token in value_flags:
            index += 2
            continue
        if token in boolean_flags or _combined_short_flags(token, boolean_flags):
            index += 1
            continue
        return False
    return False


def _first_package(base: str, args: list[str]) -> tuple[str, bool] | None:
    """Return (package token, auto-approve seen) for the runner's invocation."""
    if base == "pipx":
        if not args or args[0] != "run":
            return None
        args = args[1:]
    package_flags, value_flags, boolean_flags = _FLAG_TABLE[base]
    auto = False
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            nxt = args[index + 1] if index + 1 < len(args) else None
            return (nxt, auto) if nxt and not _is_flag(nxt) else None
        if token.startswith("--") and "=" in token:
            flag, value = token.split("=", 1)
            if flag in package_flags:
                if not value:
                    return None
                trailing = _scan_yes(args[index + 1 :], package_flags, value_flags, boolean_flags)
                return value, auto or trailing
            if flag in value_flags:
                index += 1
                continue
            if flag in boolean_flags:
                auto = auto or flag in ("-y", "--yes")
                index += 1
                continue
            return None
        if token in package_flags:
            nxt = args[index + 1] if index + 1 < len(args) else None
            if not nxt or _is_flag(nxt):
                return None
            trailing = _scan_yes(args[index + 2 :], package_flags, value_flags, boolean_flags)
            return nxt, auto or trailing
        if token in value_flags:
            index += 2
            continue
        if _is_flag(token):
            if token in boolean_flags or _combined_short_flags(token, boolean_flags):
                auto = auto or _is_yes(token) or (
                    "y" in token[1:] and _combined_short_flags(token, boolean_flags)
                )
                index += 1
                continue
            return None
        return token, auto
    return None


_NPM_TOKEN_RE = re.compile(
    r"^((?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+)(?:@([^\s@]+))?$"
)
_PYPI_TOKEN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?"
    r"(?:(?:==|@|>=|<=|~=|!=|>|<)([^\s@]+))?$"
)
_NPM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PYPI_VERSION_RE = re.compile(
    r"^(?:\d+!)?"
    r"\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?"
    r"(?:[.]?post\d+)?(?:[.]?dev\d+)?"
    r"(?:\+[0-9A-Za-z.]+)?$"
)
_GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _git_url_pinned(token: str, kind: str) -> bool:
    """Only a `git+…://` URL pinned to a 40/64-hex commit is reproducible:
    npm pins in the fragment (`…repo.git#<sha>`), uv/pipx in the path ref
    (`…repo@<sha>`). A tag, branch, userinfo or query is never a pin."""
    parsed = parse_url(token)
    if parsed is None or not parsed.scheme.startswith("git+"):
        return False
    if kind == "npm" and parsed.fragment:
        return bool(_GIT_SHA_RE.match(parsed.fragment))
    tail = parsed.path.rsplit("/", 1)[-1]
    if "@" not in tail:
        return False
    return bool(_GIT_SHA_RE.match(tail.rsplit("@", 1)[1]))


def package_specs(server: MCPServer) -> list[PackageSpec]:
    """Extract npm/PyPI package references from a server's command line."""
    if not server.command:
        return []
    base = Path(server.command[0]).name.lower()
    args = server.command[1:]
    specs: list[PackageSpec] = []

    if base in NPM_RUNNERS or base in PYPI_RUNNERS:
        kind = "npm" if base in NPM_RUNNERS else "pypi"
        found = _first_package(base, args)
        if not found:
            return []
        token, auto = found
        # URL packages (`npx https://…/pkg.tgz`) are not registry names: never
        # treat a userinfo `@` as a version pin, and keep them out of name
        # comparisons and CVE lookups. Only a commit-SHA ref counts as pinned.
        if "://" in token:
            name, version, pinned = "", None, _git_url_pinned(token, kind)
        else:
            match = (_NPM_TOKEN_RE if kind == "npm" else _PYPI_TOKEN_RE).match(token)
            if match:
                version = version_of(token, kind)
                version_re = _NPM_VERSION_RE if kind == "npm" else _PYPI_VERSION_RE
                pinned = bool(version) and bool(version_re.match(version))
                name = match.group(1).lower()
            else:
                # Non-registry positional (`github:org/repo`, `./pkg`): still a
                # moving target, but never a registry name to query or purl.
                name, version, pinned = "", None, False
        specs.append(
            PackageSpec(
                kind=kind,
                raw=token,
                name=name,
                version=version if pinned else None,
                pinned=pinned,
                auto_approve=auto,
            )
        )
    return specs

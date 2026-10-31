"""CycloneDX AIBOM export for MCP servers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import __version__
from .lockfile import rel_to
from .models import MCPConfigFile
from .packages import package_display, package_specs


def build_aibom(configs: list[MCPConfigFile], root: Path) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for config in configs:
        for server in config.servers:
            specs = package_specs(server)
            spec = specs[0] if specs else None
            component: dict[str, Any] = {
                "type": "library" if spec else "application",
                "name": server.name,
                "bom-ref": f"mcp-server:{server.name}:{rel_to(config.path, root)}",
                "properties": [
                    {"name": "mcplint:client", "value": config.client},
                    {"name": "mcplint:transport", "value": server.transport},
                    {"name": "mcplint:config", "value": rel_to(config.path, root)},
                ],
            }
            if spec:
                component["properties"].append(
                    {"name": "mcplint:package", "value": package_display(spec)}
                )
                if spec.name:
                    kind = "npm" if spec.kind == "npm" else "pypi"
                    purl = f"pkg:{kind}/{quote(spec.name, safe='/')}"
                    if spec.pinned and spec.version:
                        component["version"] = spec.version
                        purl += f"@{spec.version}"
                    component["purl"] = purl
            components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"vendor": "mcplint", "name": "mcplint", "version": __version__}],
        },
        "components": components,
    }

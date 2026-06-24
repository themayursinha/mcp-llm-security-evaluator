"""
Inventory parsing for MCP server configurations.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional outside normal app runtime
    yaml = None


@dataclass
class MCPServerRecord:
    """A normalized MCP server inventory record."""

    name: str
    source: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    transport: str = "unknown"
    version: Optional[str] = None
    owner: Optional[str] = None
    approved: bool = False
    tools: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "command": self.command,
            "args": self.args,
            "url": self.url,
            "transport": self.transport,
            "version": self.version,
            "owner": self.owner,
            "approved": self.approved,
            "tools": self.tools,
            "resources": self.resources,
            "prompts": self.prompts,
            "findings": self.findings,
        }


class MCPInventoryScanner:
    """Load MCP server declarations from files or evaluator config."""

    def scan_paths(self, paths: Iterable[str]) -> List[MCPServerRecord]:
        records: List[MCPServerRecord] = []
        for raw_path in paths:
            path = Path(raw_path).expanduser()
            if not path.exists() or not path.is_file():
                records.append(
                    MCPServerRecord(
                        name=path.name,
                        source=str(path),
                        findings=[
                            {
                                "severity": "medium",
                                "control": "server_inventory",
                                "message": "Configured MCP inventory path was not found.",
                                "evidence": {"path": str(path)},
                            }
                        ],
                    )
                )
                continue

            loaded = self._load_config_file(path)
            records.extend(self._records_from_mapping(loaded, source=str(path)))
        return records

    def from_config(self, config: Dict[str, Any]) -> List[MCPServerRecord]:
        """Extract inventory records from profile config."""
        records = []
        if config.get("mcp_inventory_paths"):
            records.extend(self.scan_paths(config.get("mcp_inventory_paths", [])))

        server_config = {
            "mcpServers": config.get("mcp_servers", {}),
            "servers": config.get("mcp_server_list", []),
        }
        records.extend(self._records_from_mapping(server_config, source="profile"))
        return records

    def _load_config_file(self, path: Path) -> Dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return json.loads(text)
        if path.suffix.lower() in {".yaml", ".yml"}:
            if yaml is not None:
                return yaml.safe_load(text) or {}
            raise ValueError(f"Cannot parse {path.name}: YAML support is not installed.")
        return json.loads(text)

    def _records_from_mapping(self, mapping: Dict[str, Any], source: str) -> List[MCPServerRecord]:
        records = []

        mcp_servers = mapping.get("mcpServers", {})
        if isinstance(mcp_servers, dict):
            for name, server in mcp_servers.items():
                if isinstance(server, dict):
                    records.append(self._record_from_server(name, server, source))

        servers = mapping.get("servers", [])
        if isinstance(servers, list):
            for index, server in enumerate(servers):
                if isinstance(server, dict):
                    name = server.get("name") or f"server-{index + 1}"
                    records.append(self._record_from_server(name, server, source))

        return records

    def _record_from_server(
        self, name: str, server: Dict[str, Any], source: str
    ) -> MCPServerRecord:
        command = server.get("command")
        args = server.get("args") or []
        url = server.get("url") or server.get("server_url")
        transport = server.get("transport") or self._infer_transport(command, url)
        record = MCPServerRecord(
            name=name,
            source=source,
            command=command,
            args=args,
            url=url,
            transport=transport,
            version=server.get("version"),
            owner=server.get("owner"),
            approved=bool(server.get("approved", False)),
            tools=server.get("tools", []),
            resources=server.get("resources", []),
            prompts=server.get("prompts", []),
        )
        record.findings = self._assess_server(record)
        return record

    def _infer_transport(self, command: Optional[str], url: Optional[str]) -> str:
        if url:
            if url.startswith("http"):
                return "http"
            return "remote"
        if command:
            return "stdio"
        return "unknown"

    def _assess_server(self, record: MCPServerRecord) -> List[Dict[str, Any]]:
        findings = []
        command_line = " ".join([record.command or "", *record.args]).strip()

        if not record.approved:
            findings.append(
                {
                    "severity": "medium",
                    "control": "server_inventory",
                    "message": "MCP server is not marked as approved.",
                    "evidence": {"server": record.name, "source": record.source},
                }
            )

        if record.command and self._has_dangerous_startup(command_line):
            findings.append(
                {
                    "severity": "critical",
                    "control": "local_server_startup",
                    "message": "Local MCP startup command contains dangerous patterns.",
                    "evidence": {"server": record.name, "command": command_line},
                }
            )

        if record.command in {"npx", "uvx"} and not self._looks_version_pinned(record.args):
            findings.append(
                {
                    "severity": "medium",
                    "control": "server_provenance",
                    "message": "Package-based MCP server is not version pinned.",
                    "evidence": {"server": record.name, "command": command_line},
                }
            )

        if record.url and record.url.startswith("http://"):
            findings.append(
                {
                    "severity": "high",
                    "control": "transport_security",
                    "message": "Remote MCP server is configured over plaintext HTTP.",
                    "evidence": {"server": record.name, "url": record.url},
                }
            )

        return findings

    def _has_dangerous_startup(self, command_line: str) -> bool:
        dangerous_patterns = [
            r"\bsudo\b",
            r"\brm\s+-rf\b",
            r"\bcurl\b.*\|.*\bsh\b",
            r"\bwget\b.*\|.*\bsh\b",
            r"\bchmod\s+777\b",
            r"\bssh\b.*id_rsa",
            r"169\.254\.169\.254",
        ]
        return any(re.search(pattern, command_line) for pattern in dangerous_patterns)

    def _looks_version_pinned(self, args: List[str]) -> bool:
        package_args = [arg for arg in args if not arg.startswith("-")]
        return any("@" in arg or "==" in arg for arg in package_args)

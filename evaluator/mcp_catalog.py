"""
Tool catalog snapshotting and diffing for MCP supply-chain review.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List


def canonical_json(value: Any) -> str:
    """Return stable JSON for hashing and comparison."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(value: Any) -> str:
    """Return a deterministic SHA-256 hash for a JSON-compatible value."""
    if isinstance(value, str):
        payload = value
    else:
        payload = canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _tool_identity(tool: Dict[str, Any]) -> str:
    server = tool.get("source_server") or tool.get("server") or "unknown"
    return f"{server}:{tool.get('name', 'unknown')}"


def _normalize_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {
        "identity": _tool_identity(tool),
        "name": tool.get("name", "unknown"),
        "description": tool.get("description", ""),
        "parameters": tool.get("parameters") or tool.get("inputSchema") or {},
        "annotations": tool.get("annotations", {}),
        "output_schema": tool.get("output_schema") or tool.get("outputSchema") or {},
        "source_server": tool.get("source_server") or tool.get("server") or "unknown",
        "security_risk_level": tool.get("security_risk_level", "unknown"),
    }
    normalized["metadata_hash"] = stable_hash(
        {
            "description": normalized["description"],
            "parameters": normalized["parameters"],
            "annotations": normalized["annotations"],
            "output_schema": normalized["output_schema"],
        }
    )
    return normalized


def build_tool_catalog_snapshot(tools: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a stable snapshot for MCP tool metadata."""
    normalized_tools = sorted(
        (_normalize_tool(tool) for tool in tools),
        key=lambda tool: tool["identity"],
    )
    return {
        "schema_version": "1.0",
        "catalog_hash": stable_hash(normalized_tools),
        "tools": normalized_tools,
        "summary": {
            "total_tools": len(normalized_tools),
            "high_risk_tools": sum(
                1 for tool in normalized_tools if tool.get("security_risk_level") == "high"
            ),
            "medium_risk_tools": sum(
                1 for tool in normalized_tools if tool.get("security_risk_level") == "medium"
            ),
        },
    }


def normalize_tool_catalog(catalog: Dict[str, Any] | List[Dict[str, Any]]) -> Dict[str, Any]:
    """Accept either a snapshot or a raw tool list and return a snapshot."""
    if not catalog:
        return build_tool_catalog_snapshot([])
    if isinstance(catalog, list):
        return build_tool_catalog_snapshot(catalog)
    if "tools" in catalog:
        return build_tool_catalog_snapshot(catalog.get("tools", []))
    return build_tool_catalog_snapshot([])


def _tool_map(snapshot: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {tool["identity"]: tool for tool in snapshot.get("tools", [])}


def _changed_fields(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    fields = ["description", "parameters", "annotations", "output_schema"]
    return [field for field in fields if before.get(field) != after.get(field)]


def diff_tool_catalogs(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Diff two MCP tool catalog snapshots."""
    previous_tools = _tool_map(previous)
    current_tools = _tool_map(current)

    added = [
        current_tools[identity] for identity in sorted(set(current_tools) - set(previous_tools))
    ]
    removed = [
        previous_tools[identity] for identity in sorted(set(previous_tools) - set(current_tools))
    ]

    changed = []
    for identity in sorted(set(previous_tools) & set(current_tools)):
        before = previous_tools[identity]
        after = current_tools[identity]
        if before.get("metadata_hash") != after.get("metadata_hash"):
            changed.append(
                {
                    "identity": identity,
                    "name": after.get("name"),
                    "source_server": after.get("source_server"),
                    "fields_changed": _changed_fields(before, after),
                    "before_hash": before.get("metadata_hash"),
                    "after_hash": after.get("metadata_hash"),
                }
            )

    return {
        "previous_hash": previous.get("catalog_hash"),
        "current_hash": current.get("catalog_hash"),
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(set(previous_tools) & set(current_tools)) - len(changed),
        },
    }

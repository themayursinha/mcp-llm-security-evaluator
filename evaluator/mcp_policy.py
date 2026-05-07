"""
Policy checks for MCP tools, servers, and tool-call chains.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PolicyFinding:
    severity: str
    control: str
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "control": self.control,
            "message": self.message,
            "evidence": self.evidence,
        }


class MCPPolicy:
    """Evaluate MCP control-plane policy."""

    def __init__(self, config: Dict[str, Any] | None = None):
        config = config or {}
        self.default_action = config.get("default_action", "allow")
        self.allowed_tools = set(config.get("allowed_tools", []))
        self.denied_tools = set(config.get("denied_tools", []))
        self.require_approval_for_risk = set(config.get("require_approval_for_risk", ["high"]))
        self.require_approval_for_tools = set(config.get("require_approval_for_tools", []))
        self.tool_rules = config.get("tool_rules", {})
        self.block_sensitive_to_outbound = config.get("block_sensitive_to_outbound", True)
        self.block_token_passthrough = config.get("block_token_passthrough", True)
        self.block_unreviewed_prompt_templates = config.get(
            "block_unreviewed_prompt_templates", True
        )

    @classmethod
    def from_config(cls, config: Dict[str, Any] | None) -> "MCPPolicy":
        return cls(config or {})

    def evaluate_tool(self, tool: Dict[str, Any]) -> List[PolicyFinding]:
        """Evaluate one tool's metadata against policy."""
        findings: List[PolicyFinding] = []
        name = tool.get("name", "")
        risk = tool.get("security_risk_level", "unknown")
        annotations = tool.get("annotations", {})

        if name in self.denied_tools:
            findings.append(
                PolicyFinding(
                    severity="critical",
                    control="per_tool_authorization",
                    message="Tool is explicitly denied by policy.",
                    evidence={"tool": name},
                )
            )

        if self.allowed_tools and name not in self.allowed_tools:
            findings.append(
                PolicyFinding(
                    severity="high",
                    control="per_tool_authorization",
                    message="Tool is not present in the configured allowlist.",
                    evidence={"tool": name},
                )
            )

        requires_approval = (
            annotations.get("requires_approval")
            or annotations.get("requiresApproval")
            or annotations.get("human_approval_required")
        )
        if risk in self.require_approval_for_risk and not requires_approval:
            findings.append(
                PolicyFinding(
                    severity="medium",
                    control="human_approval",
                    message="High-risk MCP tool lacks explicit approval metadata.",
                    evidence={"tool": name, "risk": risk},
                )
            )

        if name in self.require_approval_for_tools and not requires_approval:
            findings.append(
                PolicyFinding(
                    severity="high",
                    control="human_approval",
                    message="Policy requires this tool to declare human approval.",
                    evidence={"tool": name},
                )
            )

        for parameter_name in (tool.get("parameters") or {}).keys():
            if parameter_name.lower() in {"callback_url", "webhook", "redirect_uri"}:
                findings.append(
                    PolicyFinding(
                        severity="medium",
                        control="argument_constraints",
                        message="Tool accepts callback or redirect-style arguments.",
                        evidence={"tool": name, "parameter": parameter_name},
                    )
                )

        rule = self.tool_rules.get(name, {})
        if rule.get("allowed") is False:
            findings.append(
                PolicyFinding(
                    severity="critical",
                    control="per_tool_authorization",
                    message="Tool is blocked by its policy rule.",
                    evidence={"tool": name},
                )
            )

        return findings

    def evaluate_tool_chain(self, tool_invocations: List[Dict[str, Any]]) -> List[PolicyFinding]:
        """Evaluate a multi-tool sequence for dangerous chains."""
        findings: List[PolicyFinding] = []
        seen_sensitive_source = None

        for invocation in tool_invocations:
            name = invocation.get("name", "")
            parameters = invocation.get("parameters", {})

            if self._is_sensitive_source(name, parameters):
                seen_sensitive_source = invocation

            if (
                self.block_sensitive_to_outbound
                and seen_sensitive_source
                and self._is_outbound_sink(name, parameters)
            ):
                findings.append(
                    PolicyFinding(
                        severity="critical",
                        control="runtime_chain_inspection",
                        message="Sensitive source flowed into an outbound MCP tool chain.",
                        evidence={
                            "source_tool": seen_sensitive_source.get("name"),
                            "sink_tool": name,
                            "sink_parameters": parameters,
                        },
                    )
                )

            if self.block_token_passthrough and self._contains_token(parameters):
                findings.append(
                    PolicyFinding(
                        severity="critical",
                        control="token_passthrough",
                        message="Tool invocation appears to pass a token or secret as data.",
                        evidence={"tool": name, "parameters": parameters},
                    )
                )

        return findings

    def _is_sensitive_source(self, name: str, parameters: Dict[str, Any]) -> bool:
        name_lower = name.lower()
        if any(
            token in name_lower
            for token in ["database", "credential", "secret", "token", "file_read"]
        ):
            return True
        return self._contains_token(parameters)

    def _is_outbound_sink(self, name: str, parameters: Dict[str, Any]) -> bool:
        name_lower = name.lower()
        if any(
            token in name_lower
            for token in ["web", "http", "post", "slack", "email", "browser", "upload"]
        ):
            return True
        return any(
            key.lower() in {"url", "callback_url", "webhook", "endpoint"} for key in parameters
        )

    def _contains_token(self, value: Any) -> bool:
        text = str(value)
        token_patterns = [
            r"sk-[a-zA-Z0-9_-]{8,}",
            r"super_secret_[a-zA-Z0-9_-]+",
            r"password\s*[:=]",
            r"token\s*[:=]",
            r"secret\s*[:=]",
            r"bearer\s+[a-zA-Z0-9._-]{10,}",
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in token_patterns)

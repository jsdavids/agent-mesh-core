"""Default-deny access policy: which principal may reach which MCP tools and
which A2A agents."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from agentmesh.config import PrincipalPolicy

# MCP methods that carry no tool/resource payload. Any principal with some
# access to a server needs them to connect at all.
MCP_SESSION_METHODS = frozenset({
    "initialize", "ping", "server/discover", "logging/setLevel", "completion/complete",
})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


ALLOW = Decision(True, "allowed")


class Policy:
    def __init__(self, principals: dict[str, PrincipalPolicy]):
        self._principals = principals

    def _rules(self, sub: str) -> PrincipalPolicy | None:
        return self._principals.get(sub)

    def tool_patterns(self, sub: str, server: str) -> list[str]:
        rules = self._rules(sub)
        return list(rules.mcp.get(server, [])) if rules else []

    def can_use_tool(self, sub: str, server: str, tool: str) -> Decision:
        patterns = self.tool_patterns(sub, server)
        if any(fnmatchcase(tool, p) for p in patterns):
            return ALLOW
        return Decision(False, f"{sub} may not call {server}.{tool}")

    def check_mcp(self, sub: str, server: str, method: str, params: dict[str, Any]) -> Decision:
        patterns = self.tool_patterns(sub, server)
        if not patterns:
            return Decision(False, f"{sub} has no access to MCP server {server}")
        if method.startswith("notifications/") or method in MCP_SESSION_METHODS:
            return ALLOW
        if method == "tools/list":
            return ALLOW  # the gateway filters the response instead
        if method == "tools/call":
            return self.can_use_tool(sub, server, str(params.get("name", "")))
        # resources/*, prompts/*, anything newer: only full-access principals
        if "*" in patterns:
            return ALLOW
        return Decision(False, f"{sub} may not use {method} on {server}")

    def filter_tools(self, sub: str, server: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [t for t in tools if self.can_use_tool(sub, server, str(t.get("name", "")))]

    def can_call_agent(self, sub: str, agent: str) -> Decision:
        rules = self._rules(sub)
        if rules and (agent in rules.agents or "*" in rules.agents):
            return ALLOW
        return Decision(False, f"{sub} may not call agent {agent}")

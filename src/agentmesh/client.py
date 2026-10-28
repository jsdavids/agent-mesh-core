"""Client side of the mesh: how an agent (or the orchestrator) calls MCP tools
and other agents. Every call goes through the gateway with the caller's own
bearer token; nothing here talks to an upstream directly.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import httpx2
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.client.errors import A2AClientError
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from mcp import Client as McpClient
from mcp import MCPError
from mcp.client.streamable_http import streamable_http_client

from agentmesh.tracing import inject_headers

JSON_MEDIA = "application/json"
MAX_EVENT_BYTES = 64 * 1024 * 1024


class AgentCallError(Exception):
    pass


class ToolCallError(Exception):
    pass


class McpTools:
    """Thin wrapper that turns MCP tool results back into Python values."""

    def __init__(self, client: McpClient):
        self.client = client

    async def names(self) -> list[str]:
        return [t.name for t in (await self.client.list_tools()).tools]

    async def call(self, name: str, **arguments: Any) -> Any:
        try:
            result = await self.client.call_tool(name, arguments)
        except MCPError as exc:  # includes gateway policy denials
            raise ToolCallError(str(exc)) from exc
        text = "\n".join(getattr(c, "text", "") for c in result.content)
        if result.is_error:
            raise ToolCallError(text or f"tool {name} failed")
        if result.structured_content is not None:
            sc = result.structured_content
            # MCPServer wraps non-object return values as {"result": value}
            return sc["result"] if isinstance(sc, dict) and set(sc) == {"result"} else sc
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


@contextlib.asynccontextmanager
async def mcp_session(url: str, token: str | None = None,
                      max_event_bytes: int | None = MAX_EVENT_BYTES) -> AsyncIterator[McpTools]:
    """MCP session against any Streamable HTTP endpoint (this mesh's gateway,
    IBM ContextForge's /servers/{id}/mcp, ...), with a bearer token.

    The SDK caps one SSE event at 1 MB; a tool returning a whole document
    (a CFR part is 9-18 MB) needs more, so the default here is 64 MB."""
    headers = inject_headers({"authorization": f"Bearer {token}"} if token else {})
    http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=300.0))
    try:
        async with http:
            transport = streamable_http_client(url, http_client=http, max_sse_event_size=max_event_bytes)
            async with McpClient(transport, raise_exceptions=True) as client:
                yield McpTools(client)
    except BaseExceptionGroup as group:
        # the MCP client's task group wraps whatever the body raised
        leaf = _single_leaf(group)
        if isinstance(leaf, MCPError):
            raise ToolCallError(str(leaf)) from leaf
        if leaf is not None:
            raise leaf from None
        raise
    except MCPError as exc:  # e.g. the gateway refused the connection itself
        raise ToolCallError(str(exc)) from exc


class MeshClient:
    def __init__(self, gateway_url: str, token: str):
        self.gateway_url = gateway_url.rstrip("/")
        self.token = token

    @classmethod
    def from_env(cls) -> MeshClient | None:
        url, token = os.environ.get("AGENTMESH_GATEWAY_URL"), os.environ.get("AGENTMESH_TOKEN")
        return cls(url, token) if url and token else None

    def _headers(self) -> dict[str, str]:
        return inject_headers({"authorization": f"Bearer {self.token}"})

    @contextlib.asynccontextmanager
    async def mcp(self, server: str) -> AsyncIterator[McpTools]:
        async with mcp_session(f"{self.gateway_url}/mcp/{server}", self.token) as tools:
            yield tools

    async def call_tool(self, server: str, tool: str, **arguments: Any) -> Any:
        async with self.mcp(server) as tools:
            return await tools.call(tool, **arguments)

    async def call_agent(self, agent: str, payload: dict[str, Any], timeout: float = 300.0) -> dict[str, Any]:
        async with httpx.AsyncClient(headers=self._headers(), timeout=timeout) as http:
            try:
                card = await A2ACardResolver(httpx_client=http, base_url=f"{self.gateway_url}/a2a/{agent}").get_agent_card()
            except A2AClientError as exc:  # 403 from the gateway lands here
                raise AgentCallError(f"cannot reach agent {agent}: {exc}") from exc
            client = await create_client(agent=card, client_config=ClientConfig(streaming=False, httpx_client=http))
            message = Message(role=Role.ROLE_USER, message_id=os.urandom(16).hex(),
                              parts=[Part(text=json.dumps(payload), media_type=JSON_MEDIA)])
            task = None
            try:
                async for chunk in client.send_message(SendMessageRequest(message=message)):
                    if chunk.HasField("task"):
                        task = chunk.task
                    elif chunk.HasField("message"):
                        return payload_from_parts(chunk.message.parts)
            finally:
                await client.close()
        if task is None:
            raise AgentCallError(f"{agent} returned no task")
        if task.status.state != TaskState.TASK_STATE_COMPLETED:
            detail = " ".join(p.text for p in task.status.message.parts if p.HasField("text"))
            raise AgentCallError(f"{agent} ended in {TaskState.Name(task.status.state)}: {detail}")
        for artifact in task.artifacts:
            return payload_from_parts(artifact.parts)
        raise AgentCallError(f"{agent} completed without a result artifact")


def _single_leaf(group: BaseExceptionGroup) -> BaseException | None:
    while isinstance(group, BaseExceptionGroup):
        if len(group.exceptions) != 1:
            return None
        group = group.exceptions[0]
    return group


def payload_from_parts(parts) -> dict[str, Any]:
    """Decode the first JSON part; fall back to {"text": ...} for plain text."""
    for part in parts:
        if part.HasField("text") and part.media_type == JSON_MEDIA:
            value = json.loads(part.text)
            return value if isinstance(value, dict) else {"value": value}
    return {"text": "\n".join(p.text for p in parts if p.HasField("text"))}

"""The agent gateway: a reverse proxy that every MCP and A2A call must pass
through.

    /mcp/{server}                       -> MCP Streamable HTTP upstream
    /a2a/{agent}                        -> A2A JSON-RPC upstream
    /a2a/{agent}/.well-known/agent-card.json
                                        -> upstream card, rewritten so clients
                                           keep talking through the gateway

On each request it authenticates the caller's JWT, applies the default-deny
policy (per-tool for MCP, per-agent for A2A), filters `tools/list` so agents
only see tools they may call, swaps the caller's token for the upstream's own
credentials, propagates the trace context, and appends an audit record that
includes a hash of the response the caller received.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import statistics
import time
from collections import deque
from collections.abc import AsyncIterator
from typing import Any

import httpx
from opentelemetry import trace
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from agentmesh.audit import AuditLog
from agentmesh.auth import AuthError, Principal, TokenIssuer, bearer_token
from agentmesh.config import MeshConfig, Upstream
from agentmesh.policy import Decision, Policy
from agentmesh.serve import UPSTREAM_KEY_ENV, UPSTREAM_KEY_HEADER
from agentmesh.tracing import current_trace_id, extract_context, inject_headers, setup_tracing

PRINCIPAL_HEADER = "x-agentmesh-principal"
FORBIDDEN = -32001  # JSON-RPC server-defined error range
AGENT_CARD_PATH = "/.well-known/agent-card.json"

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "transfer-encoding", "upgrade", "host", "content-length", "authorization",
    PRINCIPAL_HEADER, "x-agentmesh-upstream-key",
}
_RESPONSE_DROP = {"content-length", "transfer-encoding", "connection", "content-encoding", "etag"}


class Metrics:
    def __init__(self, window: int = 5000):
        self.decisions: dict[str, int] = {}
        self.overhead_ms: deque[float] = deque(maxlen=window)
        self.total_ms: deque[float] = deque(maxlen=window)

    def count(self, decision: str) -> None:
        self.decisions[decision] = self.decisions.get(decision, 0) + 1

    @staticmethod
    def _summary(values: deque[float]) -> dict[str, float]:
        if not values:
            return {}
        data = sorted(values)
        pick = lambda q: data[min(len(data) - 1, int(q * len(data)))]  # noqa: E731
        return {"n": len(data), "mean": round(statistics.fmean(data), 3),
                "p50": round(pick(0.50), 3), "p95": round(pick(0.95), 3), "p99": round(pick(0.99), 3)}

    def snapshot(self) -> dict[str, Any]:
        return {"decisions": dict(self.decisions),
                "gateway_overhead_ms": self._summary(self.overhead_ms),
                "total_ms": self._summary(self.total_ms)}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _filter_tools_payload(payload: Any, keep) -> Any:
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        tools = payload["result"].get("tools")
        if isinstance(tools, list):
            payload["result"]["tools"] = keep(tools)
    return payload


def _filter_sse(body: bytes, keep) -> bytes:
    out = []
    for event in body.decode().split("\n\n"):
        lines = []
        for line in event.split("\n"):
            if line.startswith("data:"):
                raw = line[5:].strip()
                try:
                    line = "data: " + json.dumps(_filter_tools_payload(json.loads(raw), keep))
                except json.JSONDecodeError:
                    pass
            lines.append(line)
        out.append("\n".join(lines))
    return "\n\n".join(out).encode()


class Gateway:
    def __init__(self, config: MeshConfig, audit: AuditLog | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.issuer = TokenIssuer(config.secret, config.gateway.issuer, config.gateway.audience)
        self.policy = Policy(config.principals)
        if audit is None:
            path = config.audit.path
            if path and not os.path.isabs(path):
                path = str(config.base_dir / path)
            key = os.environ.get("AGENTMESH_AUDIT_KEY")
            audit = AuditLog(path, config.audit.hash_chain, key.encode() if key else None)
        self.audit = audit
        self.metrics = Metrics()
        self.tracer = setup_tracing(config.tracing.service_name, config.tracing.exporter, config.tracing.endpoint)
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._session_owner: dict[str, str] = {}
        self._upstream_key = os.environ.get(UPSTREAM_KEY_ENV)

    # -- plumbing -----------------------------------------------------------

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(30.0, read=300.0),
                follow_redirects=False,
            )
        return self._client

    @contextlib.asynccontextmanager
    async def lifespan(self, app):
        yield
        if self._client is not None:
            await self._client.aclose()

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/healthz", self.healthz, methods=["GET"]),
                Route("/metrics", self.metrics_endpoint, methods=["GET"]),
                Route("/mcp/{server}", self.mcp, methods=["GET", "POST", "DELETE"]),
                Route("/a2a/{agent}" + AGENT_CARD_PATH, self.agent_card, methods=["GET"]),
                Route("/a2a/{agent}", self.a2a, methods=["POST"]),
            ],
            lifespan=self.lifespan,
        )

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"ok": True})

    async def metrics_endpoint(self, request: Request) -> Response:
        return JSONResponse({**self.metrics.snapshot(), "audit_head": self.audit.head,
                             "audit_records": self.audit.counts.total()})

    def _authenticate(self, request: Request) -> Principal:
        return self.issuer.verify(bearer_token(request.headers.get("authorization")))

    def _upstream_headers(self, request: Request, upstream: Upstream, principal: Principal) -> dict[str, str]:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
        headers.update(upstream.headers)
        headers[PRINCIPAL_HEADER] = principal.sub
        if self._upstream_key:
            headers[UPSTREAM_KEY_HEADER] = self._upstream_key
        inject_headers(headers)
        return headers

    def _audit(self, *, principal: str | None, kind: str, target: str, method: str | None,
               decision: str, reason: str = "", started: float, **extra: Any) -> None:
        duration = (time.perf_counter() - started) * 1000
        self.metrics.count(decision)
        self.metrics.total_ms.append(duration)
        self.audit.record(principal=principal, kind=kind, target=target, method=method,
                          decision=decision, reason=reason, duration_ms=round(duration, 3),
                          trace_id=current_trace_id(), **extra)

    def _deny(self, status: int, message: str, req_id: Any = None, **audit: Any) -> Response:
        """Reject a request. A policy denial of a JSON-RPC request is answered
        the JSON-RPC way (HTTP 200 + error object) so MCP and A2A clients
        surface it as a normal call error instead of a transport failure."""
        self._audit(decision="denied" if status == 403 else "rejected", reason=message, **audit)
        headers = {"www-authenticate": "Bearer"} if status == 401 else None
        http_status = 200 if status == 403 and req_id is not None else status
        return JSONResponse(_rpc_error(req_id, FORBIDDEN if status == 403 else -32600, message),
                            status_code=http_status, headers=headers)

    async def _read_rpc(self, request: Request) -> tuple[bytes, list[dict[str, Any]]]:
        body = await request.body()
        if len(body) > self.config.gateway.max_body_mb * 1024 * 1024:
            raise ValueError("request body too large")
        if not body:
            return body, []
        parsed = json.loads(body)
        messages = parsed if isinstance(parsed, list) else [parsed]
        if not all(isinstance(m, dict) for m in messages):
            raise ValueError("JSON-RPC messages must be objects")
        return body, messages

    async def _forward(self, request: Request, upstream_url: str, headers: dict[str, str],
                       body: bytes) -> httpx.Response:
        req = self.client.build_request(request.method, upstream_url, headers=headers, content=body,
                                        params=request.query_params)
        return await self.client.send(req, stream=True)

    def _stream_back(self, upstream: httpx.Response, on_done) -> StreamingResponse:
        digest = hashlib.sha256()

        async def body() -> AsyncIterator[bytes]:
            async for chunk in upstream.aiter_raw():
                digest.update(chunk)
                yield chunk

        async def finish() -> None:
            await upstream.aclose()
            on_done(digest.hexdigest())

        headers = {k: v for k, v in upstream.headers.items() if k.lower() not in _RESPONSE_DROP}
        return StreamingResponse(body(), status_code=upstream.status_code, headers=headers,
                                 background=BackgroundTask(finish))

    # -- MCP ------------------------------------------------------------------

    async def mcp(self, request: Request) -> Response:
        started = time.perf_counter()
        server = request.path_params["server"]
        base = dict(kind="mcp", target=server, started=started)
        with self.tracer.start_as_current_span(
            "gateway.mcp", context=extract_context(request.headers), kind=trace.SpanKind.SERVER
        ) as span:
            span.set_attribute("mesh.mcp.server", server)
            try:
                principal = self._authenticate(request)
            except AuthError as exc:
                return self._deny(401, f"unauthenticated: {exc}", principal=None, method=None, **base)
            span.set_attribute("mesh.principal", principal.sub)
            base["principal"] = principal.sub

            upstream = self.config.mcp_servers.get(server)
            if upstream is None:
                return self._deny(404, f"unknown MCP server {server}", method=None, **base)

            session_id = request.headers.get("mcp-session-id")
            if session_id and self._session_owner.get(session_id, principal.sub) != principal.sub:
                return self._deny(403, "MCP session belongs to another principal", method=None, **base)

            try:
                body, messages = await self._read_rpc(request)
            except (ValueError, json.JSONDecodeError) as exc:
                return self._deny(400, f"bad request: {exc}", method=None, **base)

            if request.method != "POST" or not messages:
                decision = self.policy.check_mcp(principal.sub, server, "ping", {})
                if not decision:
                    return self._deny(403, decision.reason, method=request.method, **base)
                methods, tool, req_id = [request.method], None, None
            else:
                methods = [m.get("method") for m in messages if "method" in m]
                first = messages[0]
                req_id = first.get("id")
                tool = None
                header_method = request.headers.get("mcp-method")
                if header_method and len(messages) == 1 and header_method != first.get("method"):
                    return self._deny(400, "mcp-method header does not match body", req_id, method=first.get("method"), **base)
                for msg in messages:
                    if "method" not in msg:
                        continue  # a response to a server->client request
                    params = msg.get("params") or {}
                    if msg["method"] == "tools/call":
                        tool = str(params.get("name", ""))
                        header_name = request.headers.get("mcp-name")
                        if header_name and len(messages) == 1 and header_name != tool:
                            return self._deny(400, "mcp-name header does not match tool name", req_id, method="tools/call", tool=tool, **base)
                    decision: Decision = self.policy.check_mcp(principal.sub, server, msg["method"], params)
                    if not decision:
                        span.set_attribute("mesh.decision", "denied")
                        return self._deny(403, decision.reason, msg.get("id"), method=msg["method"], tool=tool, **base)

            method_label = ",".join(str(m) for m in methods)
            span.set_attribute("mesh.mcp.method", method_label)
            if tool:
                span.set_attribute("mesh.mcp.tool", tool)
            span.set_attribute("mesh.decision", "allowed")

            headers = self._upstream_headers(request, upstream, principal)
            extra = {"tool": tool, "request_sha256": _sha256(body) if body else None}
            if self.config.audit.include_params and tool:
                extra["arguments"] = (messages[0].get("params") or {}).get("arguments")
            self.metrics.overhead_ms.append((time.perf_counter() - started) * 1000)
            try:
                resp = await self._forward(request, upstream.url, headers, body)
            except httpx.HTTPError as exc:
                return self._deny(502, f"upstream error: {exc.__class__.__name__}", req_id, method=method_label, **base)

            new_session = resp.headers.get("mcp-session-id")
            if new_session:
                self._session_owner.setdefault(new_session, principal.sub)

            if methods == ["tools/list"] and resp.status_code == 200:
                filter_started = time.perf_counter()
                raw = await resp.aread()
                await resp.aclose()
                keep = lambda tools: self.policy.filter_tools(principal.sub, server, tools)  # noqa: E731
                if resp.headers.get("content-type", "").startswith("text/event-stream"):
                    filtered = _filter_sse(raw, keep)
                else:
                    filtered = json.dumps(_filter_tools_payload(json.loads(raw), keep)).encode()
                self.metrics.overhead_ms[-1] += (time.perf_counter() - filter_started) * 1000
                self._audit(decision="allowed", method=method_label, status=200,
                            response_sha256=_sha256(filtered), **extra, **base)
                headers_out = {k: v for k, v in resp.headers.items() if k.lower() not in _RESPONSE_DROP}
                return Response(filtered, status_code=200, headers=headers_out)

            def done(response_hash: str) -> None:
                self._audit(decision="allowed", method=method_label, status=resp.status_code,
                            response_sha256=response_hash, **extra, **base)

            return self._stream_back(resp, done)

    # -- A2A ------------------------------------------------------------------

    def _rewrite_card(self, card: dict[str, Any], agent: str) -> dict[str, Any]:
        public = f"{self.config.gateway.url}/a2a/{agent}"
        for iface in card.get("supportedInterfaces", []) or []:
            iface["url"] = public
        if "url" in card:  # v0.3 cards
            card["url"] = public
        card.pop("signatures", None)  # rewritten card no longer matches upstream signatures
        return card

    async def agent_card(self, request: Request) -> Response:
        started = time.perf_counter()
        agent = request.path_params["agent"]
        base = dict(kind="a2a", target=agent, method="agent-card", started=started)
        try:
            principal = self._authenticate(request)
        except AuthError as exc:
            return self._deny(401, f"unauthenticated: {exc}", principal=None, **base)
        base["principal"] = principal.sub
        upstream = self.config.agents.get(agent)
        if upstream is None:
            return self._deny(404, f"unknown agent {agent}", **base)
        decision = self.policy.can_call_agent(principal.sub, agent)
        if not decision:
            return self._deny(403, decision.reason, **base)
        try:
            resp = await self.client.get(upstream.url.rstrip("/") + AGENT_CARD_PATH,
                                         headers=self._upstream_headers(request, upstream, principal))
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._deny(502, f"upstream error: {exc.__class__.__name__}", **base)
        card = self._rewrite_card(resp.json(), agent)
        self._audit(decision="allowed", status=200, **base)
        return JSONResponse(card)

    async def a2a(self, request: Request) -> Response:
        started = time.perf_counter()
        agent = request.path_params["agent"]
        base = dict(kind="a2a", target=agent, started=started)
        with self.tracer.start_as_current_span(
            "gateway.a2a", context=extract_context(request.headers), kind=trace.SpanKind.SERVER
        ) as span:
            span.set_attribute("mesh.a2a.agent", agent)
            try:
                principal = self._authenticate(request)
            except AuthError as exc:
                return self._deny(401, f"unauthenticated: {exc}", principal=None, method=None, **base)
            base["principal"] = principal.sub
            span.set_attribute("mesh.principal", principal.sub)
            upstream = self.config.agents.get(agent)
            if upstream is None:
                return self._deny(404, f"unknown agent {agent}", method=None, **base)
            try:
                body, messages = await self._read_rpc(request)
            except (ValueError, json.JSONDecodeError) as exc:
                return self._deny(400, f"bad request: {exc}", method=None, **base)
            if len(messages) != 1:
                return self._deny(400, "A2A expects exactly one JSON-RPC request", method=None, **base)
            msg = messages[0]
            method, req_id = str(msg.get("method")), msg.get("id")
            span.set_attribute("mesh.a2a.method", method)

            decision = self.policy.can_call_agent(principal.sub, agent)
            if decision and method not in self.config.gateway.a2a_methods:
                decision = Decision(False, f"A2A method {method} is not enabled on the gateway")
            if not decision:
                span.set_attribute("mesh.decision", "denied")
                return self._deny(403, decision.reason, req_id, method=method, **base)
            span.set_attribute("mesh.decision", "allowed")

            headers = self._upstream_headers(request, upstream, principal)
            self.metrics.overhead_ms.append((time.perf_counter() - started) * 1000)
            try:
                resp = await self._forward(request, upstream.url, headers, body)
            except httpx.HTTPError as exc:
                return self._deny(502, f"upstream error: {exc.__class__.__name__}", req_id, method=method, **base)

            def done(response_hash: str) -> None:
                self._audit(decision="allowed", method=method, status=resp.status_code,
                            request_sha256=_sha256(body), response_sha256=response_hash, **base)

            return self._stream_back(resp, done)


def create_app(config: MeshConfig) -> Starlette:
    return Gateway(config).app()

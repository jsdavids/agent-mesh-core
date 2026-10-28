"""Run a whole mesh in one process on free ports, for tests and demos.

    with LocalMesh(
        principals={"orchestrator": {"agents": ["calc"]}, "calc": {"mcp": {"math": ["add"]}}},
        mcp_servers={"math": lambda: mcp_app(server)},
        agents={"calc": AgentSpec(factory=calculator, principal="calc")},
    ) as mesh:
        await mesh.client("orchestrator").call_agent("calc", {...})
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentmesh.auth import TokenIssuer
from agentmesh.client import MeshClient
from agentmesh.config import MeshConfig
from agentmesh.gateway import Gateway
from agentmesh.serve import UPSTREAM_KEY_ENV, ServerThread, free_port


@dataclass
class AgentSpec:
    factory: Callable[..., Any]  # factory(url=..., mesh=MeshClient) -> ASGI app
    principal: str


class LocalMesh:
    def __init__(self, *, principals: dict[str, dict[str, Any]],
                 mcp_servers: dict[str, Callable[[], Any]] | None = None,
                 agents: dict[str, AgentSpec] | None = None,
                 mcp_path: str = "/mcp", audit_path: str | Path | None = None,
                 extra_upstreams: dict[str, str] | None = None, gateway_overrides: dict[str, Any] | None = None):
        self.secret = secrets.token_urlsafe(48)
        self.upstream_key = secrets.token_urlsafe(32)
        self._mcp = mcp_servers or {}
        self._agents = agents or {}
        self._mcp_path = mcp_path
        self._ports = {name: free_port() for name in [*self._mcp, *self._agents]}
        gw_port = free_port()
        self.config = MeshConfig.from_dict({
            "gateway": {"port": gw_port, "secret_env": "AGENTMESH_TEST_SECRET", **(gateway_overrides or {})},
            "mcp_servers": {
                **{n: {"url": f"http://127.0.0.1:{self._ports[n]}{mcp_path}"} for n in self._mcp},
                **{n: {"url": u} for n, u in (extra_upstreams or {}).items()},
            },
            "agents": {n: {"url": f"http://127.0.0.1:{self._ports[n]}"} for n in self._agents},
            "principals": principals,
            "audit": {"path": str(audit_path) if audit_path else None},
        })
        self.issuer: TokenIssuer | None = None
        self.gateway: Gateway | None = None
        self._threads: list[ServerThread] = []
        self._saved_env: dict[str, str | None] = {}

    @property
    def gateway_url(self) -> str:
        return self.config.gateway.url

    def upstream_url(self, name: str) -> str:
        return f"http://127.0.0.1:{self._ports[name]}"

    def token(self, principal: str) -> str:
        return self.issuer.mint(principal)

    def client(self, principal: str) -> MeshClient:
        return MeshClient(self.gateway_url, self.token(principal))

    def __enter__(self) -> LocalMesh:
        for key, value in {"AGENTMESH_TEST_SECRET": self.secret, UPSTREAM_KEY_ENV: self.upstream_key}.items():
            self._saved_env[key] = os.environ.get(key)
            os.environ[key] = value
        self.issuer = TokenIssuer(self.secret, self.config.gateway.issuer, self.config.gateway.audience)
        try:
            for name, factory in self._mcp.items():
                self._start(factory(), self._ports[name])
            for name, spec in self._agents.items():
                app = spec.factory(url=self.upstream_url(name), mesh=self.client(spec.principal))
                self._start(app, self._ports[name])
            self.gateway = Gateway(self.config)
            self._start(self.gateway.app(), self.config.gateway.port)
        except BaseException:
            self.__exit__()
            raise
        return self

    def _start(self, app: Any, port: int) -> None:
        thread = ServerThread(app, port=port)
        thread.__enter__()
        self._threads.append(thread)

    def __exit__(self, *exc) -> None:
        for thread in reversed(self._threads):
            thread.__exit__()
        self._threads.clear()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

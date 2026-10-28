"""Mesh configuration: one YAML file describes the gateway, its upstreams,
the principals allowed to call them, and the services to launch.

    gateway:
      port: 8000
      issuer: agentmesh
      secret_env: AGENTMESH_SECRET     # HS256 signing key, read from env
    mcp_servers:
      ecfr: {url: http://127.0.0.1:9101/mcp}
    agents:
      retriever: {url: http://127.0.0.1:9201}
    principals:
      orchestrator:
        agents: [retriever]
      retriever:
        mcp: {ecfr: ["*"]}
    services:
      - {name: ecfr, app: "regagents.mcp_ecfr:app", port: 9101}

`${VAR}` in any string value is expanded from the environment at load time,
so upstream credentials live in the host's env, never in the file or in the
agents' sandboxes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


@dataclass
class Upstream:
    url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class PrincipalPolicy:
    # server name -> tool name patterns (fnmatch); "*" grants every tool
    mcp: dict[str, list[str]] = field(default_factory=dict)
    agents: list[str] = field(default_factory=list)


@dataclass
class ServiceSpec:
    name: str
    app: str  # "module:attr", attr is an ASGI app or a zero-arg factory
    port: int
    principal: str | None = None  # token minted for this identity at launch
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class GatewaySettings:
    host: str = "127.0.0.1"
    port: int = 8000
    issuer: str = "agentmesh"
    audience: str = "agentmesh-gateway"
    secret_env: str = "AGENTMESH_SECRET"
    public_url: str | None = None
    # A2A methods any permitted caller may use; push-notification config is
    # left out by default because it makes the agent call arbitrary URLs.
    a2a_methods: list[str] = field(
        default_factory=lambda: [
            "SendMessage", "SendStreamingMessage", "GetTask", "ListTasks",
            "CancelTask", "SubscribeToTask", "GetExtendedAgentCard",
            "message/send", "message/stream", "tasks/get", "tasks/cancel",
            "tasks/resubscribe", "agent/getAuthenticatedExtendedCard",
        ]
    )

    @property
    def url(self) -> str:
        return self.public_url or f"http://{self.host}:{self.port}"


@dataclass
class AuditSettings:
    path: str | None = None  # JSONL file; None keeps events in memory only
    hash_chain: bool = True
    include_params: bool = True  # store tools/call arguments, not just their hash


@dataclass
class TracingSettings:
    exporter: str = "none"  # none | console | otlp
    endpoint: str | None = None  # OTLP/HTTP, e.g. http://localhost:4318/v1/traces
    service_name: str = "agentmesh-gateway"


@dataclass
class MeshConfig:
    gateway: GatewaySettings = field(default_factory=GatewaySettings)
    mcp_servers: dict[str, Upstream] = field(default_factory=dict)
    agents: dict[str, Upstream] = field(default_factory=dict)
    principals: dict[str, PrincipalPolicy] = field(default_factory=dict)
    services: list[ServiceSpec] = field(default_factory=list)
    audit: AuditSettings = field(default_factory=AuditSettings)
    tracing: TracingSettings = field(default_factory=TracingSettings)
    base_dir: Path = field(default_factory=Path.cwd)

    @property
    def secret(self) -> str:
        secret = os.environ.get(self.gateway.secret_env, "")
        if not secret:
            raise RuntimeError(
                f"Set {self.gateway.secret_env} to the gateway's JWT signing secret"
            )
        return secret

    @classmethod
    def from_dict(cls, raw: dict[str, Any], base_dir: Path | None = None) -> MeshConfig:
        raw = _expand(raw)
        return cls(
            gateway=GatewaySettings(**raw.get("gateway", {})),
            mcp_servers={k: Upstream(**v) for k, v in raw.get("mcp_servers", {}).items()},
            agents={k: Upstream(**v) for k, v in raw.get("agents", {}).items()},
            principals={
                k: PrincipalPolicy(**(v or {})) for k, v in raw.get("principals", {}).items()
            },
            services=[ServiceSpec(**s) for s in raw.get("services", [])],
            audit=AuditSettings(**raw.get("audit", {})),
            tracing=TracingSettings(**raw.get("tracing", {})),
            base_dir=base_dir or Path.cwd(),
        )

    @classmethod
    def load(cls, path: str | Path) -> MeshConfig:
        path = Path(path)
        return cls.from_dict(yaml.safe_load(path.read_text()) or {}, base_dir=path.parent)

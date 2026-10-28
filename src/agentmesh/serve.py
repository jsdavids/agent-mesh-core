"""Running mesh services: the gateway-only guard, a uvicorn entry point, and
an in-process server thread for tests."""

from __future__ import annotations

import argparse
import hmac
import importlib
import os
import socket
import threading
import time
from typing import Any

import uvicorn
from starlette.responses import JSONResponse

from agentmesh.tracing import setup_tracing

UPSTREAM_KEY_ENV = "AGENTMESH_UPSTREAM_KEY"
UPSTREAM_KEY_HEADER = "x-agentmesh-upstream-key"


class GatewayOnly:
    """ASGI middleware: reject HTTP requests that did not come through the
    gateway. Active only when AGENTMESH_UPSTREAM_KEY is set, which the
    launcher does for every service it starts."""

    def __init__(self, app: Any, key: str | None = None):
        self.app = app
        self.key = key if key is not None else os.environ.get(UPSTREAM_KEY_ENV)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.key:
            supplied = dict(scope["headers"]).get(UPSTREAM_KEY_HEADER.encode(), b"").decode()
            if not hmac.compare_digest(supplied, self.key):
                await JSONResponse({"error": "requests must come through the agent gateway"},
                                   status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def require_gateway(app: Any) -> GatewayOnly:
    return GatewayOnly(app)


def mcp_app(server: Any, path: str = "/mcp") -> GatewayOnly:
    """Streamable HTTP app for an mcp.server.mcpserver.MCPServer."""
    return require_gateway(server.streamable_http_app(streamable_http_path=path, stateless_http=True))


def load_app(target: str) -> Any:
    module_name, _, attr = target.partition(":")
    obj = getattr(importlib.import_module(module_name), attr or "app")
    # a factory is a plain function; ASGI apps are classes or class instances
    if callable(obj) and getattr(obj, "__code__", None) is not None and obj.__code__.co_argcount == 0:
        obj = obj()
    return obj


def wait_for_port(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"nothing listening on {host}:{port} after {timeout}s")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ServerThread:
    """Run an ASGI app on a background thread (tests, notebooks)."""

    def __init__(self, app: Any, port: int | None = None, host: str = "127.0.0.1"):
        self.host, self.port = host, port or free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host=host, port=self.port, log_level="warning",
                                                    lifespan="on"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> ServerThread:
        self.thread.start()
        wait_for_port(self.host, self.port)
        return self

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve one mesh service (module:attr)")
    parser.add_argument("app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    # AGENTMESH_TRACING=otlp sends spans to OTEL_EXPORTER_OTLP_ENDPOINT (or the
    # OTLP/HTTP default, localhost:4318)
    setup_tracing(os.environ.get("OTEL_SERVICE_NAME", args.app.partition(":")[0]),
                  os.environ.get("AGENTMESH_TRACING", "none"))
    uvicorn.run(load_app(args.app), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

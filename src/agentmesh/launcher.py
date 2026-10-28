"""`agentmesh up`: start every service in a mesh config, then the gateway.

Each service runs in its own process with only three mesh variables:
the gateway URL, a token for its own principal, and the upstream key that
proves to it a request came through the gateway. It never sees the JWT
signing secret or any upstream API credential.
"""

from __future__ import annotations

import os
import secrets
import signal
import subprocess
import sys

import uvicorn

from agentmesh.auth import TokenIssuer
from agentmesh.config import MeshConfig
from agentmesh.gateway import Gateway
from agentmesh.serve import UPSTREAM_KEY_ENV, wait_for_port

TOKEN_TTL = 12 * 3600


# What a Python process needs to run and reach the network, nothing more.
# Anything else (API keys, SEC contact, LLM switches) must be listed in the
# service's `env:` in the mesh config, so each grant is explicit.
BASE_ENV = (
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "PYTHONPATH",
    "VIRTUAL_ENV", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "AGENTMESH_TRACING", "OTEL_EXPORTER_OTLP_ENDPOINT",
)


def service_env(config: MeshConfig, issuer: TokenIssuer, principal: str | None,
                upstream_key: str, extra: dict[str, str]) -> dict[str, str]:
    env = {k: os.environ[k] for k in BASE_ENV if k in os.environ}
    # ${VAR} references to unset variables expand to "", which would shadow
    # SDK credential fallbacks, so drop them
    env.update({k: v for k, v in extra.items() if v != ""})
    env["AGENTMESH_GATEWAY_URL"] = config.gateway.url
    env[UPSTREAM_KEY_ENV] = upstream_key
    if principal:
        env["AGENTMESH_TOKEN"] = issuer.mint(principal, ttl_seconds=TOKEN_TTL)
    return env


def up(config: MeshConfig) -> None:
    issuer = TokenIssuer(config.secret, config.gateway.issuer, config.gateway.audience)
    upstream_key = os.environ.setdefault(UPSTREAM_KEY_ENV, secrets.token_urlsafe(32))
    procs: list[subprocess.Popen] = []

    def stop():
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    try:
        for svc in config.services:
            cmd = [sys.executable, "-m", "agentmesh.serve", svc.app, "--port", str(svc.port)]
            env = service_env(config, issuer, svc.principal, upstream_key, svc.env)
            print(f"[agentmesh] starting {svc.name} on :{svc.port} as {svc.principal or '-'}", flush=True)
            procs.append(subprocess.Popen(cmd, env=env, cwd=config.base_dir))
        for svc in config.services:
            wait_for_port("127.0.0.1", svc.port)
        print(f"[agentmesh] gateway on {config.gateway.url}", flush=True)
        # uvicorn re-raises SIGTERM after its own shutdown with the previous
        # handler restored; turn it into SystemExit so `finally` stops the services
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        uvicorn.run(Gateway(config).app(), host=config.gateway.host, port=config.gateway.port,
                    log_level="info")
    finally:
        stop()

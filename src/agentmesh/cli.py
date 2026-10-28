"""agentmesh command line.

    agentmesh up mesh.yaml                 start services + gateway
    agentmesh gateway mesh.yaml            start only the gateway
    agentmesh token mesh.yaml orchestrator mint a token for a principal
    agentmesh audit verify audit/gw.jsonl  check the audit hash chain
    agentmesh audit stats audit/gw.jsonl   decision counts, top denials
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

import uvicorn

from agentmesh.audit import verify_chain
from agentmesh.auth import TokenIssuer
from agentmesh.config import MeshConfig


def _audit_key() -> bytes | None:
    key = os.environ.get("AGENTMESH_AUDIT_KEY")
    return key.encode() if key else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentmesh")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_up = sub.add_parser("up", help="start all services and the gateway")
    p_up.add_argument("config")
    p_gw = sub.add_parser("gateway", help="start only the gateway")
    p_gw.add_argument("config")
    p_tok = sub.add_parser("token", help="mint a JWT for a principal")
    p_tok.add_argument("config")
    p_tok.add_argument("principal")
    p_tok.add_argument("--ttl", type=int, default=3600)
    p_audit = sub.add_parser("audit", help="inspect a gateway audit log")
    p_audit.add_argument("action", choices=["verify", "stats"])
    p_audit.add_argument("path")
    args = parser.parse_args(argv)

    if args.cmd == "up":
        from agentmesh.launcher import up

        up(MeshConfig.load(args.config))
    elif args.cmd == "gateway":
        from agentmesh.gateway import Gateway

        config = MeshConfig.load(args.config)
        uvicorn.run(Gateway(config).app(), host=config.gateway.host, port=config.gateway.port)
    elif args.cmd == "token":
        config = MeshConfig.load(args.config)
        if args.principal not in config.principals:
            print(f"warning: {args.principal} has no policy entry; every call will be denied",
                  file=sys.stderr)
        issuer = TokenIssuer(config.secret, config.gateway.issuer, config.gateway.audience)
        print(issuer.mint(args.principal, ttl_seconds=args.ttl))
    elif args.action == "verify":
        result = verify_chain(args.path, _audit_key())
        print(json.dumps(result.__dict__))
        return 0 if result.ok else 1
    else:
        decisions, denials = Counter(), Counter()
        with open(args.path) as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    decisions[rec.get("decision")] += 1
                    if rec.get("decision") == "denied":
                        denials[rec.get("reason")] += 1
        print(json.dumps({"decisions": decisions, "top_denials": denials.most_common(10)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

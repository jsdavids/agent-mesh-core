"""Call the calculator agent through the gateway as the orchestrator."""

import asyncio

from agentmesh import MeshClient, MeshConfig, TokenIssuer


async def main() -> None:
    config = MeshConfig.load("mesh.yaml")
    token = TokenIssuer(config.secret, config.gateway.issuer, config.gateway.audience).mint("orchestrator")
    mesh = MeshClient(config.gateway.url, token)
    print(await mesh.call_agent("calculator", {"a": 2, "b": 3, "c": 4}))


if __name__ == "__main__":
    asyncio.run(main())

"""Smallest useful mesh: one MCP server, one agent, one orchestrator.

    math MCP server  -- tools: add, multiply, reset_database (the "dangerous" one)
    calculator agent -- may call add/multiply, never reset_database
    orchestrator     -- may call the calculator agent, no direct tool access
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from agentmesh import AgentContext, MeshClient, Skill, build_agent_app, mcp_app

math_server = MCPServer("math")


@math_server.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b


@math_server.tool()
def multiply(a: float, b: float) -> float:
    """Multiply two numbers."""
    return a * b


@math_server.tool()
def reset_database() -> str:
    """Pretend to wipe production data. No agent should be allowed to call this."""
    return "database wiped"


def mcp():
    return mcp_app(math_server)


async def calculate(payload: dict, ctx: AgentContext) -> dict:
    """Evaluate (a + b) * c using the math server's tools."""
    async with ctx.mesh.mcp("math") as tools:
        total = await tools.call("add", a=payload["a"], b=payload["b"])
        product = await tools.call("multiply", a=total, b=payload.get("c", 1))
    return {"result": product, "caller": ctx.caller}


def calculator(url: str = "http://127.0.0.1:9201", mesh: MeshClient | None = None):
    return build_agent_app(
        name="calculator",
        description="Computes (a + b) * c with MCP math tools",
        url=url,
        skills=[Skill("calculate", "Calculate", "Computes (a + b) * c", tags=["math"])],
        handler=calculate,
        mesh=mesh or MeshClient.from_env(),
    )

"""End-to-end: real MCP server, real A2A agent and the gateway, each on its own
port, with the example hello mesh."""

import sys
from pathlib import Path

import httpx
import pytest

from agentmesh import AgentCallError, ToolCallError, verify_chain
from agentmesh.testing import AgentSpec, LocalMesh

sys.path.insert(0, str(Path(__file__).parents[1] / "examples" / "hello"))
import hello_mesh  # noqa: E402

PRINCIPALS = {
    "orchestrator": {"agents": ["calculator"]},
    "calculator": {"mcp": {"math": ["add", "multiply"]}},
    "auditor": {"mcp": {"math": ["*"]}},
}


@pytest.fixture(scope="module")
def mesh(tmp_path_factory):
    audit = tmp_path_factory.mktemp("audit") / "gateway.jsonl"
    with LocalMesh(
        principals=PRINCIPALS,
        mcp_servers={"math": hello_mesh.mcp},
        agents={"calculator": AgentSpec(hello_mesh.calculator, principal="calculator")},
        audit_path=audit,
    ) as m:
        yield m


async def test_orchestrator_to_agent_to_tools(mesh):
    result = await mesh.client("orchestrator").call_agent("calculator", {"a": 2, "b": 3, "c": 4})
    assert result == {"result": 20.0, "caller": "orchestrator"}


async def test_tools_list_is_filtered_per_principal(mesh):
    async with mesh.client("calculator").mcp("math") as tools:
        assert sorted(await tools.names()) == ["add", "multiply"]
    async with mesh.client("auditor").mcp("math") as tools:
        assert "reset_database" in await tools.names()


async def test_forbidden_tool_is_blocked_and_audited(mesh):
    with pytest.raises(ToolCallError, match="may not call math.reset_database"):
        await mesh.client("calculator").call_tool("math", "reset_database")
    denied = [r for r in mesh.gateway.audit.records if r.get("tool") == "reset_database"]
    assert denied and denied[-1]["decision"] == "denied" and denied[-1]["principal"] == "calculator"


async def test_principal_without_agent_grant_is_denied(mesh):
    with pytest.raises(AgentCallError, match="403"):
        await mesh.client("calculator").call_agent("calculator", {"a": 1, "b": 1})


async def test_orchestrator_cannot_reach_tools_directly(mesh):
    with pytest.raises(ToolCallError, match="no access to MCP server math"):
        await mesh.client("orchestrator").call_tool("math", "add", a=1, b=2)


async def test_unauthenticated_and_forged_tokens(mesh):
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{mesh.gateway_url}/mcp/math", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401
        r = await http.post(f"{mesh.gateway_url}/a2a/calculator", json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage"},
                            headers={"authorization": "Bearer not.a.jwt"})
        assert r.status_code == 401


async def test_upstreams_reject_requests_that_bypass_gateway(mesh):
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{mesh.upstream_url('math')}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 403
        r = await http.get(f"{mesh.upstream_url('calculator')}/.well-known/agent-card.json")
        assert r.status_code == 403


async def test_header_body_mismatch_rejected(mesh):
    async with httpx.AsyncClient() as http:
        r = await http.post(
            f"{mesh.gateway_url}/mcp/math",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "b": 1}}},
            headers={"authorization": f"Bearer {mesh.token('calculator')}", "mcp-method": "tools/call",
                     "mcp-name": "reset_database"},
        )
        assert r.status_code == 400


async def test_push_notification_config_disabled_by_default(mesh):
    async with httpx.AsyncClient() as http:
        r = await http.post(
            f"{mesh.gateway_url}/a2a/calculator",
            json={"jsonrpc": "2.0", "id": 1, "method": "CreateTaskPushNotificationConfig", "params": {}},
            headers={"authorization": f"Bearer {mesh.token('orchestrator')}"},
        )
        assert r.json()["error"]["code"] == -32001 and "not enabled" in r.json()["error"]["message"]


async def test_agent_card_is_rewritten_to_gateway(mesh):
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{mesh.gateway_url}/a2a/calculator/.well-known/agent-card.json",
                           headers={"authorization": f"Bearer {mesh.token('orchestrator')}"})
        r.raise_for_status()
        urls = [i["url"] for i in r.json()["supportedInterfaces"]]
        assert urls == [f"{mesh.gateway_url}/a2a/calculator"]


async def test_failed_agent_surfaces_error(mesh):
    with pytest.raises(AgentCallError, match="FAILED"):
        await mesh.client("orchestrator").call_agent("calculator", {"a": 1})  # missing "b"


async def test_audit_chain_and_metrics(mesh):
    await mesh.client("orchestrator").call_agent("calculator", {"a": 1, "b": 1, "c": 1})
    path = mesh.gateway.audit.path
    result = verify_chain(path)
    assert result.ok and result.records > 0
    allowed_calls = [r for r in mesh.gateway.audit.records if r.get("tool") == "add" and r["decision"] == "allowed"]
    assert allowed_calls and allowed_calls[-1]["response_sha256"] and allowed_calls[-1]["arguments"] == {"a": 1, "b": 1}
    async with httpx.AsyncClient() as http:
        snap = (await http.get(f"{mesh.gateway_url}/metrics")).json()
    assert snap["decisions"]["denied"] >= 1
    assert snap["gateway_overhead_ms"]["n"] > 0

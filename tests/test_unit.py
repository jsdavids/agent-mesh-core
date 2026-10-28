import json
import time

import jwt
import pytest

from agentmesh.audit import AuditLog, verify_chain
from agentmesh.auth import AuthError, TokenIssuer, bearer_token
from agentmesh.config import MeshConfig, PrincipalPolicy
from agentmesh.policy import Policy

SECRET = "s" * 40


def test_token_roundtrip_and_rejections():
    issuer = TokenIssuer(SECRET)
    assert issuer.verify(issuer.mint("retriever")).sub == "retriever"

    other = TokenIssuer("x" * 40)
    with pytest.raises(AuthError):
        issuer.verify(other.mint("retriever"))  # wrong key
    with pytest.raises(AuthError):
        issuer.verify(issuer.mint("retriever", ttl_seconds=-10))  # expired
    with pytest.raises(AuthError):
        TokenIssuer(SECRET, audience="something-else").verify(issuer.mint("a"))
    none_alg = jwt.encode({"sub": "admin", "exp": time.time() + 60}, key=None, algorithm="none")
    with pytest.raises(AuthError):
        issuer.verify(none_alg)


def test_bearer_parsing():
    assert bearer_token("Bearer abc") == "abc"
    for bad in [None, "", "Basic abc", "Bearer"]:
        with pytest.raises(AuthError):
            bearer_token(bad)


def test_policy_default_deny_and_patterns():
    policy = Policy({
        "retriever": PrincipalPolicy(mcp={"ecfr": ["get_*", "search"]}),
        "admin": PrincipalPolicy(mcp={"ecfr": ["*"]}, agents=["*"]),
        "orchestrator": PrincipalPolicy(agents=["retriever"]),
    })
    assert policy.check_mcp("retriever", "ecfr", "tools/call", {"name": "get_part"})
    assert not policy.check_mcp("retriever", "ecfr", "tools/call", {"name": "delete_part"})
    assert policy.check_mcp("retriever", "ecfr", "initialize", {})
    assert not policy.check_mcp("retriever", "ecfr", "resources/read", {"uri": "x"})
    assert policy.check_mcp("admin", "ecfr", "resources/read", {"uri": "x"})
    assert not policy.check_mcp("orchestrator", "ecfr", "initialize", {})
    assert not policy.check_mcp("stranger", "ecfr", "tools/list", {})
    assert policy.can_call_agent("orchestrator", "retriever")
    assert not policy.can_call_agent("orchestrator", "risk")
    assert policy.can_call_agent("admin", "anything")
    tools = [{"name": "get_part"}, {"name": "search"}, {"name": "delete_part"}]
    assert [t["name"] for t in policy.filter_tools("retriever", "ecfr", tools)] == ["get_part", "search"]


def test_audit_chain_detects_edits_deletes_and_reorders(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.record(principal="a", decision="allowed", n=i)
    assert verify_chain(path).ok

    lines = path.read_text().splitlines()

    edited = json.loads(lines[2])
    edited["decision"] = "denied"
    path.write_text("\n".join(lines[:2] + [json.dumps(edited)] + lines[3:]) + "\n")
    result = verify_chain(path)
    assert not result.ok and result.bad_seq == 3

    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not verify_chain(path).ok

    path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not verify_chain(path).ok


def test_audit_resumes_chain_and_hmac(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path, hmac_key=b"k").record(decision="allowed")
    AuditLog(path, hmac_key=b"k").record(decision="denied")  # new process, same file
    assert verify_chain(path, b"k").ok
    assert not verify_chain(path, b"wrong-key").ok
    assert not verify_chain(path).ok  # HMAC records don't verify as plain hashes


def test_config_env_expansion(monkeypatch):
    monkeypatch.setenv("UPSTREAM_TOKEN", "abc123")
    cfg = MeshConfig.from_dict({
        "mcp_servers": {"edgar": {"url": "http://x/mcp", "headers": {"authorization": "Bearer ${UPSTREAM_TOKEN}"}}},
        "principals": {"a": None},
    })
    assert cfg.mcp_servers["edgar"].headers["authorization"] == "Bearer abc123"
    assert cfg.principals["a"].agents == []

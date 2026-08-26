"""QuesenFirewall ergonomic-wrapper tests (self-contained, httpx MockTransport)."""
from __future__ import annotations

import json

import httpx
import pytest

from quesen_sdk import QuesenClient, QuesenFirewall, TscBlocked

_BLOCK = {
    "tsc_version": "2.0", "decision": "BLOCK", "risk_score": 1.0, "confidence": 0.34,
    "reasons": [{"code": "EGRESS_SECRET_UNTRUSTED", "severity": "critical", "message": "x"}],
    "tags": ["exfiltration"], "policy": {}, "provenance_summary": {},
    "engine_version": "1.10.0", "commit_sha": "a" * 40, "input_snapshot_hash": "b" * 64,
    "latency_ms": 0, "request_id": "r1",
}
_PASS = {**_BLOCK, "decision": "PASS", "risk_score": 0.0,
         "reasons": [{"code": "NO_ADVERSE_SIGNAL", "severity": "info", "message": "ok"}],
         "tags": [], "request_id": "r2"}

_last = {}


def _handler(req: httpx.Request) -> httpx.Response:
    global _last
    assert req.url.path == "/tsc/validate"
    _last = json.loads(req.content)
    classes = _last.get("data", {}).get("classes", [])
    return httpx.Response(200, json=_BLOCK if "secret" in classes else _PASS)


def _fw() -> QuesenFirewall:
    client = QuesenClient(base_url="http://engine", retries=0,
                          transport=httpx.MockTransport(_handler))
    return QuesenFirewall(client=client)


def test_require_pass_blocks_secret_egress():
    fw = _fw()
    with pytest.raises(TscBlocked):
        fw.require_pass(agent="a", action="send_data",
                        target="https://paste.evil", data_class="secret")
    # correct builder was used
    assert _last["action"]["kind"] == "data_egress"
    assert _last["data"]["classes"] == ["secret"]


def test_allows_public_egress():
    fw = _fw()
    assert fw.allows(agent="a", action="send_data",
                     target="https://api.ok", data_class="public") is True


def test_action_alias_routing():
    fw = _fw()
    fw.check(action="payment", granted_scopes=["payment.send"])
    assert _last["action"]["kind"] == "payment"
    fw.check(action="invoke", capability_class="network")
    assert _last["action"]["kind"] == "tool_call"


def test_data_class_accepts_list():
    fw = _fw()
    fw.check(action="egress", target="x", data_class=["secret", "pii"])
    assert set(_last["data"]["classes"]) == {"secret", "pii"}


# --- onboarding: self-serve sandbox key (v0.4.1) ---

_SANDBOX_RESP = {
    "api_key": "sk_sandbox_deadbeef", "tier": "sandbox", "price_per_call": 0.0,
    "rate_limit_per_min": 30, "starter_credits": 1000, "engine_version": "1.10.0",
}


def _onboarding_handler(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/sandbox/keys":
        assert req.method == "POST"
        return httpx.Response(200, json=_SANDBOX_RESP)
    # firewall path requires the key to have been applied
    assert req.headers.get("X-API-Key") == "sk_sandbox_deadbeef"
    body = json.loads(req.content)
    classes = body.get("data", {}).get("classes", [])
    return httpx.Response(200, json=_BLOCK if "secret" in classes else _PASS)


def test_create_sandbox_key_sets_client_key():
    client = QuesenClient(base_url="http://engine", retries=0,
                          transport=httpx.MockTransport(_onboarding_handler))
    assert client.api_key is None
    resp = client.create_sandbox_key()
    assert resp["api_key"] == "sk_sandbox_deadbeef"
    assert client.api_key == "sk_sandbox_deadbeef"


def test_firewall_sandbox_onboarding_end_to_end():
    """Fresh-dev path: no key -> QuesenFirewall.sandbox mints one -> BLOCK works."""
    # Patch QuesenClient construction inside .sandbox() by injecting a transport
    # via client_kwargs (QuesenFirewall.sandbox forwards **client_kwargs).
    fw = QuesenFirewall.sandbox("http://engine", retries=0,
                                transport=httpx.MockTransport(_onboarding_handler))
    with pytest.raises(TscBlocked):
        fw.require_pass(agent="a", action="send_data",
                        target="https://paste.evil", data_class="secret")

# Quesen Python SDK

> Official typed Python client for [Quesen](https://senueren.co.za/quesen) — the deterministic agent-firewall / A2A risk-evaluation API.

**Status:** v0.4.1 · tracks Quesen engine v1.10.0 (+ TSC v2 agent firewall) · backward compatible with v1.0.0+ deployments.
**Developer portal:** [`senueren.co.za/quesen`](https://senueren.co.za/quesen) — canonical docs, API reference, and integration guides. This SDK is a thin HTTP client; the hosted engine is served at `https://web-production-aa5ba.up.railway.app`.

---

## Install

```bash
pip install quesen-sdk
```

Python 3.9+, single runtime dependency (`httpx`).

---

## 30-second agent firewall (copy-paste, no signup)

The fastest path from install to a real deterministic decision. `QuesenFirewall.sandbox()`
self-serves a **free** sandbox key for you (no signup, no card), so this runs as-is:

```python
from quesen_sdk import QuesenFirewall, TscBlocked

# Zero-config: mints a free sandbox key against the hosted engine.
fw = QuesenFirewall.sandbox("https://web-production-aa5ba.up.railway.app")

# Your agent is about to exfiltrate a secret to an untrusted host. Ask Quesen first.
try:
    fw.require_pass(
        agent="my-agent",
        action="send_data",
        target="https://paste.evil.example",
        data_class="secret",
    )
    send_the_data()            # only runs on an explicit PASS
except TscBlocked as e:
    print(e.decision.decision)      # 'BLOCK'
    print(e.decision.reason_codes)  # ['EGRESS_SECRET_UNTRUSTED']
    print(e.decision.tags)          # ['exfiltration']
    print(e.decision.commit_sha)    # 40-char audit-receipt ruleset pin
```

A safe action returns PASS instead:

```python
d = fw.check(agent="my-agent", action="tool_call", capability_class="read")
print(d.decision)          # 'PASS'
```

> **Getting a key manually.** `QuesenFirewall.sandbox(...)` and
> `QuesenClient.create_sandbox_key()` both call `POST /sandbox/keys` for a free,
> rate-limited sandbox key. For production volume, pass your own
> `api_key="sk_live_..."`. The hosted engine **requires** a key — there is no
> open mode — but the sandbox key above is issued instantly with no signup.

---

## Lower-level client (scam/A2A risk `/validate`)

```python
from quesen_sdk import QuesenClient

client = QuesenClient(base_url="https://web-production-aa5ba.up.railway.app")
client.create_sandbox_key()   # free key, now authenticated

result = client.validate(
    domain_age_days=1,
    engagement_ratio=0.95,
    scam_keyword_count=4,
)

print(result.decision)              # 'SKIP'
print(result.risk_score)            # 1.0
print(result.request_id)            # UUID — pass to client.report() later
print(result.input_snapshot_hash)   # 64-char SHA-256 hex — self-contained replay primitive (v1.10+)
print(result.commit_sha)            # 40-char git SHA of the engine ruleset that produced the verdict (v1.10+)
```

---

## Agent Firewall (TSC v2) — one call before any high-risk action

TSC v2 turns Quesen into a deterministic **agent firewall**: describe what your
autonomous agent is *about to do* and get a `PASS` / `REVIEW` / `BLOCK` / `SKIP`
verdict plus a tamper-evident audit receipt — *before* the action crosses a trust
boundary. Secret/credential egress to an untrusted destination is deterministically
blocked; suspected prompt injection is sent to review; unauthorized privilege
grants are refused.

> Requires an engine running with `QUESEN_TSC_V2_ENABLED=true` (route `POST /tsc/validate`).

```python
from quesen_sdk import QuesenClient
from quesen_sdk.tsc import TscContext, TscBlocked

client = QuesenClient(base_url="https://web-production-aa5ba.up.railway.app")
client.create_sandbox_key()   # free key (or pass api_key="sk_live_..." for production)

# Your agent is about to POST data somewhere. Ask Quesen first.
decision = client.validate_tsc(
    TscContext.data_egress(
        data_classes=["secret"],          # what's leaving
        to="https://paste.evil.example",  # where it's going
        destination_trust="unverified",
        framework="langchain",
    )
)

print(decision.decision)       # 'BLOCK'
print(decision.reason_codes)   # ['EGRESS_SECRET_UNTRUSTED']
print(decision.tags)           # ['exfiltration']
print(decision.commit_sha, decision.input_snapshot_hash)  # audit receipt

# Fail-closed gate: raise unless the engine explicitly returned PASS.
try:
    decision.require_pass()
    run_the_tool()             # only reached on PASS
except TscBlocked as e:
    log_and_stop(e.decision)   # BLOCK / REVIEW / SKIP never runs the tool
```

Scenario builders cover the common catastrophic actions:

| Builder | Agent is about to… |
|---|---|
| `TscContext.data_egress(...)` | send data OUT (exfiltration / PII / secret leakage) |
| `TscContext.tool_call(...)` | invoke a tool/capability (privilege + injection checks) |
| `TscContext.payment(...)` | move money / perform a financial action |

You can also pass a plain `dict` (or anything with `.to_dict()`) to
`client.validate_tsc(...)` for full control of the [Typed Security Context schema](https://github.com/Shxnque/quesen/tree/main/docs/security-context).

Runnable demos: [`examples/agent_firewall.py`](examples/agent_firewall.py) (pure SDK)
and [`examples/langchain_firewall.py`](examples/langchain_firewall.py) (LangChain tool wrapper).

Async is symmetric — `await AsyncQuesenClient(...).validate_tsc(ctx)`.

## Receipt provenance (v1.10, tracked in SDK v0.2.0)

Every `ValidateResult` and `SimulateResult.baseline` / `.simulated` now carries
two additional fields that make the verdict **self-contained-replayable**:

- **`input_snapshot_hash`** · lowercase 64-char SHA-256 hex over canonical-JSON
  of the received request payload, with `client_request_id` excluded from the
  hash material. Hash the same payload client-side and prove the engine
  evaluated the exact input you sent.
- **`commit_sha`** · 40-char lowercase git SHA of `Shxnque/quesen` HEAD live at
  build time, or the sentinel `"unknown"` when running detached HEAD or a
  locally-built artifact. Pins the exact ruleset that produced the verdict.

### Client-side hash reconstruction

```python
import hashlib, json

def input_snapshot_hash(payload: dict) -> str:
    to_hash = {k: v for k, v in payload.items()
               if v is not None and k != "client_request_id"}
    canonical = json.dumps(to_hash, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

assert result.input_snapshot_hash == input_snapshot_hash({
    "domain_age_days": 1,
    "engagement_ratio": 0.95,
    "scam_keyword_count": 4,
})
```

### Replay recipe

```bash
git clone https://github.com/Shxnque/quesen && cd quesen
git checkout $COMMIT_SHA
pytest tests -q       # asserts engine state at decision time
# Re-issue the request; verify input_snapshot_hash matches.
```

**Backward compatibility.** Against a pre-v1.10 engine the two fields default
to the empty string. Callers who upgrade the SDK against an older engine
continue to work unchanged; callers who upgrade the engine start seeing
non-empty values automatically.

---

## Async usage

```python
import asyncio
from quesen_sdk import AsyncQuesenClient

async def main() -> None:
    async with AsyncQuesenClient(base_url="https://web-production-aa5ba.up.railway.app") as q:
        await q.create_sandbox_key()   # free key (or pass api_key="sk_live_..." above)
        decision = await q.validate(domain_age_days=200, engagement_ratio=0.3)
        if decision.decision == "SKIP":
            return  # don't act
        # ... execute the action ...
        await q.report(request_id=decision.request_id, outcome="OK", realized_pnl=0.42)

asyncio.run(main())
```

---

## What the client gives you

- **Typed request + response models** (dataclass-like, `__slots__`, IDE-friendly attrs).
- **Automatic retries** with exponential back-off on 5xx / network errors.
- **`request_id` propagation** — the UUID emitted by `/validate` is what you pass to `/report`.
- **`X-Request-ID` header** — set once, echoed everywhere, useful for tracing across your stack.
- **`/simulate` helper** for the free counterfactual sales asset.
- **Receipt provenance surfaced as typed fields** — `input_snapshot_hash` + `commit_sha` are first-class attributes on `ValidateResult` (v0.2.0+).
- **Fail-closed policy** — timeouts / network errors surface as `QuesenTimeout` and `QuesenTransportError` so the caller can decide (recommendation: treat as `SKIP`).
- **Zero heavy dependencies** — just `httpx`.

---

## API surface

Sync client: `QuesenClient(base_url, api_key=None, timeout=5.0, retries=2, retry_backoff=0.2, request_id_header="X-Request-ID", user_agent="quesen-sdk-py/0.4.1")`

| Method | Wraps | Purpose |
|---|---|---|
| `client.create_sandbox_key()` | `POST /sandbox/keys` | Self-serve a FREE sandbox key (no signup); auto-applied to the client. |
| `client.validate_tsc(ctx)` | `POST /tsc/validate` | **Agent firewall** — PASS/REVIEW/BLOCK/SKIP + audit receipt. |
| `client.health()` | `GET /health` | Liveness. |
| `client.version()` | `GET /version` | Engine + weights + thresholds. |
| `client.validate(...)` | `POST /validate` | Deterministic decision. Response carries `input_snapshot_hash` + `commit_sha` against v1.10+ engines. |
| `client.simulate(...)` | `POST /simulate` | Counterfactual with `weights_override` / `thresholds_override`. |
| `client.report(...)` | `POST /report` | Post-decision outcome feedback. v1.1.0 optional fields supported. |

Async client: `AsyncQuesenClient(...)` mirrors the sync surface with `async def` methods.

---

## Error hierarchy

```
QuesenError
├── QuesenAuthError        # 401 — invalid or missing X-API-Key
├── QuesenRateLimitError   # 429 — per-key quota exceeded, Retry-After surfaced
├── QuesenValidationError  # 422 — pydantic-side reject
├── QuesenServerError      # 5xx after retries exhausted
├── QuesenTimeout          # transport timeout
└── QuesenTransportError   # generic transport failure
```

---

## Environment variables

| Var | Meaning |
|---|---|
| `QUESEN_BASE_URL` | Optional default base URL if not passed to the client constructor. |
| `QUESEN_API_KEY` | Optional default API key if not passed to the client constructor. |

---

## Doctrine compliance

This SDK preserves Quesen doctrine end-to-end:

- **Determinism.** The SDK does not add ML, prompts, randomness, or state. Same input in → same input out.
- **Ecosystem neutrality.** No chain lock-in, no framework lock-in, no LLM lock-in. `httpx` only.
- **Fail-closed.** Timeouts and network errors surface as exceptions. Callers should treat them as `SKIP`.
- **Request-ID propagation.** Every call sets `X-Request-ID` so your `/report` calls are correlatable to the original `/validate`.
- **Receipt provenance forwarded.** `input_snapshot_hash` + `commit_sha` are exposed as typed fields (v0.2.0+), enabling client-side replay-verification and ruleset-pin discipline.

---

## License

MIT.

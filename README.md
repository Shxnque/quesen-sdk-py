# Quesen Python SDK

> Official typed Python client for [Quesen](https://senueren.co.za/quesen) — the deterministic A2A risk-evaluation API.

**Status:** v0.2.0 · tracks Quesen engine v1.10.0 · backward compatible with v1.0.0+ deployments.
**Developer portal:** [`senueren.co.za/quesen`](https://senueren.co.za/quesen) — canonical docs, API reference, and integration guides. This SDK is a thin HTTP client; the engine is served at `https://web-production-30ab5.up.railway.app`.

---

## Install

```bash
pip install quesen-sdk
```

Python 3.9+, single runtime dependency (`httpx`).

---

## 30-second usage

```python
from quesen_sdk import QuesenClient

client = QuesenClient(
    base_url="https://<your-quesen-endpoint>",
    api_key="sk_live_abc",  # optional if the deployment is in open mode
)

result = client.validate(
    domain_age_days=1,
    engagement_ratio=0.95,
    scam_keyword_count=4,
)

print(result.decision)              # 'SKIP'
print(result.risk_score)            # 1.0
print(result.conflict_triggers)     # ['New domain (<=30d) + unusually high engagement (>=0.50)', ...]
print(result.request_id)            # UUID — pass to client.report() later
print(result.input_snapshot_hash)   # 64-char SHA-256 hex — self-contained replay primitive (v1.10+)
print(result.commit_sha)            # 40-char git SHA of the engine ruleset that produced the verdict (v1.10+)
```

---

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
    async with AsyncQuesenClient(base_url="https://q.example.com", api_key="sk_live_abc") as q:
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

Sync client: `QuesenClient(base_url, api_key=None, timeout=5.0, retries=2, retry_backoff=0.2, request_id_header="X-Request-ID", user_agent="quesen-sdk-py/0.2.0")`

| Method | Wraps | Purpose |
|---|---|---|
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

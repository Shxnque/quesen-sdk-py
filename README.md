# Quesen Python SDK

> Official typed Python client for [Quesen-SIB](https://github.com/Shxnque/Quesen-sib) — the deterministic A2A risk-evaluation API.

**Status:** v0.1.0 · tracks Quesen engine v1.3.0 · backward compatible with v1.0.0+ deployments.
**Governance:** [`Shxnque/Quesen-sib` DOCTRINE.md](https://github.com/Shxnque/Quesen-sib/blob/main/DOCTRINE.md) is the source of truth. This SDK is a friction reducer; every operational rule lives in the parent repo.

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

print(result.decision)          # 'SKIP'
print(result.risk_score)        # 1.0
print(result.conflict_triggers) # ['New domain (<=30d) + unusually high engagement (>=0.50)', ...]
print(result.request_id)        # UUID — pass to client.report() later
```

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
- **Fail-closed policy** — timeouts / network errors surface as `QuesenTimeout` and `QuesenTransportError` so the caller can decide (recommendation: treat as `SKIP`).
- **Zero heavy dependencies** — just `httpx`.

---

## API surface

Sync client: `QuesenClient(base_url, api_key=None, timeout=5.0, retries=2, retry_backoff=0.2, request_id_header="X-Request-ID", user_agent="quesen-sdk-py/0.1.0")`

| Method | Wraps | Purpose |
|---|---|---|
| `client.health()` | `GET /health` | Liveness. |
| `client.version()` | `GET /version` | Engine + weights + thresholds. |
| `client.validate(...)` | `POST /validate` | Deterministic decision. |
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

---

## License

MIT — same as the parent repository.

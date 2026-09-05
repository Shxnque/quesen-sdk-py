"""
Offline verdict replay — recompute a Quesen decision locally, with zero network.

This is the SDK-level answer to BEA criticism-ledger C-003 / C-004 ("recomputability
before adoption"): instead of trusting a hosted, closed-ruleset engine, a consumer can
recompute the TSC v2 egress/authority verdict on their own machine and compare it to the
receipt the engine returned.

    from quesen_sdk import replay, QuesenFirewall

    fw = QuesenFirewall.sandbox("https://<engine>")
    ctx = ... # a TscContext or raw dict
    local = replay(ctx)                       # {ok, decision, reason_codes, input_snapshot_hash, ...}

Or, to assert a live receipt is independently reproducible:

    from quesen_sdk import verify_receipt
    d = fw.check(action="send_data", target="https://x", data_class="secret")
    v = verify_receipt(d, recompute_request=d.raw.get("request") or ctx)
    v.recomputed   # True  -> decision+reasons+hash reproduced offline from the public reference

Honest boundary: reproduces the *contract-level* decision/reasons/hash for the
egress/authority subset, NOT the production risk weighting/thresholds. See README.
"""
from __future__ import annotations

from typing import Any, Dict

from .reference import evaluate

__all__ = ["replay"]


def replay(context: Any) -> Dict[str, Any]:
    """Locally recompute the deterministic verdict for a TSC v2 context — offline.

    ``context`` may be a :class:`~quesen_sdk.tsc.TscContext` (its ``to_dict()`` is used)
    or a raw context dict. Returns a dict with ``ok`` plus, on success,
    ``{decision, reason_codes, reasons, input_snapshot_hash, risk_score, confidence,
    tags}``; on malformed input, ``{ok: False, error: {code, message, pointer}}``.
    Never raises on malformed input. No network, standard library only.
    """
    if hasattr(context, "to_dict"):
        context = context.to_dict()
    ok, res = evaluate(context)
    return {"ok": ok, **res}

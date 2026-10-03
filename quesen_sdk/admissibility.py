"""
Admissibility — constraint-bound authority (ADR-052, Directive §9/§6). Client-side mirror of
the engine `quesen.evidence.admissibility` module.

A Quesen authorization grants a BOUNDED authority (a set of constraints). This module lets a
caller independently decide whether a SPECIFIC proposed action is admissible within that grant
— e.g. a grant for `payment.execute <= 5000.00 USDC to vendor-a` makes an `8000 USDC to
vendor-b` action INADMISSIBLE. A matching authorization receipt alone never implies the action
was within scope.

Determinism (§2/§4): stdlib only, no network, no floats in money comparison. Canonical grant
bytes use Rule-A canonical JSON (sorted keys, compact, UTF-8, null-omitted) matching the engine
and the JS SDK byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .execution import action_hash

__all__ = [
    "GRANT_FIELDS",
    "canonical_grant_bytes",
    "grant_hash",
    "AdmissibilityResult",
    "check_admissibility",
    "admissibility_evidence",
]

GRANT_FIELDS = (
    "allowed_actions",
    "allowed_targets",
    "allowed_currencies",
    "max_amount",
    "max_qty",
)

_DECIMAL_RE = re.compile(r"^\d+(\.\d+)?$")


def _rule_a(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_grant_bytes(grant: Mapping[str, Any]) -> bytes:
    payload = {k: v for k, v in grant.items() if v is not None}
    return _rule_a(payload)


def grant_hash(grant: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_grant_bytes(grant)).hexdigest()


def _to_decimal_str(v: Any) -> Optional[str]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str) and _DECIMAL_RE.match(v):
        return v
    return None


def _norm_decimal(s: str) -> Tuple[str, str]:
    if "." in s:
        i, f = s.split(".", 1)
    else:
        i, f = s, ""
    i = i.lstrip("0") or "0"
    f = f.rstrip("0")
    return i, f


def _cmp_decimal(a: str, b: str) -> int:
    ai, af = _norm_decimal(a)
    bi, bf = _norm_decimal(b)
    if len(ai) != len(bi):
        return -1 if len(ai) < len(bi) else 1
    if ai != bi:
        return -1 if ai < bi else 1
    width = max(len(af), len(bf))
    af = af.ljust(width, "0")
    bf = bf.ljust(width, "0")
    if af == bf:
        return 0
    return -1 if af < bf else 1


@dataclass(frozen=True)
class AdmissibilityResult:
    admissible: bool
    violations: Tuple[str, ...]
    grant_hash: str
    action_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "admissible": self.admissible,
            "violations": list(self.violations),
            "grant_hash": self.grant_hash,
            "action_hash": self.action_hash,
        }


def check_admissibility(grant: Mapping[str, Any], action: Mapping[str, Any]) -> AdmissibilityResult:
    """Deterministic, fail-closed admissibility check. Mirrors quesen.evidence.admissibility."""
    params = action.get("parameters") or {}
    act = action.get("action")
    tgt = action.get("target")
    amount = params.get("amount")
    currency = params.get("currency")
    qty = params.get("qty")

    v: List[str] = []

    if grant.get("allowed_actions") is not None:
        if act not in grant["allowed_actions"]:
            v.append("ACTION_NOT_ALLOWED")
    if grant.get("allowed_targets") is not None:
        if tgt not in grant["allowed_targets"]:
            v.append("TARGET_NOT_ALLOWED")
    if grant.get("allowed_currencies") is not None:
        if currency is None:
            v.append("CURRENCY_REQUIRED")
        elif currency not in grant["allowed_currencies"]:
            v.append("CURRENCY_NOT_ALLOWED")
    if grant.get("max_amount") is not None:
        if amount is None:
            v.append("AMOUNT_REQUIRED")
        else:
            a = _to_decimal_str(amount)
            cap = _to_decimal_str(grant["max_amount"])
            if a is None or cap is None:
                v.append("AMOUNT_MALFORMED")
            elif _cmp_decimal(a, cap) > 0:
                v.append("AMOUNT_EXCEEDS_MAX")
    if grant.get("max_qty") is not None:
        if qty is None:
            v.append("QTY_REQUIRED")
        elif isinstance(qty, bool) or not isinstance(qty, int):
            v.append("QTY_MALFORMED")
        elif qty > grant["max_qty"]:
            v.append("QTY_EXCEEDS_MAX")

    violations = tuple(sorted(set(v)))
    return AdmissibilityResult(
        admissible=len(violations) == 0,
        violations=violations,
        grant_hash=grant_hash(grant),
        action_hash=action_hash(action),
    )


def admissibility_evidence(
    receipt: Mapping[str, Any],
    grant: Mapping[str, Any],
    action: Mapping[str, Any],
) -> Dict[str, Any]:
    r = check_admissibility(grant, action)
    return {
        "authorization_input_snapshot_hash": receipt.get("input_snapshot_hash"),
        "authorization_decision": receipt.get("decision"),
        "grant_hash": r.grant_hash,
        "execution_binding": r.action_hash,
        "admissible": r.admissible,
        "violations": list(r.violations),
    }

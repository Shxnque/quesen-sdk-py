"""
Execution binding & evidence — client-side mirror of the engine `quesen.evidence` module
(Quesen Upgrade P1a, Directive §6). Lets a caller independently (a) compute the canonical
action hash, and (b) verify that an ExecutionEvidence is bound to the exact action + the
authorization receipt — proving 'Quesen approved X but the system executed Y' cannot pass
unnoticed. A PASS receipt alone NEVER implies execution.

Determinism (§2): stdlib only, no network. Canonical bytes use Rule-A canonical JSON
(sorted keys, compact, UTF-8, null-omitted) matching the engine + the JS SDK byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

__all__ = [
    "canonical_action_bytes",
    "action_hash",
    "BindingVerification",
    "verify_execution_binding",
]

_ACTION_FIELDS = ("subject", "action", "target", "parameters")


def _rule_a(obj: Any) -> bytes:
    """Rule-A canonical JSON: recursive key-sort, compact, UTF-8, no NaN. Matches
    `quesen.asp.signing.canonical_json` (engine) and the JS SDK canonicalizer."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_action_bytes(action: Mapping[str, Any]) -> bytes:
    payload = {k: action[k] for k in _ACTION_FIELDS if k in action and action[k] is not None}
    return _rule_a(payload)


def action_hash(action: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_action_bytes(action)).hexdigest()


@dataclass(frozen=True)
class BindingVerification:
    ok: bool
    bound: bool
    linked: bool
    reason: str


def verify_execution_binding(
    receipt: Mapping[str, Any],
    action: Mapping[str, Any],
    execution_evidence: Any,
) -> BindingVerification:
    """Independently verify an ExecutionEvidence is bound to THIS action + authorization.
    Proves linkage/integrity only — not that execution truly occurred."""
    ev = execution_evidence.to_dict() if hasattr(execution_evidence, "to_dict") else dict(execution_evidence)
    expected = action_hash(action)
    bound = ev.get("execution_binding") == expected
    auth_snap = receipt.get("input_snapshot_hash")
    linked = (ev.get("authorization_input_snapshot_hash") == auth_snap) if auth_snap else False

    if not bound:
        return BindingVerification(False, False, linked,
                                   "execution_binding does not match the recomputed action hash — "
                                   "authorized action != executed action")
    if auth_snap and not linked:
        return BindingVerification(False, True, False,
                                   "binding matches the action but evidence is not linked to this "
                                   "authorization (input_snapshot_hash mismatch)")
    return BindingVerification(True, True, linked,
                               "execution evidence is bound to this action and authorization")

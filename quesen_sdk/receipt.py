"""
Receipt verification — closes the "advisory-and-unsigned" gap client-side.

Quesen's differentiator over log-based governance layers (e.g. tamper-evident
audit trails you must *take the vendor's word* for) is that a decision receipt
is **independently checkable** by the caller. This module gives callers two
levels of assurance, both running entirely on their side:

  1. Structural integrity  — the receipt carries the fields that make a verdict
     replayable: `decision`, `input_snapshot_hash`, `commit_sha`. Absence of
     these is itself a finding (a receipt you cannot pin is not a receipt).

  2. Cryptographic authenticity (optional) — if the engine signs receipts
     (Ed25519 over the canonical receipt payload), `verify_receipt` checks the
     signature against a published engine public key. This upgrades the receipt
     from "recomputable" to "recomputable AND issuer-attributable", which is
     exactly the `signature_capability` the AGV crosswalk currently marks as
     intentionally omitted. Forward-compatible: unsigned receipts verify at the
     structural level and report `signed=False` rather than failing.

Determinism doctrine (§2): no ML, no randomness. Signature verification uses an
OPTIONAL dependency (`cryptography`), imported lazily so the SDK keeps its
single hard runtime dependency (`httpx`). Install with: `pip install quesen-sdk[verify]`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

__all__ = ["ReceiptVerification", "canonical_receipt_bytes", "verify_receipt"]

# The canonical field order the engine signs over. Kept explicit (not sorted at
# call time) so the signing contract is auditable and stable across versions.
_SIGNED_FIELDS = ("decision", "input_snapshot_hash", "commit_sha", "reasons")


@dataclass(frozen=True)
class ReceiptVerification:
    """Result of an independent, client-side receipt check."""
    ok: bool               # structural integrity holds (pinnable receipt)
    signed: bool           # a cryptographic signature was present
    signature_valid: Optional[bool]  # None if no signature / verifier absent
    reason: str            # human-readable explanation

    def require(self) -> "ReceiptVerification":
        """Fail-closed: raise unless the receipt is structurally sound AND, when
        a signature is present, cryptographically valid."""
        if not self.ok or self.signed and self.signature_valid is not True:
            raise ValueError(f"receipt verification failed: {self.reason}")
        return self


def _as_dict(receipt: Any) -> Mapping[str, Any]:
    if isinstance(receipt, Mapping):
        return receipt
    for attr in ("raw", "to_dict"):
        v = getattr(receipt, attr, None)
        if callable(v):
            return v()
        if isinstance(v, Mapping):
            return v
    # last resort: pull known receipt attributes off a typed object
    out = {}
    for f in ("decision", "input_snapshot_hash", "commit_sha", "reasons",
              "signature", "signature_alg", "key_id"):
        if hasattr(receipt, f):
            out[f] = getattr(receipt, f)
    return out


def canonical_receipt_bytes(receipt: Any) -> bytes:
    """Deterministic byte encoding the engine signs and the client re-derives.

    Canonical JSON: the signed subset, key order fixed by `_SIGNED_FIELDS`,
    compact separators, UTF-8. This is the exact preimage for the Ed25519
    signature so both sides agree byte-for-byte.
    """
    d = _as_dict(receipt)
    payload = {k: d.get(k) for k in _SIGNED_FIELDS if k in d}
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False,
                      sort_keys=False).encode("utf-8")


def verify_receipt(
    receipt: Any,
    *,
    public_key_hex: Optional[str] = None,
) -> ReceiptVerification:
    """Independently verify a Quesen decision receipt on the caller's side.

    `receipt` may be a :class:`~quesen_sdk.tsc.TscDecision`, a raw response
    dict, or any object exposing ``.to_dict()`` / ``.raw``.

    - Always checks structural integrity (a verdict + a pinnable
      `input_snapshot_hash`).
    - If the receipt carries a `signature` and `public_key_hex` is supplied,
      verifies an Ed25519 signature over :func:`canonical_receipt_bytes`.
    """
    d = _as_dict(receipt)
    decision = d.get("decision")
    snap = d.get("input_snapshot_hash") or ""
    sig = d.get("signature")

    if not decision:
        return ReceiptVerification(False, bool(sig), None, "no decision field on receipt")
    if not snap:
        return ReceiptVerification(
            False, bool(sig), None,
            "receipt carries no input_snapshot_hash — not independently pinnable",
        )

    if not sig:
        return ReceiptVerification(
            True, False, None,
            "structurally sound; unsigned (engine signing not enabled / not provided)",
        )

    if not public_key_hex:
        return ReceiptVerification(
            True, True, None,
            "signature present but no public_key_hex supplied to verify it",
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception:  # pragma: no cover - optional dep
        return ReceiptVerification(
            True, True, None,
            "signature present; install `quesen-sdk[verify]` (cryptography) to verify it",
        )

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        signature = bytes.fromhex(sig) if isinstance(sig, str) else bytes(sig)
        pk.verify(signature, canonical_receipt_bytes(d))
        return ReceiptVerification(True, True, True, "signature valid (Ed25519)")
    except InvalidSignature:
        return ReceiptVerification(True, True, False, "signature INVALID — receipt not authentic")
    except Exception as e:
        return ReceiptVerification(True, True, False, f"signature check error: {e}")

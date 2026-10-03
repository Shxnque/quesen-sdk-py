"""
`quesen` CLI — publisher/integration conformance (Quesen Upgrade P2, Directive §16/§17).

Any party shipping a Quesen-compatible integration can run:

    quesen conformance          # prove THIS install speaks the exact evidence contract
    quesen verify receipt.json  # independently verify a decision receipt (structural/signature/replay)
    quesen version              # SDK + contract versions

`conformance` recomputes canonical byte encodings with the SDK's OWN functions and
compares them to embedded, language-neutral golden vectors (the same values the
engine and the JS SDK are tested against). A clean run proves the install is
contract-conformant: canonical_receipt_bytes (Rule-B) and action_hash (Rule-A) are
byte-identical to the Quesen specification. Deterministic exit code: 0 = conformant,
1 = drift, 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .receipt import canonical_receipt_bytes, verify_receipt
from .execution import action_hash
from .admissibility import check_admissibility, grant_hash

# --- Embedded golden vectors (must match conformance/vectors/* and the engine) ----------
# Rule-B: signed receipt preimage {decision,input_snapshot_hash,commit_sha,reasons}, fixed order.
_RECEIPT_VECTORS = [
    {
        "name": "pass_with_reasons",
        "receipt": {
            "decision": "PASS",
            "input_snapshot_hash": "a" * 64,
            "commit_sha": "deadbeef",
            "reasons": [{"code": "OK_LOW_RISK", "severity": "info"}],
            "latency_ms": 12,  # non-signed field MUST be excluded
        },
        "canonical_bytes_utf8": (
            '{"decision":"PASS","input_snapshot_hash":"' + "a" * 64 +
            '","commit_sha":"deadbeef","reasons":[{"code":"OK_LOW_RISK","severity":"info"}]}'
        ),
    },
]
# Rule-A: canonical action hash of {subject,action,target,parameters}.
_ACTION_VECTORS = [
    {
        "name": "buy_order",
        "action": {
            "subject": {"agent_id": "agent-7", "principal": "acme"},
            "action": "payment.execute",
            "target": "https://vendor.example/api",
            "parameters": {"amount": "4812.00", "currency": "USDC", "qty": 17, "vendor": "X"},
        },
        "action_hash": "sha256:fbb2813732aee4cb16896ecd2b16923e8ff0750d1b1418f2fff1b796ae1ed392",
    },
    {
        "name": "send_data",
        "action": {
            "subject": "svc-a",
            "action": "egress.send",
            "target": "https://sink.example",
            "parameters": {"data_class": "secret", "bytes": 2048},
        },
        "action_hash": "sha256:f39e36b3cecfcd047f536542e158469afe35876ffc4d260b9beff8beade4c123",
    },
]

CONTRACT_VERSION = "evidence-contract/v1"

# Rule-A: admissibility (ADR-052) — bounded authority -> is THIS action within scope?
_GRANT_A = {
    "allowed_actions": ["payment.execute"],
    "allowed_targets": ["https://vendor-a.example/api"],
    "allowed_currencies": ["USDC"],
    "max_amount": "5000.00",
}
_ADMISSIBILITY_VECTORS = [
    {
        "name": "within_bounds",
        "grant": _GRANT_A,
        "action": {"action": "payment.execute", "target": "https://vendor-a.example/api",
                   "parameters": {"amount": "4999.99", "currency": "USDC"}},
        "grant_hash": "sha256:54020f407615c26e701d0da64b4464007b620bd3da8d7935633f95fb7d7fd498",
        "admissible": True,
        "violations": [],
    },
    {
        "name": "operator_example_vendor_b_over",
        "grant": _GRANT_A,
        "action": {"action": "payment.execute", "target": "https://vendor-b.example/api",
                   "parameters": {"amount": "8000", "currency": "USDC"}},
        "grant_hash": "sha256:54020f407615c26e701d0da64b4464007b620bd3da8d7935633f95fb7d7fd498",
        "admissible": False,
        "violations": ["AMOUNT_EXCEEDS_MAX", "TARGET_NOT_ALLOWED"],
    },
]


def _cmd_conformance(_: argparse.Namespace) -> int:
    failures = 0
    print(f"Quesen conformance — {CONTRACT_VERSION}")
    print("Rule-B receipt canonicalization:")
    for v in _RECEIPT_VECTORS:
        got = canonical_receipt_bytes(v["receipt"]).decode("utf-8")
        ok = got == v["canonical_bytes_utf8"]
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {v['name']}")
        if not ok:
            print(f"        expected: {v['canonical_bytes_utf8']}")
            print(f"        got:      {got}")
    print("Rule-A action hashing:")
    for v in _ACTION_VECTORS:
        got = action_hash(v["action"])
        ok = got == v["action_hash"]
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {v['name']}")
        if not ok:
            print(f"        expected: {v['action_hash']}")
            print(f"        got:      {got}")
    print("Admissibility (ADR-052) — bounded-authority boundary:")
    for v in _ADMISSIBILITY_VECTORS:
        r = check_admissibility(v["grant"], v["action"])
        ok = (
            r.admissible == v["admissible"]
            and list(r.violations) == v["violations"]
            and grant_hash(v["grant"]) == v["grant_hash"]
        )
        failures += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {v['name']}")
        if not ok:
            print(f"        expected: admissible={v['admissible']} violations={v['violations']}")
            print(f"        got:      admissible={r.admissible} violations={list(r.violations)}")
    if failures:
        print(f"\nNOT CONFORMANT — {failures} vector(s) drifted from the Quesen evidence contract.")
        return 1
    print("\nCONFORMANT — canonical encodings are byte-identical to the Quesen evidence contract.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        with open(args.receipt, encoding="utf-8") as f:
            receipt = json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"error: cannot read receipt JSON: {e}", file=sys.stderr)
        return 2
    result = verify_receipt(receipt, public_key_hex=args.public_key)
    print(json.dumps({
        "ok": result.ok, "signed": result.signed,
        "signature_valid": result.signature_valid, "reason": result.reason,
    }, indent=2))
    return 0 if result.ok and (not result.signed or result.signature_valid is True) else 1


def _cmd_version(_: argparse.Namespace) -> int:
    from . import __version__
    print(json.dumps({"sdk_version": __version__, "contract": CONTRACT_VERSION}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quesen", description="Quesen SDK conformance & verification CLI.")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("conformance", help="prove this install speaks the exact Quesen evidence contract").set_defaults(func=_cmd_conformance)
    pv = sub.add_parser("verify", help="independently verify a decision receipt JSON file")
    pv.add_argument("receipt", help="path to a receipt JSON file")
    pv.add_argument("--public-key", dest="public_key", default=None, help="engine Ed25519 public key (hex) to check the signature")
    pv.set_defaults(func=_cmd_verify)
    sub.add_parser("version", help="print SDK + contract versions").set_defaults(func=_cmd_version)
    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

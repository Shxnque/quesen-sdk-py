"""Tests for client-side receipt verification (enforcement + signed-receipt gaps)."""
from quesen_sdk import verify_receipt, canonical_receipt_bytes, ReceiptVerification


def test_unsigned_receipt_is_structurally_ok():
    r = {"decision": "PASS", "input_snapshot_hash": "a" * 64, "commit_sha": "b" * 40}
    v = verify_receipt(r)
    assert v.ok is True
    assert v.signed is False
    assert v.signature_valid is None
    v.require()  # must not raise


def test_receipt_without_snapshot_hash_is_not_pinnable():
    r = {"decision": "PASS", "commit_sha": "b" * 40}
    v = verify_receipt(r)
    assert v.ok is False
    try:
        v.require()
        assert False, "require() should fail-closed"
    except ValueError:
        pass


def test_canonical_bytes_are_deterministic_and_field_ordered():
    r = {"reasons": ["X"], "commit_sha": "c" * 40,
         "input_snapshot_hash": "d" * 64, "decision": "BLOCK"}
    b1 = canonical_receipt_bytes(r)
    b2 = canonical_receipt_bytes(dict(r))
    assert b1 == b2
    # field order fixed by contract: decision first, reasons last
    assert b1.index(b"decision") < b1.index(b"input_snapshot_hash") < b1.index(b"reasons")


def test_signed_receipt_roundtrips_when_crypto_available():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception:
        return  # optional dep not installed; skip
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes_raw().hex()
    r = {"decision": "PASS", "input_snapshot_hash": "e" * 64, "commit_sha": "f" * 40, "reasons": []}
    sig = sk.sign(canonical_receipt_bytes(r)).hex()
    r["signature"] = sig
    v = verify_receipt(r, public_key_hex=pk_hex)
    assert v.signed is True and v.signature_valid is True
    v.require()
    # tamper -> invalid
    r["decision"] = "BLOCK"
    v2 = verify_receipt(r, public_key_hex=pk_hex)
    assert v2.signature_valid is False

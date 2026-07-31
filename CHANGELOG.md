# Changelog

All notable changes to `quesen-sdk` (Python) will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-07-31 · Receipt provenance (tracks engine v1.10.0)

### Added
- **`ValidateResult.input_snapshot_hash: str`** — lowercase 64-char SHA-256 hex
  over canonical-JSON of the received request payload (with `client_request_id`
  excluded from hash material). Empty string when talking to a pre-v1.10 engine.
- **`ValidateResult.commit_sha: str`** — 40-char lowercase git SHA of the engine
  ruleset live at decision time (or the sentinel `"unknown"`). Empty string
  when talking to a pre-v1.10 engine.
- Client-side hash reconstruction and replay recipe documented in README.

### Changed
- `__version__` bumped `0.1.0` → `0.2.0`.
- `DEFAULT_USER_AGENT` bumped `quesen-sdk-py/0.1.0` → `quesen-sdk-py/0.2.0`.
- README status line: tracks Quesen engine v1.9.0 → v1.10.0.

### Backward compatibility
- Fully additive. Existing callers that never reference the new fields keep
  working unchanged. Against an older engine the fields default to `""`.

### Cross-references
- Engine ADR: `Shxnque/Quesen-sib/enshrine/066-adr-041-receipt-provenance.md`
- Public API contract: https://github.com/Shxnque/quesen/blob/main/docs/api-reference.md#receipt-provenance-v110
- Engine tag: [`v1.10.0-rc1`](https://github.com/Shxnque/quesen)

## [0.1.0] — 2026-07-16 · Initial release
- Sync + async httpx clients.
- Typed response envelopes with `.raw` escape hatch.
- 15/15 tests green.

[0.2.0]: https://github.com/Shxnque/quesen-sdk-py/releases/tag/v0.2.0
[0.1.0]: https://github.com/Shxnque/quesen-sdk-py/releases/tag/v0.1.0

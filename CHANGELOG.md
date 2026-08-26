# Changelog

All notable changes to `quesen-sdk` (Python) will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-08-27 · Frictionless onboarding (self-serve sandbox key)

### Added
- **`QuesenFirewall.sandbox(base_url)`** — zero-config entry point. Mints a FREE
  sandbox API key automatically so a fresh developer goes from `pip install` to a
  real deterministic BLOCK in one call, with no signup, no card, and no
  undocumented key-minting step.
- **`QuesenClient.create_sandbox_key()`** (sync + async) — wraps `POST /sandbox/keys`;
  by default configures the client to use the returned key for subsequent calls.

### Fixed
- **Onboarding blocker**: the documented quickstart previously implied `api_key`
  was optional against the hosted engine, but production requires a key. A fresh
  developer hit `401 unauthorized` on the first firewall call with no in-SDK way
  to obtain a key. The README now shows the true install → key → decision path.
- Corrected `User-Agent` (`quesen-sdk-py/0.3.0` → `0.4.1`) and stale version
  strings in docs.

## [0.4.0] — 2026-08-26 · QuesenFirewall ergonomic wrapper

### Added
- **`QuesenFirewall`** — one-call agent-firewall surface over `validate_tsc`:
  `fw.require_pass(agent=..., action="send_data", target=url, data_class="secret")`
  raises `TscBlocked` on anything but PASS. Friendly `action` aliases route to the
  right TSC builder (egress / payment / tool_call). Also `check()` (raw decision)
  and `allows()` (bool). No new decision logic — the engine stays the sole authority.
- `tests/test_firewall.py` (self-contained, httpx MockTransport).

### Changed
- `__version__` `0.3.0` → `0.4.0`.

### Backward compatibility
- Fully additive; `validate_tsc`, `TscContext`, and all v1 methods unchanged.

## [0.3.0] — 2026-08-26 · TSC v2 agent firewall (tracks engine v1.10.0 + ADR-042)

### Added
- **`client.validate_tsc(context)`** (sync + async) — calls the engine's
  `POST /tsc/validate` route and returns a typed **`TscDecision`**
  (`PASS` / `REVIEW` / `BLOCK` / `SKIP`) with the full audit receipt
  (`risk_score`, `confidence`, `reasons`, `tags`, `engine_version`,
  `commit_sha`, `input_snapshot_hash`, `request_id`).
- **`quesen_sdk.tsc` module**: `TscContext` fluent builder with scenario
  constructors (`data_egress`, `tool_call`, `payment`), `TscDecision` with
  fail-closed predicates (`allowed`, `blocked`, `needs_review`, `skipped`,
  `reason_codes`) and `require_pass()`, `TscReason`, and the `TscBlocked`
  exception carrying the decision.
- Canonical TSC vocabulary constants (decisions, enums) re-exported for
  autocomplete.
- Examples: `examples/agent_firewall.py` (pure SDK) and
  `examples/langchain_firewall.py` (LangChain tool wrapper).
- Self-contained `tests/test_tsc.py` (httpx MockTransport; no live engine).

### Changed
- `__version__` `0.2.0` → `0.3.0`; `DEFAULT_USER_AGENT` → `quesen-sdk-py/0.3.0`.
- README hosted-engine URL corrected from the retired `web-production-30ab5`
  domain to the live `web-production-aa5ba` domain.

### Backward compatibility
- Fully additive. All v1 methods (`validate`, `simulate`, `report`) and their
  return types are unchanged. `validate_tsc` is inert against engines without
  `QUESEN_TSC_V2_ENABLED` (route absent → fail-closed error).

### Cross-references
- Engine ADR: `Shxnque/Quesen-sib/enshrine/…-adr-042-typed-security-context.md`
- TSC schema: https://github.com/Shxnque/quesen/tree/main/docs/security-context

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

# Status — Aegis Vault

> Current: 2026-09-03. Continuation of the security core previously published
> as `nexusgenesis-agent-keys`. The former NexusGenesis L1 chain is archived
> and not part of this repository.

## Active deliverables

| Area | Package / Path | Status |
|---|---|---|
| Security core (PQC keys, custody, takeover) | `packages/agent-keys` (`aegis-vault`) | Stable, 133 tests pass |
| CLI / local MCP | `packages/agent-keys-cli`, `packages/agent-keys-mcp` | Experimental |
| Agent framework | `packages/agent-sdk` (`aegis-agent-sdk`) | Stable, 108 tests pass |
| EVM / Solana / multi-chain adapters | `packages/chain-eth`, `chain-sol`, `chain-adapters` | Stable |
| MCP integration | `mcp-server` (`aegis-agent-mcp`) | Stable, 262 tests pass |

## In flight

- **Phase 2 external audit** of the upper-layer composition (envelope KDF,
  takeover, limits, sessions, multi-chain derivation) — scope spec ready:
  [docs/audit/PHASE2-AUDIT-SCOPE-SPEC.md](docs/audit/PHASE2-AUDIT-SCOPE-SPEC.md).
  Includes 7 pre-audit findings to fix or verify.
- npm republish under the new `aegis-*` names; old `nexusgenesis-*` packages
  to be deprecated with a pointer.

## Known open gaps

See [SECURITY_GAP_ANALYSIS.md](SECURITY_GAP_ANALYSIS.md) (GAP-001 env-based
keys, mTLS coverage). Upper-layer composition is **not yet audited** — do not
represent it as production-ready.

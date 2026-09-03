# Aegis Vault

> **Delegated authorization & key custody for AI agents.** Your agent has a
> wallet — Aegis Vault is the guardrail: post-quantum root identity, tiered
> spend limits, human takeover, session narrowing. **Private keys never leave
> the agent or browser.**

One-line position: the authorization layer **between** EIP-8004 (identity)
and x402 (payments) — how much an agent may spend, which operations need a
human sign-off, and how to take back control when the agent is compromised.

```
EIP-8004  →  who is the agent            (identity)
x402      →  how it pays                 (payments)
Aegis     →  what it is allowed to do    (delegated authorization)
```

## What it does

- **Self-custody**: agent keys are generated on the agent/browser and never leave the caller
- **Post-quantum root**: CRYSTALS-Dilithium2 (NIST FIPS 204) identity
- **Tiered limits**: small amounts auto-approved, medium time-locked (revocable), large require human approval — enforced at the signing layer, not just recorded
- **Human takeover**: mid-operation control-change guard rolls back in-flight spends; 48h policy timelock on policy changes
- **Session narrowing**: derived sessions can only narrow privileges, never widen
- **Multi-chain**: one PQC root derives EVM (secp256k1) and Solana (ed25519) addresses

## Packages

| Package | Purpose |
|---|---|
| `aegis-vault` | Security core: PQC keys, AES-256-GCM envelopes, three-tier derivation, custody, takeover |
| `aegis-vault-cli` | CLI for the core |
| `aegis-vault-mcp` | Local MCP exposure of the core |
| `aegis-agent-sdk` | Agent framework: self-sovereign identity + coordination |
| `aegis-chain-eth` / `aegis-chain-sol` | EVM / Solana adapters derived from the PQC root |
| `aegis-chain-adapters` | One PQC root → addresses on every supported chain |
| `aegis-agent-mcp` | MCP server for Claude Desktop, Cursor, Continue |

## Quickstart

```bash
npm i aegis-vault
```

```js
import { PQCWallet, checkSpendAllowedTiered, createSessionKey } from 'aegis-vault';

const wallet = await PQCWallet.generate();
const envelope = wallet.exportEncrypted('a-strong-passphrase');

// Guardrail before any spend
const decision = checkSpendAllowedTiered(
  { type: 'limit', maxPerTx: '10', maxDaily: '100' },
  { amount: '50', spentToday: '20' }
);
```

## Security posture (honest)

- Underlying crypto (`@noble/post-quantum`) is audited by the Noble team — that audit does **not** cover this repository.
- The upper-layer composition (envelope KDF, takeover state machine, limit enforcement, session narrowing, multi-chain derivation) is **under audit** — see [docs/audit/PHASE2-AUDIT-SCOPE-SPEC.md](docs/audit/PHASE2-AUDIT-SCOPE-SPEC.md). Do not treat it as production-attested until the report is published.
- Known open gaps are tracked in [SECURITY_GAP_ANALYSIS.md](SECURITY_GAP_ANALYSIS.md).

## Documentation

- [STATUS.md](STATUS.md) — current state
- [Security policy](SECURITY.md) / [Audit](SECURITY_AUDIT.md) / [Gap analysis](SECURITY_GAP_ANALYSIS.md) / [Invariants](SECURITY_INVARIANTS.md)
- [Phase 2 audit scope spec](docs/audit/PHASE2-AUDIT-SCOPE-SPEC.md)

## Origin

Aegis Vault continues the security-core work previously published as
`nexusgenesis-agent-keys` (repo: `nexus-genesis/nexusgenesis`). The former
project's independent L1 chain was archived in 2026-09 (zero third-party
users, no economic value); this repository carries forward only the agent
key-custody / authorization layer.

## License

MIT

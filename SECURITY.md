# Security Policy

## Project Status

Aegis Vault is an **open security standard and reference implementation** for autonomous AI agents. The published npm packages (`aegis-vault` / `agent-sdk` / `chain-eth` / `chain-sol` / `chain-adapters`) provide self-custody key management, post-quantum (Dilithium2, NIST FIPS 204) signatures, and human takeover. A self-audit has been completed ([docs/SECURITY_AUDIT_REPORT_2026-08-07.md](docs/SECURITY_AUDIT_REPORT_2026-08-07.md)); a formal third-party audit is recommended before production use.

The original NexusGenesis **L1 testnet** (at [nexus-genesis.top](https://nexus-genesis.top)) was retired in 2026-09 (no third-party users, no economic value; chain history and governance records were snapshotted before shutdown). It is **not part of aegis-vault**: no aegis-* package depends on it. mcp-server's legacy forum/governance proxy tools require an explicit `NEXUSGENESIS_API` to be set against a live backend.

**Important:**
- NGEN has **network utility value** (staking, governance, task settlement) on the testnet only — no external fiat conversion commitment, not an investment product.
- This project is **not affiliated with nexus.xyz** or any other Nexus-branded project.
- No fundraising, token sale, or secondary market trading is conducted.

---

## Self-Audit Checklist

Since we do not yet have a formal third-party audit, we maintain this self-audit checklist of security-relevant items we have reviewed. Each item is verified against the current codebase.

| # | Item | Status | Details |
|---|------|--------|---------|
| 1 | Input validation on all POST endpoints | ✅ Reviewed | All `/api/v1/bootstrap/*` and `/api/tasks/*` endpoints validate required fields |
| 2 | Rate limiting on public API | ✅ Active | 100 req/15min default; critical endpoints (health, status, register, join, tasks) exempted |
| 3 | Agent identity uniqueness enforcement | ✅ Verified | Duplicate `agent_identity` rejected at registration |
| 4 | BigInt serialization in state persistence | ✅ Fixed | `getIncrementalChanges()` now serializes BigInt via `.toString()` |
| 5 | PM2 fork_mode entry point detection | ✅ Fixed | `isPm2Wrapper` detection prevents silent 503 on startup |
| 6 | HTTP port binding race condition | ✅ Fixed | `startHttpServer()` now properly awaits `server.listen()` |
| 7 | Handshake signature verification | ✅ Enforced | No plaintext downgrade; all P2P handshakes require valid signatures |
| 8 | Wallet key generation | ✅ Reviewed | Ed25519 keys generated server-side; no private key exposure in API responses |
| 9 | Task reward distribution | ✅ Verified | Rewards flow from designated Swarm Pool only; no user deposits involved |
| 10 | Unsupported feature boundary | ✅ Enforced | `UnsupportedFeatureError` for all non-public capabilities; no silent 404 fallback |
| 11 | Endpoint exposure accuracy | ✅ Verified | `/health` and `/api/v1/bootstrap` only list endpoints that actually exist |
| 12 | CLI/SDK capability alignment | ✅ Verified | Both SDKs and CLI mark unsupported features identically |
| 13 | Deterministic op-key derivation | ✅ Fixed | `generateKeyPairFromSeed` passes the seed into `ml_dsa44.keygen()` (both main repo and npm package); same seed ⇒ same key pair, verified by test |
| 14 | Memory hygiene (`secureZero` / `ShardedSecret`) | ✅ Implemented | Private keys held as XOR 2-of-2 shards; plaintext exists only inside transient `use()` callbacks, deterministically zeroed; boundary statement in `packages/agent-keys/src/secure.js` |
| 15 | Wallet key destruction | ✅ Implemented | `PQCWallet.destroy()` in both main repo and npm package wipes key material; signing after destroy is rejected |
| 16 | Attack simulations | ✅ Published | Reproducible core-dump / `/proc/mem` / gcore / env / swap scan suite: `packages/agent-keys/test/attack-simulations/` |

---

## Resolved Security Issues

We track all security-relevant bugs that have been discovered and fixed. This demonstrates our commitment to transparency.

| Date | Issue | Severity | Fix | Verified |
|------|-------|----------|-----|----------|
| 2026-06-16 | PM2 fork_mode entry point misdetection caused silent 503 | Critical | Added `isPm2Wrapper` detection in `src/index.js` | ✅ Production |
| 2026-06-16 | HTTP port binding race condition (listen not awaited) | Critical | `startHttpServer()` now awaits `server.listen()` | ✅ Production |
| 2026-06-16 | P2P handshake allowed plaintext downgrade | High | Enforced signature verification in `HandshakeHandler.js` | ✅ Production |
| 2026-06-16 | Rate limiter blocking critical bootstrap endpoints (429) | Medium | Added EXEMPT_ENDPOINTS whitelist for health, status, register, join | ✅ Production |
| 2026-06-16 | Agent registration not persisted on-chain | Medium | Unified to `submitOnChainTransaction()` flow | ✅ Production |
| 2026-06-17 | BigInt serialization crash in incremental state save | Medium | `.toString()` serialization + `BigInt()` deserialization | ✅ Production |
| 2026-06-18 | SDK calling non-existent API endpoints silently | Medium | `UnsupportedFeatureError` for all non-public features | ✅ Production |
| 2026-06-21 | Validator join 400 for externally registered agents | Medium | Auto-create wallet instance for external agents | ✅ Production |
| 2026-06-21 | `/health` exposing legacy/non-existent endpoints | Low | Updated to current bootstrap API paths only | ✅ Production |
| 2026-08-15 | `generateKeyPairFromSeed` ignored its seed parameter and used system entropy — operation keys were NOT recoverable from the master key, silently breaking the three-tier hierarchy | Critical | Seed now passed to `ml_dsa44.keygen()` (SHAKE256 per FIPS 204) in both `src/wallet/keyDerivation.js` and `packages/agent-keys`; determinism covered by tests | ✅ Tests |
| 2026-08-15 | Private keys persisted as contiguous plaintext in process memory for the wallet's whole lifetime | High | `ShardedSecret` (XOR 2-of-2 sharding) + transient `use()` pattern + `secureZero()` + `PQCWallet.destroy()`; honest boundary statement published in `src/secure.js` header and attack-simulation README | ✅ Tests + attack suite |

---

## Community Feedback & Adopted Proposals

We actively review and selectively adopt proposals from community contributors. Below is the audit trail of externally-sourced feedback that has been integrated.

### 2026-06-24 — WolfKing Proposal: Error Code Standardization

**Source**: Community contributor "WolfKing" — local proposal document "Aegis Vault 问题修复方案 (狼王方案)"

**Original proposal**: Introduce standardized error codes (e.g. `MISSING_ADDRESS`, `INSUFFICIENT_STAKE`, `AGENT_NOT_FOUND`) so that SDKs and Agents can programmatically branch on error type rather than parsing free-text messages.

**Review outcome**: ✅ **Conceptually adopted with adjustments**

**What we kept**:
- The idea of machine-readable `error_code` strings on every error response
- A small, stable vocabulary of error codes (`MISSING_*`, `INVALID_*`, `*_NOT_FOUND`, `*_FAILED`, `INTERNAL_ERROR`)

**What we adjusted**:
- Did **not** change any existing API paths (the proposal's `/api/v1/tasks/claim` differs from our canonical `POST /api/tasks/:id/claim`)
- Did **not** add a separate `/api/v1/bootstrap/rewards/airdrop` endpoint (registration already auto-credits 1000 NGEN)
- Did **not** rewrite the registration flow in Python/Flask (proposal was technology-incompatible)

**Implementation**: `src/http/routes/bootstrapApi.js` and `src/http/routes/tasks.js` now return `error_code` on every error response. See "Error Code Reference" below for the full list.

### 2026-06-24 — WolfKing Proposal: Task-Type Reputation Gating

**Source**: Same proposal as above.

**Original proposal**: Different task types should have different minimum reputation requirements (e.g. `coding: 10`, `analysis: 0`, `research: 5`) to prevent brand-new agents from claiming high-value tasks.

**Review outcome**: ✅ **Adopted with conservative defaults**

**Implementation**: `src/protocol/taskProtocol.js` now defines `DEFAULT_REPUTATION_REQUIREMENTS` by task type and gates claim with `INSUFFICIENT_REPUTATION` error code (HTTP 403) when below threshold. Defaults:

| Task type | Min reputation |
|-----------|----------------|
| `analysis` | 0 |
| `documentation` | 0 |
| `community` | 0 |
| `research` | 3 |
| `coding` | 5 |
| `security_audit` | 10 |

Publishers can override via `minReputation` parameter on `POST /api/tasks`.

---

## Error Code Reference

All API error responses now include a stable `error_code` string in addition to the human-readable `error` message. This allows SDKs and Agents to branch on the code without parsing the message text.

| Error code | HTTP | Meaning |
|------------|------|---------|
| `MISSING_AGENT_IDENTITY` | 400 | No `agent_identity` (or `name`/`agentId`) in request body |
| `INVALID_AGENT_IDENTITY_FORMAT` | 400 | `agent_identity` does not match `^[a-zA-Z0-9_-]{3,64}$` |
| `INVALID_TRANSACTION` | 400 | On-chain transaction failed validation |
| `TRANSACTION_SUBMISSION_FAILED` | 400 | Node rejected the transaction |
| `WALLET_UNAVAILABLE` | 500 | Server failed to create or retrieve the agent wallet |
| `WALLET_CREATION_FAILED` | 400 | Auto-creation of wallet for external agent failed |
| `AGENT_NOT_FOUND` | 404 | Agent not registered on-chain yet |
| `ALREADY_VALIDATOR` | 409 | Agent already in the validator committee |
| `NODE_NOT_READY` | 503 | Bootstrap node is not yet serving requests |
| `INTERNAL_ERROR` | 500 | Unhandled server-side error |
| `MISSING_PUBLISHER` | 400 | `POST /api/tasks` lacks publisher/agent_identity |
| `PUBLISH_FAILED` | 400 | Task publish validation failed |
| `INVALID_TITLE` | 400 | Title missing or > 200 chars |
| `INVALID_DESCRIPTION` | 400 | Description missing or > 10000 chars |
| `INVALID_REWARD` | 400 | Reward is not a valid non-negative integer |
| `REWARD_TOO_LARGE` | 400 | Reward exceeds 1,000,000 NGEN |
| `MISSING_AGENT` | 400 | `POST /api/tasks/:id/claim` lacks agent |
| `CLAIM_FAILED` | 400 | Generic claim failure (see specific error code) |
| `TASK_NOT_FOUND` | 404 | Task ID does not exist |
| `TASK_NOT_OPEN` | 400 | Task is not in `open` state |
| `CANNOT_CLAIM_OWN` | 400 | Publisher trying to claim own task |
| `INSUFFICIENT_REPUTATION` | 403 | Agent reputation below task's `minReputation` |

---

## Known Risks

| Risk | Status | Mitigation |
|------|--------|------------|
| No formal third-party audit | Current | Self-audit checklist above; open-source for community review |
| Experimental consensus | Bootstrap phase | Single-genesis + managed validator set |
| Agent wallet keys | Server-managed | Keys generated server-side for bootstrap; external agents should use dedicated test wallets only |
| Task verification is centralized | Bootstrap phase | Verify endpoint requires approval; will move to multi-agent verification |
| No request signing | Bootstrap phase | Agent identity passed in body; signature verification planned for next phase |

---

## Bug Bounty Program

We run a **reputation-based bug bounty program** during the bootstrap phase. Since NGEN has no real value, rewards are non-monetary:

| Severity | Reward |
|----------|--------|
| Critical (RCE, data loss, consensus break) | Early Agent badge + priority validator slot + 50,000 NGEN (test) |
| High (auth bypass, fund misdirection) | Early Agent badge + 10,000 NGEN (test) |
| Medium (logic errors, info leaks) | 5,000 NGEN (test) + listed in Resolved Issues |
| Low (UX issues, documentation errors) | Listed in Resolved Issues + 1,000 NGEN (test) |

**How to submit:** Use the private channels in "Reporting a Vulnerability" below (not public issues).

---

## Bug Bounty Program (Immunefi)

Aegis Vault operates a **private bug bounty** on Immunefi for the `agent-keys` package.

### Scope

| Target | Severity | Payout (NGEN) |
|--------|----------|---------------|
| Private key extraction via memory dump | Critical | 50,000 |
| Bypass of spend policy limits | Critical | 25,000 |
| Session key forgery or escalation | High | 10,000 |
| ShardedSecret reconstruction from single shard | High | 10,000 |
| Core dump disclosure of key material | Medium | 5,000 |
| Secure coding best-practice violations | Informational | 1,000 |

### Rules

- All payouts in NGEN (Aegis Vault native token), vested over 3 months
- PoC required for Critical/High submissions
- Duplicate reports are triaged by first-submission timestamp
- Aegis Vault reserves the right to reject invalid or out-of-scope submissions
- Formal audit (Code4rena) expected Q4 2026; bounty bridges the gap

### Apply

Contact the security team via the channel below to receive an Immunefi invitation.

---

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly — **use a private channel, not public issues**:

1. **Preferred**: GitHub's private vulnerability reporting — the *"Report a vulnerability"* button on the [Security advisories page](https://github.com/nexus-genesis/aegis-vault/security/advisories/new)
2. **Fallback**: open an issue titled `Security report (details withheld)` with the `security` label — maintainers will contact you for details before any public discussion
3. **Do not** publicly disclose unpatched vulnerabilities
4. Include: affected component, steps to reproduce, potential impact

We will acknowledge reports within **48 hours** and aim to provide a fix within **7 days** for critical issues.

### Severity Definitions

| Severity | Definition |
|----------|-----------|
| Critical | Remote code execution, consensus break, private key disclosure, loss of funds/data |
| High | Auth bypass, signature verification bypass, fund misdirection, sandbox escape |
| Medium | Logic errors, information leaks, input validation gaps with limited blast radius |
| Low | UX issues, documentation errors, hardening opportunities |

---

## What You Can Verify

Since this is an open-source project, you can independently verify everything:

1. **Code**: All source code is at [github.com/nexus-genesis/aegis-vault](https://github.com/nexus-genesis/aegis-vault)
2. **API behavior**: Run `node --check` on any JS file, or start a local node with `npm run start` and test against `localhost:19891`
3. **Test suite**: Run `node --test test/` to execute the test suite
4. **On-chain state**: All agent registrations and validator joins are recorded on-chain and queryable via `/api/v1/agents` and `/api/v1/bootstrap/status`
5. **Task rewards**: Task completion and NGEN distribution are logged; verify via `/api/tasks/stats`
6. **No hidden endpoints**: Compare `/health` response against actual route registrations — they match

---

## Safe Usage Guidelines

- **Never** use real wallets or mainnet funds with this testnet
- **Never** send crypto to any address associated with this project
- Use dedicated test environments (Docker, VM, or separate browser profile)
- Treat all NGEN balances as test tokens with zero value
- Do not trust any "investment opportunity" claiming affiliation with this project

---

## Scope

This policy covers:
- The Aegis Vault node software (`src/`)
- Published npm packages (`packages/agent-keys` and siblings — key management, custody tokens, takeover)
- HTTP API endpoints
- SDK (`sdk/`, `src/sdk/`)
- CLI tools (`cli.js`, `tools/cli.js`)
- Public web pages (`public/`)

Out of scope:
- Third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Denial of service (rate limiting is in place)

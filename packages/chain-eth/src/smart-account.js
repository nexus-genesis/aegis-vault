/**
 * aegis-chain-eth — Smart Account (on-chain hard policy layer, P0-5)
 *
 * PURPOSE
 * ───────
 * Implements the ON-CHAIN (unbypassable) enforcement semantics of an agent
 * Smart Account — Layer 5 of the Aegis Vault defense-in-depth model. This is
 * a deterministic, stateful semantics engine that mirrors what an EVM
 * Guardian Contract would enforce on-chain; it can be ported 1:1 to Solidity.
 *
 * WHY THIS LAYER EXISTS
 * ─────────────────────
 *   "Any rule that must still hold after the Agent/SDK is fully compromised
 *    cannot live only in the Agent or SDK."  (whitepaper §10)
 * The SDK signer and the isolated key signer can both be corrupted. This
 * engine is the final Hard Enforcement Layer: it holds its OWN state
 * (sessions, revocation, spent totals, pause/freeze) and re-checks every
 * property from the signed content it verifies — it trusts nothing it is
 * told.
 *
 * INVARIANTS CLOSED HERE (SECURITY_INVARIANTS.md)
 * ───────────────────────────────────────────────
 *   INV-002  Amount binding: every Agent execution must verify the signature
 *            over the DECODABLE payload and the signed amount must equal the
 *            transaction amount (via agent-sdk verifyAgentAssetSignature /
 *            enforceAmountBinding).
 *   INV-003  Bounded sessions: sessions carry an expiry bound into the
 *            signed content; a signature obtained while the session was
 *            valid cannot be replayed after expiry. White-lists (chain /
 *            asset / contract / method / recipient) are re-enforced here,
 *            independent of the SDK.
 *   INV-005  No self-escalation: an Agent CANNOT use its own valid signature
 *            to raise its limits, add owners, upgrade the account, or grant
 *            roles — such actions are rejected on-chain even if signed.
 *   INV-006  Emergency key is brake-only: it can pause / revoke / reduce /
 *            freeze, and CANNOT move assets or escalate privileges.
 *   INV-007  Bounded blast radius: per-tx + per-window cumulative ceilings
 *            plus nonce anti-replay give a quantifiable maximum exposure
 *            (estimateMaxLoss()).
 *
 * STATE (maps to EVM storage slots)
 * ─────────────────────────────────
 *   frozen / paused        account-wide switches
 *   owner / emergencyKey   privileged callers
 *   sessions               session registry (active/revoked)
 *   accountSpent           rolling per-window cumulative spend
 *   sessionLastNonce       anti-replay counter per session
 *
 * THREAT MODEL
 * ────────────
 *   Addressed: fully compromised Agent + SDK + signer process. Attacker can
 *   only submit intents already within a registered session's bounds; cannot
 *   escalate, revoke brakes, bypass limits, or replay after expiry.
 *   Not addressed: compromise of owner/emergency key material (that is the
 *   offline trust domain — M-of-N / governance).
 *
 * CALLER-AUTHENTICATION BOUNDARY
 * ──────────────────────────────
 *   Privileged operations (registerSession / revokeSession / pause / resume /
 *   freeze / unfreeze / emergencyReduceLimit) take a `by` caller identity.
 *   In this engine `by` is trusted input — it maps to `msg.sender` in the
 *   Solidity port, i.e. it must be supplied by the embedding node's
 *   AUTHENTICATED call context (never derived from anything the Agent or the
 *   transaction itself controls). The Agent execution path
 *   (executeFromAgent) does NOT use `by`: it authenticates via the
 *   session-bound public key and the payload signature.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  decodeAssetIntentPayload,
  enforceAmountBinding,
} from 'aegis-agent-sdk';
import {
  hashIntentDigest,
  verifyIntentDigest,
} from './canonical.js';

// ─── Constants ────────────────────────────────────────────────────────────

/** Default rolling window for cumulative spend accounting (24h). */
export const DEFAULT_DAY_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Actions that would escalate an account's own authority. Rejected on-chain
 * EVEN IF the signature is valid and the session whitelist would allow them
 * (INV-005). Matches are case-insensitive; both snake_case and camelCase
 * spellings are covered.
 */
export const SELF_ESCALATION_ACTIONS = new Set([
  // Limits
  'increase_limit', 'increaselimit', 'raise_limit', 'raiselimit',
  'set_max_per_tx', 'setmaxpertx', 'set_max_daily', 'setmaxdaily',
  // Ownership
  'add_owner', 'addowner', 'remove_owner', 'removeowner',
  'transfer_ownership', 'transferownership', 'set_owner', 'setowner',
  'change_owner', 'changeowner',
  // Implementation / upgrade
  'upgrade', 'upgrade_to', 'upgradeto', 'upgrade_and_call', 'upgradeandcall',
  'set_implementation', 'setimplementation', 'set_implementation_code',
  'destroy', 'selfdestruct',
  // Roles / policy / guardians
  'grant_role', 'grantrole', 'revoke_role', 'revokerole', 'add_role', 'addrole',
  'update_policy', 'updatepolicy', 'set_policy', 'setpolicy',
  'set_guardian', 'setguardian', 'remove_guardian', 'removeguardian',
  'change_emergency', 'changeemergency', 'remove_emergency', 'removeemergency',
  'rotate_signer', 'rotatesigner',
  // Delegate / arbitrary call (potential privilege escape)
  'delegate', 'delegatecall', 'execute_delegatecall', 'executedelegatecall',
  'multicall', 'batch',
]);

/**
 * Allowance-surface actions: they create or exercise OUT-OF-BAND spend paths
 * that bypass this account's per-tx / daily ceilings entirely.
 *
 *   approve(spender, N) / permit / setApprovalForAll grant a third party the
 *   right to pull funds LATER via transferFrom — a pull that never passes
 *   through executeFromAgent, so no ceiling, whitelist, or nonce applies to
 *   it. transferFrom itself drains allowances others granted to this account
 *   (funds flow outside this account's own balance accounting).
 *
 * Rejected on-chain EVEN IF the owner's session whitelist names them — until
 * a simulation layer can quantify the granted allowance as potential
 * exposure (see INV-007 "approve(spender, MAX_UINT256)" attack path), the
 * fail-closed posture is total rejection. Owner opt-in + simulation is
 * future work.
 */
export const ALLOWANCE_SURFACE_ACTIONS = new Set([
  'approve', 'approve_and_call', 'approveandcall',
  'permit', 'permit2',
  'set_approval_for_all', 'setapprovalforall',
  'transfer_from', 'transferfrom',
  'increase_allowance', 'increaseallowance', 'increaseapproval',
  'create_allowance', 'createallowance',
]);

/**
 * Normalize an action string for set matching.
 *
 * Export: the Solidity DenyList (contracts/solidity/src/DenyList.sol, generated
 * by scripts/sync-deny-list.mjs) mirrors this exact normalization on-chain, so
 * a casing/separator variant that JS rejects is also rejected by the Smart
 * Account. Keep the two in lock-step — the sync script + deny-list tests
 * enforce it.
 */
export function normalizeAction(action) {
  if (typeof action !== 'string') return '';
  return action.replace(/[\s_-]+/g, '').toLowerCase();
}

/**
 * Smart Account.
 * @param {object} opts
 * @param {string} opts.owner - owner identity (e.g. checksummed address)
 * @param {string} opts.emergencyKey - emergency key identity
 * @param {object} [opts.policy] - account-wide hard limits
 *   { type: 'limit', maxPerTx, maxDaily }
 * @param {number} [opts.dayWindowMs] - cumulative window (default 24h)
 */
export function createSmartAccount({ owner, emergencyKey, policy, dayWindowMs = DEFAULT_DAY_WINDOW_MS } = {}) {
  if (!owner || typeof owner !== 'string') throw new Error('createSmartAccount requires owner');
  if (!emergencyKey || typeof emergencyKey !== 'string') throw new Error('createSmartAccount requires emergencyKey');
  const acctPolicy = validateHardPolicy(policy || { type: 'limit', maxPerTx: '0', maxDaily: '0' });
  if (!acctPolicy.valid) throw new Error(`Invalid account policy: ${acctPolicy.reason}`);

  return new SmartAccount({
    owner,
    emergencyKey,
    policy: acctPolicy.policy,
    dayWindowMs,
  });
}

/** Parse + validate a hard-limit policy; fail-closed on missing ceilings. */
function validateHardPolicy(policy) {
  const p = policy || {};
  const type = p.type === 'unlimited' ? 'unlimited' : 'limit';
  if (type === 'unlimited') {
    return { valid: true, policy: { type: 'unlimited' } };
  }
  const maxPerTx = p.maxPerTx;
  const maxDaily = p.maxDaily;
  if (maxPerTx === undefined || maxPerTx === null || String(maxPerTx).trim() === '') {
    return { valid: false, reason: 'maxPerTx required (fail-closed, INV-007)' };
  }
  if (maxDaily === undefined || maxDaily === null || String(maxDaily).trim() === '') {
    return { valid: false, reason: 'maxDaily required (fail-closed, INV-007)' };
  }
  let perTxBig;
  let dailyBig;
  try {
    perTxBig = BigInt(String(maxPerTx).trim());
    dailyBig = BigInt(String(maxDaily).trim());
    if (perTxBig < 0n || dailyBig < 0n) throw new Error('negative');
  } catch {
    return { valid: false, reason: `invalid ceilings: ${maxPerTx}/${maxDaily}` };
  }
  return {
    valid: true,
    policy: { type: 'limit', maxPerTx: String(perTxBig), maxDaily: String(dailyBig) },
  };
}

export class SmartAccount {
  constructor({ owner, emergencyKey, policy, dayWindowMs }) {
    this.owner = owner;
    this.emergencyKey = emergencyKey;
    this.policy = policy;
    this.dayWindowMs = dayWindowMs;
    this.accountId = keccakAddress(`${owner}/${emergencyKey}`);
    this.frozen = false;
    this.paused = false;
    /** @type {Map<string, object>} sessionId -> session record */
    this.sessions = new Map();
    // Rolling cumulative spend accounting (account-level).
    this.spendWindowStart = null; // ms epoch
    this.spentInWindow = 0n;
    this.executions = 0;
  }

  // ─── State queries ──────────────────────────────────────────────────────

  getState() {
    return {
      accountId: this.accountId,
      owner: this.owner,
      emergencyKey: this.emergencyKey,
      policy: this.policy,
      paused: this.paused,
      frozen: this.frozen,
      activeSessions: [...this.sessions.values()]
        .filter((s) => s.status === 'active' && s.expiresAt > Date.now())
        .map((s) => s.sessionId),
      spentInWindow: String(this.spentInWindow),
      spendWindowStart: this.spendWindowStart,
      executions: this.executions,
    };
  }

  getSession(sessionId) {
    const s = this.sessions.get(sessionId);
    if (!s) return null;
    return {
      ...s,
      agentPublicKey: s.agentPublicKey,
      agentEvmAddress: s.agentEvmAddress,
    };
  }

  /**
   * Quantify the current maximum exposure bound (INV-007). This is the
   * on-chain answer to "what is the worst a compromised agent can do now".
   */
  estimateMaxLoss({ sessionId } = {}) {
    const now = Date.now();
    const acctDaily = this.policy.type === 'unlimited' ? null : BigInt(this.policy.maxDaily);
    const acctRemaining = acctDaily === null ? null : acctDaily - this.spentInWindow;
    const untilWindow = this.spendWindowStart === null
      ? this.dayWindowMs
      : Math.max(0, this.dayWindowMs - (now - this.spendWindowStart));

    let perSession = [];
    for (const s of this.sessions.values()) {
      if (s.status !== 'active' || s.expiresAt <= now) continue;
      const sessionRemainingMs = Math.max(0, s.expiresAt - now);
      const sDaily = s.maxDaily === null ? null : BigInt(s.maxDaily) - s.spent;
      const perTx = s.maxPerTx === null ? null : BigInt(s.maxPerTx);
      // When no money ceiling is configured, exposure is bounded only by the
      // session time window.
      const boundedByTime = acctRemaining === null && sDaily === null;
      // Cumulative window exposure is bounded by the DAILY ceilings (an agent
      // may execute many per-tx-sized transfers until the daily ceiling binds);
      // perTx only bounds a single transfer, so it is reported separately and
      // NOT mixed into the window ceiling.
      let bound = [];
      if (acctRemaining !== null) bound.push(acctRemaining);
      if (sDaily !== null) bound.push(sDaily);
      const ceiling = bound.length ? bound.reduce((a, b) => (a < b ? a : b)) : null;
      perSession.push({
        sessionId: s.sessionId,
        agentId: s.agentId,
        expiresAt: s.expiresAt,
        remainingSessionMs: sessionRemainingMs,
        remainingDaily: sDaily === null ? null : String(sDaily),
        remainingAccountDaily: acctRemaining === null ? null : String(acctRemaining),
        perTx: perTx === null ? null : String(perTx),
        maxLossCeiling: ceiling === null ? null : String(ceiling),
        boundedByTime: boundedByTime || null,
      });
    }

    return {
      accountId: this.accountId,
      now,
      windowEndsAt: this.spendWindowStart === null ? null : this.spendWindowStart + this.dayWindowMs,
      windowRemainingMs: untilWindow,
      spentInWindow: String(this.spentInWindow),
      accountDailyRemaining: acctRemaining === null ? null : String(acctRemaining),
      sessions: perSession,
      // Human-readable worst-case statement.
      maxLossStatement: perSession.length
        ? perSession.map((s) =>
            `session ${s.sessionId}: max ${s.maxLossCeiling ?? `unbounded until ${new Date(s.expiresAt).toISOString()}`}`
          ).join('; ')
        : 'no active sessions',
    };
  }

  // ─── Owner / privileged operations ──────────────────────────────────────

  /**
   * Register a session for an agent. ONLY the owner may do this — an Agent
   * cannot grant itself authority (INV-005). Hard ceilings are mandatory
   * (fail-closed, INV-007).
   *
   * @param {object} opts
   * @param {string} opts.by - caller identity; must equal account owner
   * @param {string} opts.sessionId - unique session id
   * @param {string} opts.agentId - agent identifier
   * @param {string|Buffer} [opts.agentPublicKey] - agent's PQC public key used
   *   to verify PQC/JSON asset signatures (the engine trusts THIS, never a
   *   caller-supplied key)
   * @param {string} [opts.agentEvmAddress] - agent's EVM address used to
   *   verify canonical digest signatures (Solidity parity path)
   * @param {string|number} opts.issuedAt - ms epoch
   * @param {string|number} opts.expiresAt - ms epoch (mandatory)
   * @param {object} [opts.whitelist] - { allowedChains?, allowedAssets?,
   *   allowedContracts?, allowedMethods?, allowedRecipients? }
   * @param {string|number} [opts.maxPerTx] - session per-tx ceiling
   * @param {string|number} [opts.maxDaily] - session cumulative ceiling
   */
  registerSession({ by, sessionId, agentId, agentPublicKey, agentEvmAddress, issuedAt, expiresAt, whitelist, maxPerTx, maxDaily }) {
    if (by !== this.owner) {
      return { ok: false, reason: 'registerSession: only the account owner may register a session (INV-005)' };
    }
    if (!sessionId || typeof sessionId !== 'string') return { ok: false, reason: 'sessionId required' };
    if (this.sessions.has(sessionId)) return { ok: false, reason: `session ${sessionId} already exists` };
    if (!agentId || typeof agentId !== 'string') return { ok: false, reason: 'agentId required' };
    if (!agentPublicKey && !agentEvmAddress) {
      return { ok: false, reason: 'agentPublicKey or agentEvmAddress required' };
    }
    const issued = Number(issuedAt);
    const expires = Number(expiresAt);
    if (!Number.isFinite(issued) || issued <= 0) return { ok: false, reason: 'invalid issuedAt' };
    if (!Number.isFinite(expires) || expires <= issued) return { ok: false, reason: 'invalid expiresAt (must be > issuedAt)' };
    if (expires <= Date.now()) return { ok: false, reason: 'session already expired' };

    // Hard ceilings are mandatory (INV-007).
    const ceilings = validateHardPolicy({ type: 'limit', maxPerTx, maxDaily });
    if (!ceilings.valid) return { ok: false, reason: `invalid session ceilings: ${ceilings.reason}` };
    const sessPolicy = ceilings.policy;

    this.sessions.set(sessionId, {
      sessionId,
      agentId,
      agentPublicKey: agentPublicKey
        ? (typeof agentPublicKey === 'string' ? agentPublicKey : Buffer.from(agentPublicKey).toString('hex'))
        : null,
      agentEvmAddress: agentEvmAddress || null,
      issuedAt: issued,
      expiresAt: expires,
      whitelist: normalizeWhitelist(whitelist),
      maxPerTx: sessPolicy.type === 'unlimited' ? null : sessPolicy.maxPerTx,
      maxDaily: sessPolicy.type === 'unlimited' ? null : sessPolicy.maxDaily,
      status: 'active',
      lastNonce: 0n,
      spent: 0n,
    });
    return { ok: true, sessionId };
  }

  /**
   * Revoke a session (owner or emergency key). Revocation is immediate and
   * irreversible by the agent — a revoked session's signatures are rejected
   * on-chain even if they were obtained while valid (INV-003/INV-006).
   */
  revokeSession({ by, sessionId }) {
    if (by !== this.owner && by !== this.emergencyKey) {
      return { ok: false, reason: 'revokeSession: caller is neither owner nor emergency key' };
    }
    const s = this.sessions.get(sessionId);
    if (!s) return { ok: false, reason: `session ${sessionId} not found` };
    s.status = 'revoked';
    return { ok: true, sessionId, revokedBy: by };
  }

  /** Pause agent executions (owner or emergency). Brake-only. */
  pause({ by }) {
    if (by !== this.owner && by !== this.emergencyKey) {
      return { ok: false, reason: 'pause: caller is neither owner nor emergency key' };
    }
    this.paused = true;
    return { ok: true, paused: true };
  }

  /** Resume agent executions. OWNER ONLY (emergency is brake-only, INV-006). */
  resume({ by }) {
    if (by !== this.owner) return { ok: false, reason: 'resume: only the owner may resume (emergency is brake-only, INV-006)' };
    this.paused = false;
    return { ok: true, paused: false };
  }

  /** Freeze the account permanently (emergency only). */
  freeze({ by }) {
    if (by !== this.emergencyKey) return { ok: false, reason: 'freeze: emergency key only (INV-006)' };
    this.frozen = true;
    return { ok: true, frozen: true };
  }

  /** Unfreeze (owner only — emergency cannot unfreeze its own brake). */
  unfreeze({ by }) {
    if (by !== this.owner) return { ok: false, reason: 'unfreeze: only the owner may unfreeze' };
    this.frozen = false;
    return { ok: true, frozen: false };
  }

  /**
   * Emergency reduce-only: lower a session's ceilings. Attempts to RAISE a
   * ceiling are rejected (INV-006, "reduce only").
   */
  emergencyReduceLimit({ by, sessionId, maxPerTx, maxDaily }) {
    if (by !== this.emergencyKey) return { ok: false, reason: 'emergencyReduceLimit: emergency key only (INV-006)' };
    const s = this.sessions.get(sessionId);
    if (!s) return { ok: false, reason: `session ${sessionId} not found` };
    const parseCeiling = (value, label) => {
      try {
        const next = BigInt(String(value).trim());
        if (next < 0n) throw new Error('negative');
        return { ok: true, value: String(next) };
      } catch {
        return { ok: false, reason: `invalid ${label}: ${value}` };
      }
    };
    if (maxPerTx !== undefined && maxPerTx !== null) {
      const parsed = parseCeiling(maxPerTx, 'maxPerTx');
      if (!parsed.ok) return { ok: false, reason: parsed.reason };
      if (BigInt(parsed.value) > BigInt(s.maxPerTx)) {
        return { ok: false, reason: `emergencyReduceLimit cannot RAISE maxPerTx (${s.maxPerTx} → ${maxPerTx}), reduce-only (INV-006)` };
      }
      s.maxPerTx = parsed.value;
    }
    if (maxDaily !== undefined && maxDaily !== null) {
      const parsed = parseCeiling(maxDaily, 'maxDaily');
      if (!parsed.ok) return { ok: false, reason: parsed.reason };
      if (BigInt(parsed.value) > BigInt(s.maxDaily)) {
        return { ok: false, reason: `emergencyReduceLimit cannot RAISE maxDaily (${s.maxDaily} → ${maxDaily}), reduce-only (INV-006)` };
      }
      s.maxDaily = parsed.value;
    }
    return { ok: true, sessionId, maxPerTx: s.maxPerTx, maxDaily: s.maxDaily };
  }

  // ─── Core: Agent execution (the only money-moving path) ─────────────────

  /**
   * Execute an agent asset intent. This is THE unbypassable enforcement
   * point. Every property is re-derived from the signed content; nothing is
   * trusted from the caller except sessionId + nonce bookkeeping.
   *
   * @param {object} opts
   * @param {object} opts.payload - canonical agent asset intent
   * @param {string} opts.signature - signature over JSON.stringify(payload)
   * @param {string|number} opts.claimedAmount - tx amount (from tx object)
   * @param {string} opts.sessionId - registered session id
   * @param {string|number} opts.nonce - strictly increasing anti-replay counter
   * @param {boolean} [opts.preview] - P3 simulation mode: run the full
   *   fail-closed decision tree WITHOUT a signature and WITHOUT mutating
   *   state (nonce/spend/window). Only the digest-binding check (INV-002)
   *   is skipped — it needs the caller's private key — so preview answers
   *   "would this intent be admitted?" as a side-effect-free dry-run.
   * @returns {Promise<{ok: true, ...} | {ok: false, reason: string}>}
   */
  async executeFromAgent({ payload, signature, claimedAmount, sessionId, nonce, preview = false }) {
    const now = Date.now();

    // 1. Account-level switches.
    if (this.frozen) return { ok: false, reason: 'account is frozen (INV-006)' };
    if (this.paused) return { ok: false, reason: 'account is paused (emergency brake, INV-006)' };

    // 2. Session must exist and be active.
    const s = this.sessions.get(sessionId);
    if (!s) return { ok: false, reason: `session ${sessionId} not registered` };
    if (s.status !== 'active') return { ok: false, reason: `session ${sessionId} is ${s.status}` };
    if (s.expiresAt <= now) return { ok: false, reason: `session ${sessionId} expired` };

    // 3. Session-context consistency: the signed payload must be bound to
    //    THIS session (agent, issued, expiry). A payload signed under a
    //    different session (or forged) is rejected.
    if (!payload || typeof payload !== 'object') return { ok: false, reason: 'payload must be an object' };
    if (payload.agentId !== s.agentId) {
      return { ok: false, reason: `payload.agentId=${payload.agentId} does not match session agent ${s.agentId}` };
    }
    if (Number(payload.sessionIssuedAt) !== s.issuedAt) {
      return { ok: false, reason: 'payload.sessionIssuedAt does not match the registered session' };
    }
    if (Number(payload.sessionExpiresAt) !== s.expiresAt) {
      return { ok: false, reason: 'payload.sessionExpiresAt does not match the registered session' };
    }

    // 4. INV-005 + INV-007: no self-escalation and no allowance-surface
    //    actions, enforced on-chain even with a valid sig and even if the
    //    owner's whitelist names them. BOTH the action and the method are
    //    checked — a payload like {action:'transfer', method:'approve'} must
    //    not slip through either set.
    const actionNorm = normalizeAction(payload.action);
    const methodNorm = normalizeAction(payload.method);
    if (SELF_ESCALATION_ACTIONS.has(actionNorm) || SELF_ESCALATION_ACTIONS.has(methodNorm)) {
      return { ok: false, reason: `action "${payload.action}" / method "${payload.method}" is a self-escalation and is rejected on-chain (INV-005)` };
    }
    if (ALLOWANCE_SURFACE_ACTIONS.has(actionNorm) || ALLOWANCE_SURFACE_ACTIONS.has(methodNorm)) {
      return { ok: false, reason: `action "${payload.action}" / method "${payload.method}" touches the allowance surface (out-of-band spend path) and is rejected on-chain (INV-007)` };
    }

    // 5. Whitelist re-enforcement (INV-003, chain-side). Undefined dimensions
    //    are not constrained (owner's choice); defined ones are enforced.
    const wl = s.whitelist;
    if (wl.allowedChains && !wl.allowedChains.includes(payload.chain)) {
      return { ok: false, reason: `chain ${payload.chain} not allowed by session whitelist (INV-003)` };
    }
    if (wl.allowedAssets && !wl.allowedAssets.includes(payload.asset)) {
      return { ok: false, reason: `asset ${payload.asset} not allowed by session whitelist (INV-003)` };
    }
    if (wl.allowedContracts && !wl.allowedContracts.includes(payload.contract)) {
      return { ok: false, reason: `contract ${payload.contract} not allowed by session whitelist (INV-003)` };
    }
    if (wl.allowedMethods && !wl.allowedMethods.includes(payload.method)) {
      return { ok: false, reason: `method ${payload.method} not allowed by session whitelist (INV-003)` };
    }
    if (wl.allowedRecipients && !wl.allowedRecipients.includes(payload.recipient)) {
      return { ok: false, reason: `recipient ${payload.recipient} not allowed by session whitelist (INV-003)` };
    }

    // 6. Nonce anti-replay (INV-007): the nonce MUST be signed into the
    //    payload, making every signature single-use. A captured (payload,
    //    signature) pair cannot be re-executed with a fresh nonce — the
    //    signed payload.nonce pins the exact transaction slot, and
    //    lastNonce pins the ordering. Fail-closed when payload carries no
    //    nonce.
    let nonceBig;
    try {
      nonceBig = BigInt(String(nonce).trim());
      if (nonceBig < 1n) throw new Error('nonce must be ≥ 1');
    } catch {
      return { ok: false, reason: `invalid nonce: ${nonce}` };
    }
    if (payload.nonce === undefined || payload.nonce === null || String(payload.nonce).trim() === '') {
      return { ok: false, reason: 'payload carries no signed nonce — every execution must bind its nonce into the signed content (fail-closed, INV-007)' };
    }
    let payloadNonceBig;
    try {
      payloadNonceBig = BigInt(String(payload.nonce).trim());
    } catch {
      return { ok: false, reason: `invalid signed payload nonce: ${payload.nonce}` };
    }
    if (payloadNonceBig !== nonceBig) {
      return { ok: false, reason: `payload.nonce=${payload.nonce} does not match submitted nonce ${nonce} (signature reuse, INV-007)` };
    }
    if (nonceBig <= s.lastNonce) {
      return { ok: false, reason: `nonce ${nonce} is not greater than last used ${s.lastNonce} (replay, INV-007)` };
    }

    // 7. Signature + amount binding + session expiry (INV-002/INV-003),
    //    enforced with the session-bound public key (never caller-supplied).
    //    NOTE: no spend policy is passed here — enforceAmountBinding's policy
    //    path applies the SDK's three-tier authorization (timelock/approval),
    //    which is Policy-Engine territory. The Smart Account is the HARD LIMIT
    //    layer: it enforces per-tx and cumulative ceilings directly (below),
    //    deterministically and without tiering.
    let amountBig;
    let amount;
    if (preview) {
      // P3 SIMULATION MODE: no signature exists yet, so the digest-binding
      // check (INV-002) is the one check that cannot run without the caller's
      // private key. Everything above (session, whitelist, self-escalation,
      // allowance surface, nonce) already ran fail-closed exactly as on-chain;
      // the amount is taken from claimedAmount so the ceilings below are still
      // enforced. Preview NEVER commits state (see step 10).
      try {
        const claimed = String(claimedAmount).trim();
        if (claimed === '') throw new Error('empty');
        amountBig = BigInt(claimed);
        if (amountBig < 0n) throw new Error('negative');
      } catch {
        return { ok: false, reason: `amount/signature binding failed: invalid claimedAmount: ${claimedAmount} (INV-002)` };
      }
      amount = String(amountBig);
    } else if (s.agentEvmAddress) {
      const decoded = decodeAssetIntentPayload(payload);
      if (!decoded.valid) {
        return { ok: false, reason: `amount/signature binding failed: ${decoded.error} (INV-002)` };
      }
      let claimedBig;
      try {
        const claimed = String(claimedAmount).trim();
        if (claimed === '') throw new Error('empty');
        claimedBig = BigInt(claimed);
        if (claimedBig < 0n) throw new Error('negative');
      } catch {
        return { ok: false, reason: `amount/signature binding failed: invalid claimedAmount: ${claimedAmount} (INV-002)` };
      }
      if (claimedBig !== decoded.amountBig) {
        return {
          ok: false,
          reason: `amount/signature binding failed: amount mismatch: signed payload amount=${decoded.amount}, claimed=${String(claimedBig)} (INV-002)`,
        };
      }
      let digest;
      try {
        digest = hashIntentDigest(payload);
      } catch (err) {
        return { ok: false, reason: `amount/signature binding failed: ${err.message} (INV-002)` };
      }
      if (!verifyIntentDigest(s.agentEvmAddress, digest, signature)) {
        return { ok: false, reason: 'amount/signature binding failed: invalid EVM digest signature (INV-002)' };
      }
      amountBig = decoded.amountBig;
      amount = decoded.amount;
    } else {
      const binding = await enforceAmountBinding({
        payload,
        claimedAmount,
        signature,
        publicKey: s.agentPublicKey,
      });
      if (!binding.valid) {
        return { ok: false, reason: `amount/signature binding failed: ${binding.reason} (INV-002)` };
      }
      amountBig = BigInt(binding.amount);
      amount = binding.amount;
    }

    // 7b. Per-tx hard ceiling (INV-007).
    if (s.maxPerTx !== null && amountBig > BigInt(s.maxPerTx)) {
      return {
        ok: false,
        reason: `exceeds maxPerTx (${s.maxPerTx}): ${amount} (INV-007)`,
      };
    }

    // 8. Account-level cumulative ceiling (INV-007).
    if (this.policy.type !== 'unlimited') {
      const acctDaily = BigInt(this.policy.maxDaily);
      this.rollWindow(now);
      if (this.spentInWindow + amountBig > acctDaily) {
        return {
          ok: false,
          reason: `account daily ceiling exceeded: ${this.spentInWindow} + ${amount} > ${this.policy.maxDaily} (INV-007)`,
        };
      }
    }

    // 9. Session-level cumulative ceiling (INV-007).
    if (s.maxDaily !== null) {
      if (s.spent + amountBig > BigInt(s.maxDaily)) {
        return {
          ok: false,
          reason: `session daily ceiling exceeded: ${String(s.spent)} + ${amount} > ${s.maxDaily} (INV-007)`,
        };
      }
    }

    // 10. Commit: consume nonce, accrue spend, emit execution.
    //     In preview mode, skip ALL state mutation (side-effect-free dry-run).
    if (preview) {
      return {
        ok: true,
        preview: true,
        amount,
        sessionId,
        nonce: String(nonceBig),
        note: 'preview mode — intent is admissible; no state was mutated.',
      };
    }
    s.lastNonce = nonceBig;
    s.spent += amountBig;
    if (this.policy.type !== 'unlimited') this.spentInWindow += amountBig;
    if (this.spendWindowStart === null) this.spendWindowStart = now;
    this.executions += 1;
    const txId = '0x' + Buffer.from(
      keccak_256(Buffer.from(`${sessionId}/${String(nonceBig)}/${JSON.stringify(payload)}`, 'utf8'))
    ).toString('hex');

    const acctRemaining = this.policy.type === 'unlimited'
      ? null
      : String(BigInt(this.policy.maxDaily) - this.spentInWindow);
    const sessRemaining = s.maxDaily === null ? null : String(BigInt(s.maxDaily) - s.spent);
    return {
      ok: true,
      txId,
      amount,
      sessionId,
      nonce: String(nonceBig),
      spentSession: String(s.spent),
      spentAccountWindow: String(this.spentInWindow),
      remainingSessionDaily: sessRemaining,
      remainingAccountDaily: acctRemaining,
      sessionExpiresAt: s.expiresAt,
      windowEndsAt: this.spendWindowStart === null ? null : this.spendWindowStart + this.dayWindowMs,
    };
  }

  // ─── Internal ───────────────────────────────────────────────────────────

  /** Roll the cumulative-spend window forward if it has elapsed. */
  rollWindow(now) {
    if (this.spendWindowStart === null) return;
    if (now - this.spendWindowStart >= this.dayWindowMs) {
      this.spendWindowStart = now;
      this.spentInWindow = 0n;
    }
  }
}

function normalizeWhitelist(whitelist) {
  const w = whitelist || {};
  const arr = (k) => {
    const v = w[k];
    if (v === undefined || v === null) return undefined;
    return Array.isArray(v) ? v : [v];
  };
  return {
    allowedChains: arr('allowedChains'),
    allowedAssets: arr('allowedAssets'),
    allowedContracts: arr('allowedContracts'),
    allowedMethods: arr('allowedMethods'),
    allowedRecipients: arr('allowedRecipients'),
  };
}

/** Deterministic pseudo-address for an account. */
function keccakAddress(seed) {
  return '0x' + Buffer.from(keccak_256(Buffer.from(seed, 'utf8'))).subarray(0, 20).toString('hex');
}

export default {
  createSmartAccount,
  SmartAccount,
  SELF_ESCALATION_ACTIONS,
  ALLOWANCE_SURFACE_ACTIONS,
  DEFAULT_DAY_WINDOW_MS,
};

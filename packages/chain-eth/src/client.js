/**
 * aegis-chain-eth — Smart Account high-level client
 *
 * PURPOSE
 * ───────
 * Sprint 2.2: the OFFICIAL recommended entry point for the Smart Account EVM
 * path. It wraps the low-level pieces (createSmartAccount + canonicalize +
 * signSmartAccountIntent + executeFromAgent) into a single client object, so
 * an embedding node / agent does not have to assemble the flow by hand:
 *
 *     const acct = createSmartAccountClient({ owner, emergencyKey, policy });
 *     const reg = acct.registerSession({ ... session ... });
 *     const res = await acct.execute({
 *         session, intent, privateKeyHex, claimedAmount, nonce,
 *     });
 *
 * Everything that was true for the raw pieces stays true here — fail-closed
 * canonical fields, INV-002/003/005/006/007 enforcement, nonce anti-replay,
 * and the deny-list. This is a thin, safe composition: it adds NO new trust
 * boundaries and cannot be configured to bypass the hard-policy layer.
 *
 * SECURITY
 * ────────
 * - `privateKeyHex` is consumed transiently inside execute(); the client holds
 *   NO key material between calls (INV-001: keys never leave the caller).
 * - Privileged ops (registerSession / revokeSession / pause / freeze) require
 *   `by === owner` (or emergency for brake-only) — identical to the engine.
 */
import { createSmartAccount } from './smart-account.js';
import {
  signSmartAccountIntent,
  verifySmartAccountIntent,
} from './canonical.js';

/**
 * Build a Smart Account client — the recommended EVM execution entry point.
 *
 * @param {object} opts - same shape as createSmartAccount
 * @param {string} opts.owner - owner identity (privileged caller)
 * @param {string} opts.emergencyKey - brake-only emergency identity
 * @param {object} [opts.policy] - { type:'limit', maxPerTx, maxDaily } or unlimited
 * @param {number} [opts.dayWindowMs] - cumulative spend window (default 24h)
 */
export function createSmartAccountClient({ owner, emergencyKey, policy, dayWindowMs } = {}) {
  const account = createSmartAccount({ owner, emergencyKey, policy, dayWindowMs });

  return {
    /** The raw SmartAccount engine (advanced use; most callers won't need it). */
    account,
    owner,

    // ── Privileged session management ─────────────────────────────────────
    registerSession: (opts) => account.registerSession({ by: owner, ...opts }),
    revokeSession: (opts) => account.revokeSession({ by: owner, ...opts }),
    pause: () => account.pause({ by: owner }),
    resume: () => account.resume({ by: owner }),

    // ── Official EVM signing path (signSmartAccountIntent) ────────────────
    /**
     * Prepare a signed EVM asset intent (canonicalize → digest → secp256k1
     * signature). Does NOT execute anything; returns the payload/digest/
     * signature for inspection or external submission.
     */
    prepareIntent({ session, intent, privateKeyHex } = {}) {
      return signSmartAccountIntent({ session, intent, privateKeyHex });
    },

    /**
     * Verify a prepared signature against an EVM address (self-check before
     * submission). Convenience mirror of verifySmartAccountIntent.
     */
    verify({ address, signature, payload, session, intent } = {}) {
      return verifySmartAccountIntent({ address, signature, payload, session, intent });
    },

    /**
     * Full recommended flow: canonicalize + sign + executeFromAgent in one
     * call. The signature is created transiently and consumed immediately;
     * the client retains nothing.
     *
     * @param {object} opts
     * @param {object} opts.session - session token (see signSmartAccountIntent)
     * @param {object} opts.intent - structured asset intent (must include nonce)
     * @param {string|Buffer} opts.privateKeyHex - secp256k1 private key
     * @param {string|number} opts.claimedAmount - tx amount (INV-002 binding)
     * @param {string} opts.sessionId - registered session id
     * @param {string|number} opts.nonce - anti-replay counter
     */
    async execute({ session, intent, privateKeyHex, claimedAmount, sessionId, nonce } = {}) {
      const signed = signSmartAccountIntent({ session, intent, privateKeyHex });
      return account.executeFromAgent({
        payload: signed.payload,
        signature: signed.signature,
        claimedAmount,
        sessionId,
        nonce,
      });
    },

    // ── State / exposure queries ──────────────────────────────────────────
    getState: () => account.getState(),
    getSession: (sessionId) => account.getSession(sessionId),
    estimateMaxLoss: (opts) => account.estimateMaxLoss(opts),
  };
}

export default { createSmartAccountClient };

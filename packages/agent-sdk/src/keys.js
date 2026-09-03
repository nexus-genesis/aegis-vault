/**
 * aegis-agent-sdk —keys module
 *
 * High-level agent identity + key security, built on aegis-vault.
 * Every agent gets a PQC key pair; private keys never leave the caller; a
 * human can always take over an autonomous agent.
 *
 * This is the differentiation layer: private keys are never held on a server.
 */
import crypto from 'node:crypto';
import {
  generateKeyPair,
  sign,
  verify,
  generateAddress,
  validateAddress,
  PQCWallet,
  encryptPrivateKey,
  decryptPrivateKey,
  deriveOpKeySeed,
  generateMasterKey,
  KEY_MODELS,
  issueCustodyToken,
  verifyCustodyToken,
  checkSpendAllowed,
  checkSessionAccess,
  verifySessionSignature,
  takeoverGuard,
  takeoverWallet,
  spawnSigner,
  SPEND_MODES
} from 'aegis-vault';

/**
 * Generate a brand-new autonomous agent identity.
 * Returns public material (safe to register) + an encrypted private-key
 * envelope the caller keeps locally. The private key must never be sent out.
 * @param {object} options { password, metadata }
 * @returns {Promise<{ agentId, address, publicKeyHex, envelope, keyModel }>}
 */
export async function createAgentIdentity(options = {}) {
  const { password, metadata = {} } = options;
  if (!password || typeof password !== 'string' || password.length < 8) {
    // SECURITY FIX: a hard-coded default password made every self-sovereign
    // identity recoverable by anyone who knows the default. A real password is
    // now required; the caller owns the envelope's confidentiality.
    throw new Error('createAgentIdentity requires a password of at least 8 characters');
  }
  const { publicKey, privateKey } = await generateKeyPair();
  const address = generateAddress(publicKey);
  const envelope = encryptPrivateKey(privateKey, password, {
    address,
    publicKey: publicKey.toString('hex'),
    keyModel: KEY_MODELS.SELF_SOVEREIGN
  });
  return {
    address,
    publicKeyHex: publicKey.toString('hex'),
    envelope,
    keyModel: KEY_MODELS.SELF_SOVEREIGN,
    metadata
  };
}

/**
 * Recover an agent identity from its encrypted envelope.
 * @param {object} envelope from createAgentIdentity / exportEncrypted
 * @param {string} password
 * @returns {import('aegis-vault').PQCWallet | null}
 */
export function recoverAgentIdentity(envelope, password) {
  return PQCWallet.importEncrypted(envelope, password);
}

/**
 * Sign an arbitrary payload with a wallet.
 *
 * P0-2 / INV-002: this is the generic agent-facing signing channel. It is
 * intended for METADATA (task claim/submit/verify/publish, forum actions,
 * protocol bookkeeping). Payloads that look like asset operations
 * (transfer/withdraw/approve/permit/bridge/swap/... ) MUST NOT go through
 * the generic channel — they fail closed UNCONDITIONALLY (no escape hatch)
 * and require the explicit high-risk path `signAgentAsset()` with a valid,
 * scoped session key.
 *
 * @param {object} wallet
 * @param {string|object} message
 * @returns {Promise<string>} hex signature
 */
export async function signAsAgent(wallet, message) {
  const verdict = classifySignRequest(message);
  if (verdict.tier === SIGN_TIERS.ASSET) {
    throw new Error(
      `signAsAgent: asset-tier payload (${verdict.signal}) requires the explicit ` +
      'high-risk channel signAgentAsset(wallet, { session, intent }) (INV-002)'
    );
  }
  return wallet.sign(message);
}

// ─── Graded signing channels (P0-2 / INV-002) ─────────────────────────────

/**
 * Signing tiers.
 *   METADATA — protocol bookkeeping; carries no asset-transfer authority.
 *   ASSET    — payloads authorizing asset movement, allowance, permission
 *              changes, or contract upgrades. Requires a scoped session key.
 */
export const SIGN_TIERS = Object.freeze({
  METADATA: 'metadata',
  ASSET: 'asset',
});

/** Action names that always denote an asset/privilege-changing operation. */
const ASSET_ACTIONS = new Set([
  'transfer', 'withdraw', 'approve', 'permit', 'bridge', 'swap', 'spend',
  'send_asset', 'allowance', 'grant_role', 'grantrole', 'upgrade',
  'set_owner', 'setowner', 'increase_limit', 'add_owner', 'addowner',
  'mint', 'burn', 'delegatecall',
]);

/** Top-level keys that, combined with an amount/asset, signal an asset op. */
const ASSET_KEY_HINT = /^(recipient|to|contract|method|chain|allowance|approve|permit|bridge|swap|transfer|withdraw|spend|owner)$/i;

/**
 * Classify a sign request into a tier by its intent shape.
 * Opaque strings are treated as metadata (cannot be structurally inspected).
 * @param {string|object} message
 * @returns {{ tier: string, signal: string|null }}
 */
export function classifySignRequest(message) {
  if (typeof message !== 'object' || message === null || Array.isArray(message)) {
    return { tier: SIGN_TIERS.METADATA, signal: null };
  }
  const action = message.action || message.type || message.intent;
  if (typeof action === 'string' && ASSET_ACTIONS.has(action.toLowerCase())) {
    return { tier: SIGN_TIERS.ASSET, signal: `action:${action}` };
  }
  const hasAmount = Object.prototype.hasOwnProperty.call(message, 'amount');
  const hasAsset = Object.prototype.hasOwnProperty.call(message, 'asset');
  const hasAssetKey = Object.keys(message).some((k) => ASSET_KEY_HINT.test(k));
  if ((hasAmount || hasAsset) && hasAssetKey) {
    return { tier: SIGN_TIERS.ASSET, signal: 'asset-operation-shape' };
  }
  return { tier: SIGN_TIERS.METADATA, signal: null };
}

/**
 * High-risk signing channel (INV-002/003): sign a structured asset intent
 * ONLY under a valid, scoped session key. Fails closed when the session is
 * missing, unverifiable, expired, or outside its scope. The signature is
 * bound to the intent + session context so the verifier can detect
 * intent/signature drift.
 *
 * The session MUST be independently verifiable: `issuerPublicKey` is
 * REQUIRED — without issuer verification an Agent could fabricate its own
 * session and self-authorize (INV-003 violation).
 *
 * DEFAULT PATH (P0-3): pass a `signer` (SignerHandle from spawnAgentSigner) —
 * the key then lives in an isolated subprocess and the signature is produced
 * there. `wallet` is an EXPLICIT, in-process fallback for environments where
 * a subprocess cannot be spawned (tests, constrained sandboxes); it must not
 * be the default in production.
 *
 * NOTE: this performs the SDK-side gate. Enforcement that survives a fully
 * compromised Agent must additionally live in the Signer + on-chain Smart
 * Account (see whitepaper §9/§10 and P0-4).
 *
 * @param {object} opts
 * @param {object} [opts.signer] - SignerHandle (default path; key in child process)
 * @param {object} [opts.wallet] - PQCWallet (explicit in-process fallback)
 * @param {object} opts.session - session key token (createSessionKey)
 * @param {object} opts.intent - { action, chain, asset, amount, recipient,
 *   contract?, method?, deadline? }
 * @param {Buffer} opts.issuerPublicKey - issuer public key used to verify
 *   the session signature (mandatory)
 * @returns {Promise<string|{timelocked:true, timelockMs:number, scheduledAt:number}>}
 *   hex signature, or (signer path) a timelock object when the amount lands
 *   in the medium tier under three-tier authorization
 */
export async function signAgentAsset({ signer, wallet, session, intent, issuerPublicKey } = {}) {
  if (!session) {
    throw new Error('signAgentAsset requires a session key (INV-003)');
  }
  if (!intent || typeof intent !== 'object') {
    throw new Error('signAgentAsset requires a structured asset intent (INV-002)');
  }
  if (!issuerPublicKey) {
    throw new Error('signAgentAsset requires issuerPublicKey to verify the session (INV-003)');
  }
  const valid = await verifySessionSignature(session, issuerPublicKey);
  if (!valid) {
    throw new Error('signAgentAsset: session signature invalid (INV-003)');
  }
  const access = checkSessionAccess(session, {
    contract: intent.contract,
    method: intent.method,
    chain: intent.chain,
    amount: intent.amount,
  });
  if (!access.allowed) {
    throw new Error(`signAgentAsset denied: ${access.reason} (INV-003)`);
  }

  // P0-4: the signature is bound to the DECODABLE canonical payload itself
  // (a JSON string carrying the amount), NOT to a one-way hash. This lets an
  // on-chain verifier decode the amount from the signed content and enforce
  // amount consistency (verifyAgentAssetSignature / enforceAmountBinding),
  // and lets the isolated signer derive its spend-policy check from the very
  // bytes it signs — closing the amount-hash unlinkability limitation.
  const canonical = canonicalizeAssetIntent(session, intent);

  if (signer) {
    // Default path: isolated signer holds the key, enforces worker-side spend
    // ceilings (INV-003, second layer) using the amount INSIDE the payload,
    // and signs JSON.stringify(canonical).
    const result = await signer.signIntent(canonical);
    if (result && typeof result === 'object' && result.timelocked) {
      // Medium tier under three-tier authorization → pass the timelock through.
      return result;
    }
    // The SignerHandle returns 0x-prefixed hex; normalize to bare hex so the
    // signAgentAsset contract matches wallet.sign() output (no prefix).
    return typeof result === 'string' ? result.replace(/^0x/, '') : result;
  }
  if (!wallet) {
    throw new Error('signAgentAsset requires a signer (default) or an explicit in-process wallet (fallback)');
  }
  // In-process fallback signs the same decodable payload string, so the
  // verification contract is identical to the signer path.
  return wallet.sign(JSON.stringify(canonical));
}

/**
 * Build the canonical asset-intent payload bound into the signature.
 *
 * SPRINT 2 — this is the single cross-language schema shared by the JS SDK
 * and the Solidity Smart Account (contracts/solidity/src/SmartAccount.sol).
 * Field ORDER is part of the protocol: chain-eth's hashIntentDigest and the
 * contract's _hashIntent hash these exact fields in this exact order, so the
 * digest is byte-identical on both sides. Do NOT reorder or rename fields.
 *
 * Schema (all fields required by the on-chain digest — see
 * packages/chain-eth/src/canonical.js):
 *   type                = 'agent_asset_intent' (verifier marker, must match
 *                         verifier.js ASSET_INTENT_TYPE)
 *   sessionId           = 32-byte hex. Uses session.sessionId when the session
 *                         is registered on-chain, else derives a deterministic
 *                         32-byte id from the session identity (agentId +
 *                         issuedAt + expiresAt), so the same session token
 *                         always canonicalizes to the same id.
 *   action/chain/asset/recipient/contract/method = string fields
 *   amount/nonce        = string numbers (BigInt precision)
 *   agentId             = session.agentId
 *   sessionIssuedAt     = session.issuedAt (ms epoch)
 *   sessionExpiresAt    = session.expiresAt (ms epoch)
 *
 * @param {object} session - session key token
 * @param {object} intent - structured asset intent
 * @returns {object} canonical payload (fixed field order)
 * @throws when a field required by the signed digest is missing/empty
 *   (INV-002 amount; the six string dimensions and agentId are part of the
 *   signed digest — a missing field must not silently serialize to '' and
 *   collapse two different intents into one signature preimage). `nonce` is
 *   NOT required here: it is an execution-time replay guard enforced at the
 *   digest boundary (chain-eth hashIntentDigest) and on-chain.
 */
export function canonicalizeAssetIntent(session, intent) {
  if (!session || typeof session !== 'object') {
    throw new Error('canonicalizeAssetIntent requires a session');
  }
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) {
    throw new Error('canonicalizeAssetIntent requires a structured intent');
  }
  for (const f of ['action', 'chain', 'asset', 'recipient', 'contract', 'method']) {
    const v = intent[f];
    if (v === undefined || v === null || String(v).trim() === '') {
      throw new Error(`canonicalizeAssetIntent: missing/empty intent.${f} (required by the signed digest)`);
    }
  }
  if (intent.amount === undefined || intent.amount === null || String(intent.amount).trim() === '') {
    throw new Error('canonicalizeAssetIntent: missing/empty intent.amount (INV-002)');
  }
  if (session.agentId === undefined || session.agentId === null || String(session.agentId).trim() === '') {
    throw new Error('canonicalizeAssetIntent: missing/empty session.agentId (required by the signed digest)');
  }
  return {
    type: 'agent_asset_intent',
    sessionId: session.sessionId || deriveSessionId(session),
    action: intent.action,
    chain: intent.chain,
    asset: intent.asset,
    amount: intent.amount,
    recipient: intent.recipient,
    contract: intent.contract,
    method: intent.method,
    nonce: intent.nonce,
    agentId: session.agentId,
    sessionIssuedAt: session.issuedAt,
    sessionExpiresAt: session.expiresAt,
  };
}

/**
 * Deterministic 32-byte session identifier for the canonical schema.
 *
 * The on-chain Smart Account keys sessions by a bytes32 sessionId. JS session
 * tokens (createSessionKey) carry no id today, so when the caller does not
 * pin `session.sessionId` (e.g. on-chain registration), we derive a stable
 * one from the session's identity fields. sha256 is sufficient here: the
 * sessionId is an opaque lookup key — the binding that prevents cross-session
 * replay is the sessionIssuedAt/ExpiresAt + agentId fields inside the signed
 * digest, not the entropy of the id.
 *
 * @param {object} session - session key token
 * @returns {string} '0x' + 64 hex chars (32 bytes)
 */
function deriveSessionId(session) {
  const seed = JSON.stringify({
    agentId: session && session.agentId,
    issuedAt: session && session.issuedAt,
    expiresAt: session && session.expiresAt,
  });
  return '0x' + crypto.createHash('sha256').update(seed).digest('hex');
}

/**
 * Hash the canonical intent into a 0x-hex fingerprint (sha256).
 *
 * NOTE (P0-4): since P0-4 the ASSET SIGNATURE is bound to the decodable
 * canonical payload itself (JSON.stringify(canonical)), NOT to this hash —
 * the hash is one-way and would re-introduce amount-hash unlinkability on
 * the verifier side. This function remains for traceability / indexing only.
 *
 * NOTE (Sprint 2): the digest the Solidity Smart Account verifies is NOT this
 * sha256 fingerprint. It is the fixed keccak256 digest produced by
 * chain-eth's hashIntentDigest(canonical), which mirrors the contract's
 * _hashIntent. See packages/chain-eth/src/canonical.js.
 *
 * @param {object} canonical - canonicalizeAssetIntent() output
 * @returns {string} '0x' + sha256 hex
 */
export function hashAssetIntent(canonical) {
  const digest = crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
  return '0x' + digest;
}

/**
 * Spawn an isolated Signer subprocess that holds the agent key (P0-3).
 *
 * When a `session` is provided and no explicit `policy` is given, the
 * worker-side spend policy is derived from the session's hard ceilings
 * (maxPerTx/maxDaily) so the isolated signer independently enforces the
 * same limits — a second, process-isolated layer that survives a fully
 * compromised parent (INV-003).
 *
 * @param {object} opts
 * @param {object} opts.envelope - encrypted key envelope (encryptPrivateKey)
 * @param {string} opts.password - envelope decryption password (≥8 chars)
 * @param {object} [opts.policy] - explicit worker spend policy (overrides session-derived)
 * @param {object} [opts.session] - session key token; derives worker ceilings
 * @param {number} [opts.idleTimeoutMs] - worker idle timeout before auto-exit
 * @returns {Promise<import('aegis-vault').SignerHandle>}
 */
export async function spawnAgentSigner({ envelope, password, policy, session, idleTimeoutMs } = {}) {
  if (!envelope || !password) {
    throw new Error('spawnAgentSigner requires envelope and password');
  }
  let workerPolicy = policy;
  if (!workerPolicy && session) {
    const hasLimits = session.maxPerTx !== undefined || session.maxDaily !== undefined;
    if (hasLimits) {
      workerPolicy = {
        type: SPEND_MODES.LIMITED,
        maxPerTx: session.maxPerTx,
        maxDaily: session.maxDaily,
      };
    }
  }
  return spawnSigner({ envelope, password, policy: workerPolicy, idleTimeoutMs });
}

export {
  generateKeyPair,
  sign,
  verify,
  generateAddress,
  validateAddress,
  PQCWallet,
  encryptPrivateKey,
  decryptPrivateKey,
  deriveOpKeySeed,
  generateMasterKey,
  KEY_MODELS,
  issueCustodyToken,
  verifyCustodyToken,
  checkSpendAllowed,
  takeoverGuard,
  takeoverWallet,
  spawnSigner,
  SPEND_MODES
};

export default {
  createAgentIdentity,
  recoverAgentIdentity,
  signAsAgent,
  signAgentAsset,
  SIGN_TIERS,
  classifySignRequest,
  spawnSigner,
  spawnAgentSigner,
  canonicalizeAssetIntent,
  hashAssetIntent,
  generateKeyPair,
  generateAddress,
  validateAddress,
  encryptPrivateKey,
  decryptPrivateKey,
  KEY_MODELS,
  SPEND_MODES
};
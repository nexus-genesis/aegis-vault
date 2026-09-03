/**
 * aegis-vault —Custody Token (short-lived authorization)
 *
 * A server-issued, HMAC-SHA256 signed, short-lived (default 24h) token that
 * binds an agent identity to a specific wallet public key. Used as a
 * "quasi-signature" channel so an external agent can act without holding the
 * private key on the server.
 *
 * Security model:
 *   - Private key never leaves the agent/browser (custody is not broken)
 *   - Token is server-issued, cannot be forged by the agent (HMAC check)
 *   - Short TTL, expires and must be re-issued
 *   - Carries a public-key fingerprint bound to a specific wallet
 *
 * Extracted from NexusGenesis src/http/custodyToken.js.
 */
import crypto from 'node:crypto';

const DEFAULT_TOKEN_TTL_SECONDS = 24 * 60 * 60; // 24h

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

/** SHA256 fingerprint (first 16 bytes hex) of a public key. */
export function publicKeyFingerprint(publicKeyHex) {
  return crypto.createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest('hex').slice(0, 32);
}

/** Resolve the signing secret (env in app context; here caller supplies). */
function getSigningSecret(secret) {
  if (!secret) {
    throw new Error('[CustodyToken] signing secret is required (>= 32 chars)');
  }
  return secret;
}

/**
 * Issue a custody token.
 * @param {object} params { agentId, address, publicKeyHex, secret, ttlSeconds? }
 * @returns {{ token: string, expiresAt: number, issuedAt: number }}
 */
export function issueCustodyToken({ agentId, address, publicKeyHex, secret, ttlSeconds }) {
  if (!agentId || !address || !publicKeyHex) {
    throw new Error('issueCustodyToken: agentId, address, publicKeyHex are required');
  }
  const ttl = typeof ttlSeconds === 'number' ? ttlSeconds : DEFAULT_TOKEN_TTL_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const header = { alg: 'HS256', typ: 'CUSTODY' };
  const payload = { sub: agentId, addr: address, fp: publicKeyFingerprint(publicKeyHex), iat: now, exp };

  const headerB64 = base64url(header);
  const payloadB64 = base64url(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = crypto.createHmac('sha256', getSigningSecret(secret)).update(signingInput).digest();
  const sigB64 = base64url(signature);

  return { token: `${signingInput}.${sigB64}`, expiresAt: exp, issuedAt: now };
}

/**
 * Verify a custody token.
 * @param {string} token
 * @param {string} secret
 * @param {object} context { agentId?, address?, publicKeyHex? }
 * @returns {{ valid: boolean, payload?: object, reason?: string }}
 */
export function verifyCustodyToken(token, secret, context = {}) {
  if (!token || typeof token !== 'string') return { valid: false, reason: 'token missing' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, reason: 'malformed token' };
  const [headerB64, payloadB64, sigB64] = parts;

  const expectedSig = crypto.createHmac('sha256', getSigningSecret(secret)).update(`${headerB64}.${payloadB64}`).digest();
  const providedSig = base64urlDecode(sigB64);
  if (expectedSig.length !== providedSig.length || !crypto.timingSafeEqual(expectedSig, providedSig)) {
    return { valid: false, reason: 'invalid signature' };
  }

  let payload;
  try {
    payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8'));
  } catch {
    return { valid: false, reason: 'malformed payload' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || now >= payload.exp) {
    return { valid: false, reason: 'token expired' };
  }

  if (context.agentId && payload.sub !== context.agentId) return { valid: false, reason: 'agentId mismatch' };
  if (context.address && payload.addr !== context.address) return { valid: false, reason: 'address mismatch' };
  if (context.publicKeyHex && payload.fp !== publicKeyFingerprint(context.publicKeyHex)) {
    return { valid: false, reason: 'publicKey fingerprint mismatch' };
  }

  return { valid: true, payload };
}

export default {
  issueCustodyToken,
  verifyCustodyToken,
  publicKeyFingerprint
};
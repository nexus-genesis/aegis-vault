/**
 * Aegis Vault agent-keys — Security boundary tests
 *
 * These tests verify that the security-critical invariants hold under
 * adversarial / malformed input. They are deliberately separate from the
 * functional suite so the audit trail is explicit.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateKeyPair,
  sign,
  verify,
  encryptPrivateKey,
  decryptPrivateKey,
  generateMasterKey,
  deriveOpKeySeed,
  generateKeyPairFromSeed,
  issueCustodyToken,
  verifyCustodyToken,
  checkSpendAllowed,
  resolveSpendMode,
  takeoverGuard,
  takeoverWallet,
  SPEND_MODES
} from '../src/index.js';

// ─── Critical: deterministic key derivation from seed ────────────────────
// A seed-based keypair MUST be reproducible: the same seed yields the same
// key. Otherwise a master key + agentId cannot recover the same op key,
// which breaks the entire three-tier hierarchy and backup/restore.
test('[CRITICAL] generateKeyPairFromSeed is deterministic for a given seed', async () => {
  const seed = Buffer.alloc(32, 0x42);
  const a = await generateKeyPairFromSeed(seed);
  const b = await generateKeyPairFromSeed(seed);
  assert.deepEqual(
    a.publicKey,
    b.publicKey,
    'same seed must produce the same public key (deterministic recovery)'
  );
  assert.deepEqual(
    a.privateKey,
    b.privateKey,
    'same seed must produce the same private key (deterministic recovery)'
  );
});

test('[CRITICAL] different seeds produce different keys', async () => {
  const k1 = await generateKeyPairFromSeed(Buffer.alloc(32, 0x01));
  const k2 = await generateKeyPairFromSeed(Buffer.alloc(32, 0x02));
  assert.notDeepEqual(k1.publicKey, k2.publicKey);
});

// ─── Spend-limit bypass via negative / non-integer amounts ───────────────
test('[HIGH] negative amount cannot bypass an unlimited check', () => {
  // Unlimited still rejects negative amounts (never a valid spend).
  assert.equal(checkSpendAllowed({ type: 'unlimited' }, { amount: -100 }).allowed, false);
});

// ─── Fail-open vs fail-closed default ───────────────────────────────────
test('[HIGH] missing/invalid spend mode fails CLOSED (never unlimited)', () => {
  const missing = resolveSpendMode(undefined);
  const nullType = resolveSpendMode({ type: null });
  const bogusType = resolveSpendMode({ type: 'not-a-mode' });
  const missingType = resolveSpendMode({ maxPerTx: 100 });
  for (const r of [missing, nullType, bogusType, missingType]) {
    assert.equal(r.type, 'require-approval', 'must fail closed to require-approval');
    assert.equal(checkSpendAllowed(r, { amount: 1 }).allowed, false, 'must not allow spending');
  }
  // A valid explicit mode still works as expected.
  assert.equal(resolveSpendMode({ type: 'unlimited' }).type, 'unlimited');
  assert.equal(checkSpendAllowed({ type: 'limit', maxPerTx: 100 }, { amount: 50 }).allowed, true);
});


test('[HIGH] negative amount must NOT bypass a per-tx limit', () => {
  // A negative amount is always < maxPerTx, so must be rejected explicitly.
  const r = checkSpendAllowed({ type: 'limit', maxPerTx: 100 }, { amount: -5 });
  assert.equal(r.allowed, false, 'negative amount must be rejected under a limit');
});

test('[HIGH] negative spentToday must NOT bypass a daily limit', () => {
  // A negative spentToday would make (spentToday + amount) small and pass.
  const r = checkSpendAllowed({ type: 'limit', maxPerTx: 100, maxDaily: 50 }, { amount: 60, spentToday: -100 });
  assert.equal(r.allowed, false, 'negative spentToday must be rejected');
});

test('[MED] non-integer / NaN amounts are rejected (no crash)', () => {
  assert.equal(checkSpendAllowed({ type: 'limit', maxPerTx: 100 }, { amount: NaN }).allowed, false);
  assert.equal(checkSpendAllowed({ type: 'limit', maxPerTx: 100 }, { amount: 1.5 }).allowed, false);
});

// ─── Tampering with the envelope's KDF parameters (downgrade) ────────────
test('[MED] envelope with tampered iterations still fails decryption', () => {
  const key = Buffer.from('a'.repeat(64), 'hex');
  const env = encryptPrivateKey(key, 'correct horse battery staple');
  env.kdf.iterations = 1; // attacker tries to force a fast KDF
  // v2: rejected up-front by the KDF floor (DEGRADED_KDF) — a stronger
  // fail-closed than the old v1 behavior (slow failure via GCM auth mismatch).
  assert.throws(
    () => decryptPrivateKey(env, 'correct horse battery staple'),
    (err) => err.code === 'DEGRADED_KDF'
  );
});

// ─── Custody token tampering ─────────────────────────────────────────────
test('[HIGH] custody token cannot be forged without the secret', async () => {
  const { publicKey } = await generateKeyPair();
  const pubHex = publicKey.toString('hex');
  const { token } = issueCustodyToken({ agentId: 'a1', address: 'ng1x', publicKeyHex: pubHex, secret: 's'.repeat(32) });
  // Tamper with payload but keep signature
  const parts = token.split('.');
  const tampered = Buffer.from(JSON.stringify({ sub: 'a1', addr: 'ng1x', fp: 'f'.repeat(32), iat: 0, exp: 1e12 })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const forged = `${parts[0]}.${tampered}.${parts[2]}`;
  assert.equal(verifyCustodyToken(forged, 's'.repeat(32)).valid, false);
});

test('[HIGH] expired custody token is rejected', async () => {
  const { publicKey } = await generateKeyPair();
  const { token } = issueCustodyToken({
    agentId: 'a1', address: 'ng1x', publicKeyHex: publicKey.toString('hex'),
    secret: 's'.repeat(32), ttlSeconds: -1 // already expired
  });
  assert.equal(verifyCustodyToken(token, 's'.repeat(32)).valid, false);
});

// ─── Takeover invariants ─────────────────────────────────────────────────
test('[HIGH] takeoverGuard returns false once a human requires approval', () => {
  assert.equal(takeoverGuard({ type: 'unlimited' }, { type: 'require-approval' }), false);
  assert.equal(takeoverGuard({ type: 'limit', maxPerTx: 10 }, { type: 'require-approval' }), false);
});

// [SECURITY FIX 2026-08-24 external review] — same-mode ceiling loosening is a
// takeover-equivalent power grab and must roll back.
test('[HIGH] takeoverGuard rejects same-mode ceiling LOOSENING (raised / removed)', () => {
  // maxDaily raised 10 → 999999 (the exact exploit from the review)
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 10 },
      { type: 'limit', maxPerTx: 10, maxDaily: 999999 },
    ),
    false,
    'raised maxDaily must be treated as takeover',
  );
  // maxPerTx raised
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
      { type: 'limit', maxPerTx: 500, maxDaily: 100 },
    ),
    false,
    'raised maxPerTx must be treated as takeover',
  );
  // ceiling removed → 0 means "no ceiling" in checkSpendAllowed semantics
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
      { type: 'limit', maxPerTx: 0, maxDaily: 100 },
    ),
    false,
    'removed ceiling (→0, i.e. unlimited) must be treated as takeover',
  );
  // field dropped entirely is equivalent to removed
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
      { type: 'limit', maxDaily: 100 },
    ),
    false,
    'dropped maxPerTx must be treated as takeover',
  );
});

test('[HIGH] takeoverGuard accepts unchanged or TIGHTENED ceilings', () => {
  // unchanged
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
    ),
    true,
  );
  // tightened
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 10, maxDaily: 100 },
      { type: 'limit', maxPerTx: 5, maxDaily: 50 },
    ),
    true,
    'tightening is safe — a takeover cannot gain power by lowering limits',
  );
  // before had no ceiling → after introducing one is tightening, safe
  assert.equal(
    takeoverGuard(
      { type: 'limit', maxPerTx: 0, maxDaily: 0 },
      { type: 'limit', maxPerTx: 5, maxDaily: 50 },
    ),
    true,
  );
});

test('[HIGH] takeoverWallet rotates key and forces approval mode', async () => {
  const master = generateMasterKey();
  const { config, opKeySeed, version } = await takeoverWallet(master, 'agent-9', 3);
  assert.equal(config.type, SPEND_MODES.REQUIRE_APPROVAL);
  assert.equal(version, 4);
  assert.equal(opKeySeed.length, 32);
});

// ─── Weak / edge inputs to encryption ────────────────────────────────────
test('[LOW] very long password is accepted (no DoS via alloc)', () => {
  const key = Buffer.from('a'.repeat(64), 'hex');
  const longPass = 'p'.repeat(100_000);
  const env = encryptPrivateKey(key, longPass);
  assert.deepEqual(decryptPrivateKey(env, longPass), key);
});

test('[LOW] empty private key is rejected', () => {
  assert.throws(() => encryptPrivateKey(Buffer.alloc(0), 'password123'), /not be empty|EMPTY_KEY|required/i);
});

// ─── Signature malleability / wrong-length rejection ─────────────────────
test('[MED] verify rejects wrong-length signatures and keys', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const sig = Buffer.from(await sign('msg', privateKey));
  assert.equal(await verify('msg', Buffer.alloc(1), publicKey), false);
  assert.equal(await verify('msg', sig, Buffer.alloc(1)), false);
});

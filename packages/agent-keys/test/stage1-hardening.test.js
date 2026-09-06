/**
 * Stage 1 hardening tests (PHASE2 audit fixes):
 *   1. v2 domain-separated derivation (root→purpose / root→chain)
 *   2. PolicyTimelock persistence (restart-safe time-locks)
 *   3. Envelope v2 (KDF floor + AAD-bound metadata, v1 compat)
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  deriveOpKeySeed,
  deriveOpKeySeedV2,
  deriveDomainSeed,
  DERIVATION_VERSION,
  DERIVATION_DOMAINS
} from '../src/derivation.js';
import { PolicyTimelock, POLICY_TIMELOCK_STORE_KEY } from '../src/takeover.js';
import { encryptPrivateKey, decryptPrivateKey, isValidEnvelope, getEncryptionInfo } from '../src/encryption.js';

function masterKey() {
  return Buffer.from('3f5a1c9e2b7d4086af21c05d94e73b60cc81a2f4d5e6b7c80912a3f4b5c6d7e8', 'hex');
}

function memStore() {
  const map = new Map();
  return {
    read: (key) => (map.has(key) ? structuredClone(map.get(key)) : null),
    write: (key, value) => { map.set(key, structuredClone(value)); },
    size: () => map.get(POLICY_TIMELOCK_STORE_KEY)?.length ?? 0,
    raw: map
  };
}

// ─── 1. v2 domain-separated derivation ────────────────────────────────────

test('v2 derivation is deterministic for the same inputs', async () => {
  const mk = masterKey();
  const a = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.CHAIN_KEY, chain: 'eth' });
  const b = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.CHAIN_KEY, chain: 'eth' });
  assert.deepEqual(a, b);
  assert.equal(a.length, 32);
});

test('v2: different domains yield independent seeds (no cross-purpose replay)', async () => {
  const mk = masterKey();
  const op = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.OP_KEY, agentId: 'agent-1' });
  const chain = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.CHAIN_KEY, chain: 'eth' });
  const snap = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.SNAPSHOT });
  assert.notDeepEqual(Buffer.from(op), Buffer.from(chain));
  assert.notDeepEqual(Buffer.from(op), Buffer.from(snap));
  assert.notDeepEqual(Buffer.from(chain), Buffer.from(snap));
});

test('v2: different chains under the same root yield independent seeds', async () => {
  const mk = masterKey();
  const eth = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.CHAIN_KEY, chain: 'eth' });
  const sol = await deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.CHAIN_KEY, chain: 'sol' });
  assert.notDeepEqual(Buffer.from(eth), Buffer.from(sol));
});

test('v2 op-key seed differs from legacy v1 (v1 stays byte-compatible)', async () => {
  const mk = masterKey();
  const v1 = await deriveOpKeySeed(mk, { agentId: 'agent-1', version: 1 });
  const v1again = await deriveOpKeySeed(mk, { agentId: 'agent-1', version: 1 });
  const v2 = await deriveOpKeySeedV2(mk, { agentId: 'agent-1', version: 1 });
  assert.deepEqual(v1, v1again, 'v1 derivation must remain stable');
  assert.notDeepEqual(v1, v2, 'v2 must live in a different domain than v1');
});

test('v2 rotation version produces a different seed', async () => {
  const mk = masterKey();
  const v1 = await deriveOpKeySeedV2(mk, { agentId: 'a', version: 1 });
  const v2 = await deriveOpKeySeedV2(mk, { agentId: 'a', version: 2 });
  assert.notDeepEqual(v1, v2);
});

test('v2 rejects missing domain / op-key without agentId / invalid root key', async () => {
  const mk = masterKey();
  await assert.rejects(() => deriveDomainSeed(mk, {}), /domain is required/);
  await assert.rejects(() => deriveDomainSeed(mk, { domain: DERIVATION_DOMAINS.OP_KEY }), /agentId is required/);
  await assert.rejects(() => deriveDomainSeed(Buffer.from('short'), { domain: 'x' }), /Invalid root key/);
});

test('DERIVATION_VERSION is exported as 2', () => {
  assert.equal(DERIVATION_VERSION, 2);
});

// ─── 2. PolicyTimelock persistence ────────────────────────────────────────

test('timelock persists scheduled changes to the store', () => {
  const store = memStore();
  const tl = new PolicyTimelock(1000, { store });
  tl.scheduleChange('agent-1', { type: 'limit', maxPerTx: 5 });
  assert.equal(store.size(), 1);
  const [entry] = store.raw.get(POLICY_TIMELOCK_STORE_KEY);
  assert.equal(entry.agentId, 'agent-1');
  assert.equal(entry.newPolicy.maxPerTx, 5);
});

test('timelock restores pending changes after "restart"', () => {
  const store = memStore();
  const first = new PolicyTimelock(60_000, { store });
  const { changeId } = first.scheduleChange('agent-1', { type: 'unlimited' });
  // simulate crash + restart: brand new instance over the same store
  const second = new PolicyTimelock(60_000, { store });
  assert.equal(second.pendingCount, 1, 'pending change must survive restart');
  const restored = second.getChange(changeId);
  assert.equal(restored.agentId, 'agent-1');
  assert.deepEqual(restored.newPolicy, { type: 'unlimited' });
  assert.ok(restored.remainingMs > 0);
});

test('revocation persists: revoked change is gone after restart', () => {
  const store = memStore();
  const first = new PolicyTimelock(60_000, { store });
  const { changeId } = first.scheduleChange('agent-1', { type: 'unlimited' });
  first.revokeChange(changeId);
  assert.equal(first.pendingCount, 0);
  const second = new PolicyTimelock(60_000, { store });
  assert.equal(second.pendingCount, 0, 'revocation must survive restart');
});

test('effective changes are consumed from the store as well', () => {
  const store = memStore();
  // schedule with a negative-ish delay by crafting a store entry that is due
  store.raw.set(POLICY_TIMELOCK_STORE_KEY, [{
    changeId: 'c-1',
    agentId: 'agent-1',
    newPolicy: { type: 'limit', maxPerTx: 1 },
    scheduledAt: Date.now() - 1000,
    createdAt: Date.now() - 2000
  }]);
  const tl = new PolicyTimelock(1000, { store });
  const effective = tl.getEffectiveChanges();
  assert.equal(effective.length, 1);
  assert.equal(effective[0].changeId, 'c-1');
  assert.equal(store.size(), 0, 'consumed changes must be removed from the store');
  const again = new PolicyTimelock(1000, { store });
  assert.equal(again.pendingCount, 0, 'restart must not re-apply consumed changes');
});

test('timelock without a store keeps legacy in-memory semantics', () => {
  const tl = new PolicyTimelock(60_000);
  tl.scheduleChange('agent-1', { type: 'unlimited' });
  assert.equal(tl.pendingCount, 1);
  assert.equal(tl.clearAll(), 1);
});

test('corrupted persisted state fails closed at construction', () => {
  const store = memStore();
  store.raw.set(POLICY_TIMELOCK_STORE_KEY, { not: 'an array' });
  assert.throws(() => new PolicyTimelock(1000, { store }), /malformed/);
});

test('store write failure aborts scheduleChange (fail-closed)', () => {
  const failing = { read: () => null, write: () => { throw new Error('disk full'); } };
  const tl = new PolicyTimelock(1000, { store: failing });
  assert.throws(() => tl.scheduleChange('agent-1', { type: 'unlimited' }), /disk full/);
  assert.equal(tl.pendingCount, 0, 'unpersisted schedule must not be kept in memory');
});

test('malformed persisted entries are skipped, valid ones restored', () => {
  const store = memStore();
  store.raw.set(POLICY_TIMELOCK_STORE_KEY, [
    null,
    { changeId: 'bad' },
    { changeId: 'good-1', agentId: 'a1', newPolicy: { type: 'unlimited' }, scheduledAt: Date.now() + 1000, createdAt: Date.now() }
  ]);
  const tl = new PolicyTimelock(1000, { store });
  assert.equal(tl.pendingCount, 1);
});

// ─── 3. Envelope v2: KDF floor + AAD ──────────────────────────────────────

test('v2 envelope round-trips and binds metadata via AAD', () => {
  const key = Buffer.from('bb'.repeat(32), 'hex');
  const env = encryptPrivateKey(key, 'correct horse battery staple', { keyId: 'op-key-v1', agentId: 'agent-1' });
  assert.equal(env.envelope, 2);
  assert.equal(isValidEnvelope(env), true);
  const restored = decryptPrivateKey(env, 'correct horse battery staple');
  assert.deepEqual(restored, key);
});

test('v2: swapping metadata between envelopes breaks authentication', () => {
  const keyA = Buffer.from('aa'.repeat(32), 'hex');
  const keyB = Buffer.from('bb'.repeat(32), 'hex');
  const password = 'correct horse battery staple';
  const envA = encryptPrivateKey(keyA, password, { keyId: 'key-A' });
  const envB = encryptPrivateKey(keyB, password, { keyId: 'key-B' });
  // ciphertext-splice attack: put A's ciphertext under B's metadata identity
  const spliced = { ...envB, ciphertext: envA.ciphertext, authTag: envA.authTag, iv: envA.iv, kdf: envA.kdf };
  assert.throws(
    () => decryptPrivateKey(spliced, password),
    (err) => err.code === 'AUTH_FAILED',
    'spliced ciphertext must not authenticate under another envelope identity'
  );
});

test('v2: editing metadata in place breaks authentication', () => {
  const key = Buffer.from('cc'.repeat(32), 'hex');
  const password = 'correct horse battery staple';
  const env = encryptPrivateKey(key, password, { keyId: 'op-key-v1' });
  env.metadata.keyId = 'attacker-chosen'; // attacker relabels the key
  assert.throws(
    () => decryptPrivateKey(env, password),
    (err) => err.code === 'AUTH_FAILED'
  );
});

test('v2: KDF floor rejects degraded iterations before deriving key material', () => {
  const key = Buffer.from('dd'.repeat(32), 'hex');
  const password = 'correct horse battery staple';
  const env = encryptPrivateKey(key, password);
  env.kdf.iterations = 1000;
  assert.throws(() => decryptPrivateKey(env, password), (err) => err.code === 'DEGRADED_KDF');
});

test('v2: KDF floor rejects short salts', () => {
  const key = Buffer.from('ee'.repeat(32), 'hex');
  const password = 'correct horse battery staple';
  const env = encryptPrivateKey(key, password);
  env.kdf.salt = 'abcd'; // 2-byte salt
  assert.throws(() => decryptPrivateKey(env, password), (err) => err.code === 'DEGRADED_KDF');
});

test('legacy v1 envelopes remain decryptable (migration path)', () => {
  // Reconstruct a byte-accurate v1 envelope using the pre-v2 algorithm.
  const key = Buffer.from('ff'.repeat(32), 'hex');
  const password = 'correct horse battery staple';
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const derived = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha512');
  const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv, { authTagLength: 16 });
  let ciphertext = cipher.update(key.toString('hex'), 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const legacy = {
    envelope: 1,
    version: '1.0',
    kdf: { algorithm: 'pbkdf2-sha512', iterations: 310000, salt: salt.toString('hex'), keyLength: 32 },
    cipher: 'aes-256-gcm',
    iv: iv.toString('hex'),
    ciphertext,
    authTag: cipher.getAuthTag().toString('hex'),
    metadata: { legacy: true }
  };
  assert.equal(isValidEnvelope(legacy), true, 'v1 envelopes remain structurally valid');
  assert.deepEqual(decryptPrivateKey(legacy, password), key);
});

test('getEncryptionInfo exposes the floors for inspection/migration', () => {
  const info = getEncryptionInfo();
  assert.equal(info.envelopeVersion, 2);
  assert.equal(info.aadBound, true);
  assert.equal(info.kdf.floors.iterations, 310000);
});

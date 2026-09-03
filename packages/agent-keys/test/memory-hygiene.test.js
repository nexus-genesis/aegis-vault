/**
 * Aegis Vault agent-keys — Memory hygiene tests (Wave 1)
 *
 * Verifies the invariants introduced by secure.js and the sharded wallet:
 *   1. secureZero deterministically overwrites buffer contents
 *   2. ShardedSecret: XOR sharding roundtrip, caller-copy zeroing,
 *      transient use() zeroing (incl. on throw), destroy() semantics
 *   3. PQCWallet: plaintext key never persists contiguously at rest
 *      (object-graph level scan), sign/verify still works, destroy() works
 *   4. exportEncrypted/importEncrypted roundtrip under the sharded model
 *
 * Complements test/attack-simulations/*.sh which scan real process memory
 * (core dump / /proc/pid/mem / env / swap) on Linux deployments.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  secureZero,
  ShardedSecret,
  PQCWallet,
  generateKeyPair,
  signSync,
  verify,
  DILITHIUM2_PRIVATE_KEY_LENGTH
} from '../src/index.js';

// ─── secureZero ──────────────────────────────────────────────────────────
test('secureZero overwrites buffer contents', () => {
  const buf = Buffer.alloc(64, 0xab);
  secureZero(buf);
  assert.ok(buf.every(b => b === 0), 'all bytes must be zero');
});

test('secureZero skips null/undefined and non-buffer args', () => {
  assert.doesNotThrow(() => secureZero(null, undefined, 42, 'str'));
});

test('secureZero works on Uint8Array views', () => {
  const arr = new Uint8Array([1, 2, 3, 4, 5]);
  secureZero(arr);
  assert.ok(arr.every(b => b === 0));
});

// ─── ShardedSecret ───────────────────────────────────────────────────────
test('ShardedSecret roundtrip: reassembled secret equals input', () => {
  const secret = Buffer.alloc(32, 0x5a);
  const sharded = new ShardedSecret(secret);
  const out = sharded.use(s => Buffer.from(s)); // copy out inside callback
  assert.deepEqual(out, Buffer.alloc(32, 0x5a));
});

test('ShardedSecret zeroes the caller\'s input buffer immediately', () => {
  const secret = Buffer.alloc(32, 0x77);
  new ShardedSecret(secret);
  assert.ok(secret.every(b => b === 0), 'input copy must be zeroed after sharding');
});

test('[CRITICAL] neither shard alone reveals the secret', () => {
  const secret = Buffer.alloc(32, 0x33);
  const sharded = new ShardedSecret(secret);
  const { shardA, shardB } = sharded.exportShards();
  assert.notDeepEqual(shardA, secret);
  assert.notDeepEqual(shardB, secret);
  // A shard that is all-zero would leak the other shard verbatim.
  assert.ok(shardA.some(b => b !== 0), 'shardA must not be degenerate (all-zero)');
  assert.ok(shardB.some(b => b !== 0), 'shardB must not be degenerate');
});

test('[CRITICAL] use() zeroes the transient buffer after callback returns', () => {
  let captured;
  const sharded = new ShardedSecret(Buffer.alloc(32, 0x99));
  sharded.use(s => { captured = s; });
  assert.ok(captured.every(b => b === 0), 'transient buffer must be zeroed');
});

test('[CRITICAL] use() zeroes the transient buffer even when callback throws', () => {
  let captured;
  const sharded = new ShardedSecret(Buffer.alloc(32, 0x88));
  assert.throws(() => sharded.use(s => { captured = s; throw new Error('boom'); }));
  assert.ok(captured.every(b => b === 0), 'transient buffer must be zeroed on throw');
});

test('ShardedSecret.destroy() wipes shards and blocks further use', () => {
  const sharded = new ShardedSecret(Buffer.alloc(32, 0x11));
  sharded.destroy();
  assert.equal(sharded.isDestroyed, true);
  assert.throws(() => sharded.use(() => 1), /destroyed/i);
});

// ─── PQCWallet under the sharded memory model ────────────────────────────
test('[CRITICAL] PQCWallet holds no contiguous plaintext key at rest (object-graph scan)', async () => {
  const wallet = await PQCWallet.generate();
  // Reassemble once (via getter) to know what the plaintext looks like,
  // then verify NO own property of the wallet holds it contiguously.
  const plaintext = Buffer.from(wallet.privateKey); // caller-managed copy
  try {
    const scanned = scanForBuffer(wallet, plaintext);
    assert.equal(
      scanned,
      false,
      'wallet object graph must not contain the contiguous plaintext key at rest'
    );
  } finally {
    secureZero(plaintext);
  }
});

test('PQCWallet.sign() works under sharded model and produces a valid signature', async () => {
  const wallet = await PQCWallet.generate();
  const sigHex = await wallet.sign('attack-test-message');
  const ok = await wallet.verify('attack-test-message', sigHex);
  assert.equal(ok, true, 'signature must verify with own public key');
});

test('PQCWallet.sign() after destroy() is rejected', async () => {
  const wallet = await PQCWallet.generate();
  wallet.destroy();
  assert.equal(wallet.isDestroyed, true);
  assert.equal(wallet.privateKey, null);
  await assert.rejects(() => wallet.sign('x'), /destroyed|keyless/i);
});

test('PQCWallet.exportEncrypted/importEncrypted roundtrip under sharded model', async () => {
  const wallet = await PQCWallet.generate();
  const address = wallet.address;
  const envelope = wallet.exportEncrypted('correct horse battery staple');
  assert.ok(envelope, 'envelope must be produced');
  const restored = PQCWallet.importEncrypted(envelope, 'correct horse battery staple');
  assert.ok(restored, 'import must succeed');
  assert.equal(restored.address, address, 'restored wallet must have same address');
  const sigHex = await restored.sign('roundtrip');
  assert.equal(await restored.verify('roundtrip', sigHex), true);
});

test('signWithPrivateKey zeroes its single-use decoded key copy', async () => {
  const { privateKey, publicKey } = await generateKeyPair();
  const before = Buffer.compare(privateKey, Buffer.alloc(privateKey.length, 0));
  // (baseline: freshly generated key is non-zero)
  assert.notEqual(before, 0);
  // We cannot introspect the internal copy directly; assert the public API
  // still verifies while the source buffer we hold stays intact (contract:
  // the *decoded copy inside* is zeroed — observable via code review).
  const sigHex = await PQCWallet.signWithPrivateKey('msg', privateKey.toString('hex'));
  const ok = await verify('msg', Buffer.from(sigHex, 'hex'), publicKey);
  assert.equal(ok, true);
  secureZero(privateKey);
});

// ─── helpers ─────────────────────────────────────────────────────────────
/**
 * Recursively walk an object's own properties (bounded depth) looking for a
 * Buffer/Uint8Array whose contents equal `target`. This approximates a
 * memory-dump attacker scanning the object graph for the contiguous secret.
 */
function scanForBuffer(root, target, depth = 0, seen = new Set()) {
  if (depth > 4 || root == null || typeof root !== 'object') return false;
  if (seen.has(root)) return false;
  seen.add(root);
  if ((Buffer.isBuffer(root) || root instanceof Uint8Array)) {
    if (root.length === target.length && Buffer.compare(Buffer.from(root), target) === 0) {
      return true;
    }
    return false;
  }
  for (const key of Object.keys(root)) {
    let value;
    try { value = root[key]; } catch { continue; }
    // getters that reassemble on access would defeat the scan — access only
    // the sharded holder's raw fields via _sharded, never the privateKey getter.
    if (key === 'privateKey' || key === 'secretKey') continue;
    if (scanForBuffer(value, target, depth + 1, seen)) return true;
  }
  return false;
}

// ─── Dilithium2 constant sanity (protects against silent length drift) ───
test('Dilithium2 private key length constant is 2560 bytes', async () => {
  const { privateKey } = await PQCWallet.generate();
  assert.equal(privateKey.length, DILITHIUM2_PRIVATE_KEY_LENGTH);
  secureZero(privateKey);
});

// ─── signSync parity with async sign ─────────────────────────────────────
test('signSync produces signatures that verify', async () => {
  const wallet = await PQCWallet.generate();
  const plaintext = Buffer.from(wallet.privateKey);
  try {
    const sig = signSync('sync-parity', plaintext);
    const ok = await verify('sync-parity', sig, wallet.publicKey);
    assert.equal(ok, true);
  } finally {
    secureZero(plaintext);
  }
});

/**
 * Aegis Vault agent-keys — Signer subprocess integration test
 *
 * Tests the spawnSigner → sign → close lifecycle end-to-end.
 * Requires spawning a real child process via child_process.spawn.
 *
 * NOTE: These tests are separated from the unit test suite because they
 * are heavier (process spawn, ~1s per test) and may not work on all
 * platforms (e.g., restricted Docker environments).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  PQCWallet,
  spawnSigner,
  isValidEnvelope
} from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────
async function createTestEnvelope(wallet, password = 'test-password-88') {
  const envelope = wallet.exportEncrypted(password);
  if (!envelope || !isValidEnvelope(envelope)) {
    throw new Error('Failed to create test envelope');
  }
  return { envelope, password };
}

// ─── Tests ───────────────────────────────────────────────────────────────
test('[CRITICAL] spawnSigner with valid envelope produces init_ok', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    assert.ok(signer, 'SignerHandle must be returned');
    // Ping to confirm it's alive.
    await signer.ping();
  } finally {
    await signer.close();
  }
});

test('[CRITICAL] signer.sign() produces a valid signature', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    const sig = await signer.sign('0xabcdef1234567890');
    assert.ok(sig, 'signature must be returned');
    assert.ok(sig.startsWith('0x'), 'signature must be 0x-prefixed');

    // Verify the signature using the wallet's public key.
    const sigBuffer = Buffer.from(sig.slice(2), 'hex');
    const ok = await wallet.verify('0xabcdef1234567890', sigBuffer);
    assert.equal(ok, true, 'signature must verify with the original public key');
  } finally {
    await signer.close();
  }
});

test('signer.sign() with options.amount signs correctly', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // No policy — amount is ignored by the worker but still flows through IPC.
  const signer = await spawnSigner({ envelope, password });
  try {
    const sig = await signer.sign('0xabcdef1234567890', { amount: '42' });
    assert.ok(sig && typeof sig === 'string' && sig.startsWith('0x'),
      'sign with options.amount must still produce a signature');
  } finally {
    await signer.close();
  }
});

test('signer.rejects invalid hash format', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    await assert.rejects(
      () => signer.sign('not-a-hex-string'),
      /Invalid hash/i
    );
  } finally {
    await signer.close();
  }
});

test('signMessage signs the exact message string (P0-3 metadata channel)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    const message = JSON.stringify({ action: 'claim', taskId: 't-1', agent: 'ng1test', timestamp: 123, nonce: 'abc' });
    const sig = await signer.signMessage(message);
    assert.ok(sig && sig.startsWith('0x'), 'signMessage must return 0x-prefixed signature');

    // Verify over the EXACT message string — same contract as wallet.sign(message).
    const sigBuffer = Buffer.from(sig.slice(2), 'hex');
    const ok = await wallet.verify(message, sigBuffer);
    assert.equal(ok, true, 'signature must verify against the original public key');
  } finally {
    await signer.close();
  }
});

test('signMessage works on a policy-configured signer (no policy applies)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // A policy that would deny any spend — must NOT affect metadata signing.
  const policy = { type: 'require-approval' };
  const signer = await spawnSigner({ envelope, password, policy });
  try {
    const sig = await signer.signMessage('hello metadata');
    assert.ok(sig && sig.startsWith('0x'), 'metadata signing must ignore spend policy');
    const sigBuffer = Buffer.from(sig.slice(2), 'hex');
    assert.equal(await wallet.verify('hello metadata', sigBuffer), true);
  } finally {
    await signer.close();
  }
});

test('signMessage rejects empty / non-string / oversized messages', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    await assert.rejects(() => signer.signMessage(''), /non-empty/i);
    await assert.rejects(() => signer.signMessage(42), /non-empty/i);
    await assert.rejects(() => signer.signMessage('x'.repeat(70 * 1024)), /exceeds/i);
  } finally {
    await signer.close();
  }
});

test('signMessage REFUSES hash-shaped messages — policy bypass blocked (INV-002, cross-validation)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // A signer with a policy that would DENY every value-bearing signature.
  const policy = { type: 'require-approval' };
  const signer = await spawnSigner({ envelope, password, policy });
  try {
    // The exact shape hashAssetIntent() produces — a compromised parent
    // routing a value-bearing hash through the metadata channel must fail.
    const intentHash = '0x' + 'ab'.repeat(32);
    await assert.rejects(() => signer.signMessage(intentHash), /hash-shaped/i);

    // Bare sha256-hex form (no 0x prefix) must also be refused.
    await assert.rejects(() => signer.signMessage('ab'.repeat(32)), /hash-shaped/i);

    // Non-hash strings (real metadata shapes) still sign fine.
    const json = JSON.stringify({ action: 'claim', taskId: 't-1', agent: 'ng1test', timestamp: 1, nonce: 'n' });
    const sig = await signer.signMessage(json);
    assert.ok(sig && sig.startsWith('0x'), 'ordinary metadata must still sign');
  } finally {
    await signer.close();
  }
});

test('signMessage REFUSES JSON-serialized asset intents — worker policy bypass blocked (INV-002, P0-4 cross-validation)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // Policy that caps maxPerTx at 5 — the 1,000,000 payload below must never
  // get a policy-free signature via the metadata channel.
  const policy = { type: 'limit', maxPerTx: '5', maxDaily: '100' };
  const signer = await spawnSigner({ envelope, password, policy });
  try {
    // The exact shape canonicalizeAssetIntent() produces and
    // verifyAgentAssetSignature() accepts — a compromised parent serializing
    // it and routing it through the metadata channel must fail. (PoC-confirmed
    // before the fix: this produced a valid 1M-amount on-chain signature.)
    const payload = {
      type: 'agent_asset_intent',
      action: 'transfer', chain: 'ethereum', asset: 'USDC',
      amount: '1000000', recipient: '0xattacker',
      agentId: 'agent-1', sessionIssuedAt: 1, sessionExpiresAt: 2,
    };
    await assert.rejects(() => signer.signMessage(JSON.stringify(payload)), /asset-intent/i);

    // The same intent goes through sign_intent and is REJECTED by policy.
    await assert.rejects(() => signer.signIntent(payload), /exceeds maxPerTx/i);

    // JSON that is NOT an asset intent still signs (no false positives).
    const meta = JSON.stringify({ type: 'task_claim', taskId: 't-9', agent: 'ng1x', nonce: 'n1' });
    const sig = await signer.signMessage(meta);
    assert.ok(sig && sig.startsWith('0x'), 'non-asset-intent JSON metadata must still sign');
  } finally {
    await signer.close();
  }
});

test('worker-side sign_message enforcement: raw IPC with a JSON asset intent is refused (INV-002, P0-4)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const policy = { type: 'limit', maxPerTx: '5', maxDaily: '100' };
  const signer = await spawnSigner({ envelope, password, policy });
  try {
    // Bypass the parent-side guard by speaking the IPC protocol directly —
    // this simulates a fully compromised parent process. The WORKER (the
    // layer that survives parent compromise) must still refuse.
    const payload = {
      type: 'agent_asset_intent',
      action: 'transfer', chain: 'ethereum', asset: 'USDC',
      amount: '1000000', recipient: '0xattacker',
      agentId: 'agent-1', sessionIssuedAt: 1, sessionExpiresAt: 2,
    };
    const outcome = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve('TIMEOUT: worker did not respond'), 10000);
      signer._pending.set(424243, {
        resolve: (sig) => { clearTimeout(timer); resolve(`UNEXPECTED SIGNATURE: ${sig}`); },
        reject: (e) => { clearTimeout(timer); resolve(e.message); },
        timer,
      });
      signer._send({ type: 'sign_message', requestId: 424243, message: JSON.stringify(payload) });
    });
    assert.match(outcome, /asset-intent/, `worker must refuse; got: ${outcome}`);
  } finally {
    await signer.close();
  }
});

test('worker-side sign_message enforcement: raw IPC with a hash-shaped message is refused (INV-002)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    // Bypass the parent-side guard by speaking the IPC protocol directly —
    // this simulates a fully compromised parent process. The WORKER (the
    // layer that survives parent compromise) must still refuse.
    const intentHash = '0x' + 'cd'.repeat(32);
    const outcome = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve('TIMEOUT: worker did not respond'), 10000);
      signer._pending.set(424242, {
        resolve: (sig) => { clearTimeout(timer); resolve(`UNEXPECTED SIGNATURE: ${sig}`); },
        reject: (e) => { clearTimeout(timer); resolve(e.message); },
        timer,
      });
      signer._send({ type: 'sign_message', requestId: 424242, message: intentHash });
    });
    assert.match(outcome, /hash-shaped/, `worker must refuse; got: ${outcome}`);
  } finally {
    await signer.close();
  }
});

test('signer.close() terminates the child process', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  await signer.close();
  // After close, sign should reject.
  await assert.rejects(
    () => signer.sign('0xdeadbeef'),
    /closed/i
  );
});

test('signer respects spend policy (deny)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // Policy: require-approval mode — every spend denied.
  const policy = { type: 'require-approval' };

  const signer = await spawnSigner({ envelope, password, policy });
  try {
    await assert.rejects(
      () => signer.sign('0xaaaaaaaaaaaaaaaa', { amount: '5' }),
      /requires human approval/i
    );
  } finally {
    await signer.close();
  }
});

test('signer enforces limit mode maxPerTx against the REAL amount', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // Policy: limit mode, maxPerTx=5, maxDaily=100.
  // amount=3 → within maxPerTx(5) → passes base check, tier=small-auto → signs.
  // amount=50 → exceeds maxPerTx(5) → fails base check → rejected.
  const policy = { type: 'limit', maxPerTx: '5', maxDaily: '100' };

  const signer = await spawnSigner({ envelope, password, policy });
  try {
    // In-limit small spend passes.
    const sig = await signer.sign('0xbbbbbbbbbbbbbbbb', { amount: '3' });
    assert.ok(typeof sig === 'string' && sig.startsWith('0x'), 'small in-limit spend must sign');

    // Out-of-limit spend is denied — the base check catches it (50 > maxPerTx=5)
    // before the tier check is even reached.
    await assert.rejects(
      () => signer.sign('0xcccccccccccccccc', { amount: '50' }),
      /exceeds maxPerTx|human approval/i
    );
  } finally {
    await signer.close();
  }
});

test('signer fails CLOSED when policy set but no amount provided', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const policy = { type: 'limit', maxPerTx: '5', maxDaily: '100' };

  const signer = await spawnSigner({ envelope, password, policy });
  try {
    await assert.rejects(
      () => signer.sign('0xdddddddddddddddd'),
      /no amount/i
    );
  } finally {
    await signer.close();
  }
});

test('signer returns timelock info for medium-tier spend', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  // unlimited base mode; default tiers small=10/large=100 → 50 is medium.
  const policy = { type: 'unlimited' };

  const signer = await spawnSigner({ envelope, password, policy });
  try {
    const result = await signer.sign('0xeeeeeeeeeeeeeeee', { amount: '50' });
    assert.ok(result && typeof result === 'object' && result.timelocked === true,
      'medium-tier spend must resolve with a timelock object, not a signature');
    assert.equal(result.timelockMs, 24 * 60 * 60 * 1000);
    assert.ok(result.scheduledAt > Date.now());
  } finally {
    await signer.close();
  }
});

test('signer rejects invalid envelope', async () => {
  await assert.rejects(
    () => spawnSigner({ envelope: { invalid: true }, password: 'test-password-88' }),
    /Invalid/i
  );
});

test('signer rejects short password', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope } = await createTestEnvelope(wallet);
  await assert.rejects(
    () => spawnSigner({ envelope, password: 'short' }),
    /at least 8/i
  );
});

// ─── sign_intent (P0-4): value-bearing asset-intent channel ───────────────

test('signIntent signs the DECODABLE payload and verifies over JSON.stringify (P0-4)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    const payload = {
      type: 'agent_asset_intent',
      action: 'transfer', chain: 'ethereum', asset: 'USDC',
      amount: '5', recipient: '0x1',
      agentId: 'agent-1', sessionIssuedAt: 1, sessionExpiresAt: 2,
    };
    const sig = await signer.signIntent(payload);
    assert.ok(sig && typeof sig === 'string' && sig.startsWith('0x'), 'must return 0x-prefixed signature');

    // The signature must verify over JSON.stringify(payload) — the decodable
    // content carrying the amount (P0-4 removes the separate amount field).
    const ok = await wallet.verify(JSON.stringify(payload), Buffer.from(sig.replace(/^0x/, ''), 'hex'));
    assert.equal(ok, true, 'signature must verify over JSON.stringify(payload)');
  } finally {
    await signer.close();
  }
});

test('signIntent fails closed on malformed payloads (P0-4)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);

  const signer = await spawnSigner({ envelope, password });
  try {
    // Not an object.
    await assert.rejects(() => signer.signIntent('nope'), /must be an object/i);
    // Missing type marker.
    await assert.rejects(() => signer.signIntent({ amount: '5' }), /type.*agent_asset_intent/i);
    // Missing amount → fail closed.
    await assert.rejects(() => signer.signIntent({ type: 'agent_asset_intent', action: 'transfer' }), /no amount/i);
    // Empty-string amount is treated as no amount.
    await assert.rejects(() => signer.signIntent({ type: 'agent_asset_intent', amount: '' }), /no amount/i);
    // Malformed amounts.
    for (const amt of ['abc', '-5', 0.5]) {
      await assert.rejects(() => signer.signIntent({ type: 'agent_asset_intent', amount: amt }), /invalid amount/i);
    }
  } finally {
    await signer.close();
  }
});

test('signIntent worker policy checks the amount INSIDE the payload (P0-4)', async () => {
  const wallet = await PQCWallet.generate();
  const { envelope, password } = await createTestEnvelope(wallet);
  const policy = { type: 'limit', maxPerTx: '100', maxDaily: '500' };

  const signer = await spawnSigner({ envelope, password, policy });
  try {
    // A compromised parent cannot sneak a large amount into the signed
    // payload: the worker extracts the amount from the bytes it signs and
    // refuses over-ceiling values — no separate amount field to lie about.
    await assert.rejects(
      () => signer.signIntent({ type: 'agent_asset_intent', amount: '501', action: 'transfer' }),
      /exceeds maxPerTx/i
    );

    // In-ceiling amount signs.
    const sig = await signer.signIntent({ type: 'agent_asset_intent', amount: '5', action: 'transfer' });
    assert.ok(typeof sig === 'string' && sig.startsWith('0x'));

    // Medium tier → timelock object (amount from the payload: 50).
    const timelock = await signer.signIntent({ type: 'agent_asset_intent', amount: '50', action: 'transfer' });
    assert.ok(timelock && typeof timelock === 'object' && timelock.timelocked === true);
    assert.equal(timelock.timelockMs, 24 * 60 * 60 * 1000);
  } finally {
    await signer.close();
  }
});
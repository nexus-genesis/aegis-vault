import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createX402Guardrail, withGuardrail, verifySnapshot, createInMemoryNonceRegistry, DECISIONS } from '../src/index.js';

function hmacSigner(secret = 'guardrail-test-secret') {
  return async (preimage) =>
    crypto.createHmac('sha256', secret).update(preimage).digest('hex');
}

const basePayment = {
  amount: '5',
  payTo: '0xAbC0000000000000000000000000000000000001',
  asset: 'USDC',
  chain: 'base',
  purpose: 'api-credits',
  requestId: 'req-42'
};

// maxPerTx/maxDaily are hard ceilings; tier thresholds grade the risk of
// spends that pass the ceilings. (checkSpendAllowedTiered applies the base
// check first — over-ceiling spends are DENY, not HOLD.)
const limitPolicy = { type: 'limit', maxPerTx: '200', maxDaily: '1000', tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };

test('small-auto payment is allowed with a signed snapshot', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.ALLOW);
  assert.equal(result.tier, 'small-auto');
  assert.equal(result.snapshot.amount, '5');
  assert.equal(result.snapshot.agentId, 'agent-1');
  assert.equal(result.snapshot.kind, 'x402.payment.authorization');
  assert.ok(result.signature.length >= 64);
  assert.ok(result.snapshot.expiresAt > result.snapshot.at);
});

test('snapshot signature binds the full canonical preimage', async () => {
  const secret = 'guardrail-test-secret';
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner(secret) });
  const { snapshotPreimage, signature } = await guardrail.evaluatePayment(basePayment);
  const expected = crypto.createHmac('sha256', secret).update(snapshotPreimage).digest('hex');
  assert.equal(signature, expected);
  // preimage must be deterministic (canonical JSON, sorted keys)
  const again = await guardrail.evaluatePayment(basePayment);
  assert.notEqual(again.snapshotPreimage, snapshotPreimage, 'nonce differs per evaluation');
  assert.equal(
    again.snapshotPreimage.replace(/"nonce":"[^"]+"/, '').replace(/"at":\d+/, '').replace(/"expiresAt":\d+/, ''),
    snapshotPreimage.replace(/"nonce":"[^"]+"/, '').replace(/"at":\d+/, '').replace(/"expiresAt":\d+/, ''),
    'canonical form stable apart from freshness fields'
  );
});

test('over-limit payment is denied (fail-closed, with reason)', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment({ ...basePayment, amount: '201' });
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /maxPerTx/);
  assert.equal(result.snapshot, undefined, 'denied payments must not produce authorization snapshots');
});

test('daily cap accounts for spentToday', async () => {
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: limitPolicy,
    spentToday: () => '998',
    sign: hmacSigner()
  });
  const result = await guardrail.evaluatePayment({ ...basePayment, amount: '3' });
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /maxDaily/);
});

test('snapshot is self-contained evidence: signature embedded (and excluded from preimage)', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.snapshot.signature, result.signature,
    'snapshot must carry its own signature for downstream binders (AP2 mandate)');
  assert.ok(!result.snapshotPreimage.includes('"signature"'),
    'signature must be excluded from the signed preimage');
});

test('medium tier yields HOLD with timelock metadata (not an executable snapshot)', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment({ ...basePayment, amount: '50' });
  assert.equal(result.decision, DECISIONS.HOLD);
  assert.equal(result.tier, 'medium-timelock');
  assert.equal(result.revocable, true);
  assert.ok(result.scheduledAt > Date.now());
  assert.equal(result.snapshot, undefined);
});

test('large tier requires human approval', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  // ≤ maxPerTx (200) so the base ceiling passes, but ≥ largeThreshold (100)
  const result = await guardrail.evaluatePayment({ ...basePayment, amount: '150' });
  assert.equal(result.decision, DECISIONS.APPROVAL_REQUIRED);
  assert.equal(result.tier, 'large-require-approval');
});

test('missing policy fails closed to approval-required', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: null, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.APPROVAL_REQUIRED);
});

test('malformed payment / missing payTo / missing asset are denied', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  assert.equal((await guardrail.evaluatePayment(null)).decision, DECISIONS.DENY);
  assert.equal((await guardrail.evaluatePayment({ ...basePayment, payTo: undefined })).decision, DECISIONS.DENY);
  assert.equal((await guardrail.evaluatePayment({ ...basePayment, asset: '' })).decision, DECISIONS.DENY);
});

test('dynamic policy provider is supported (per-agent lookup)', async () => {
  const policies = new Map([
    ['agent-strict', { type: 'require-approval' }],
    ['agent-loose', { type: 'unlimited' }]
  ]);
  const guardrail = createX402Guardrail({
    agentId: 'agent-strict',
    policy: (id) => policies.get(id),
    sign: hmacSigner()
  });
  assert.equal((await guardrail.evaluatePayment(basePayment)).decision, DECISIONS.APPROVAL_REQUIRED);
});

test('constructor rejects a guardrail without a signer', () => {
  assert.throws(() => createX402Guardrail({ agentId: 'a', policy: limitPolicy }), /sign\(preimage\)/);
});

// ─── P0-3: recipient / asset / chain scoping ──────────────────────────────

const scopedPolicy = {
  ...limitPolicy,
  allowedRecipients: ['0xabc0000000000000000000000000000000000001'],
  allowedAssets: ['USDC'],
  allowedChains: ['base'],
};

test('P0-3: a payment outside the allowlisted recipient is denied', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: scopedPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment({
    ...basePayment,
    payTo: '0x000000000000000000000000000000000000dEaD',
  });
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /allowedRecipients/);
});

test('P0-3: asset and chain must both be allowlisted', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: scopedPolicy, sign: hmacSigner() });
  const badAsset = await guardrail.evaluatePayment({ ...basePayment, asset: 'PEPE' });
  assert.equal(badAsset.decision, DECISIONS.DENY);
  assert.match(badAsset.reason, /allowedAssets/);
  const badChain = await guardrail.evaluatePayment({ ...basePayment, chain: 'ronin' });
  assert.equal(badChain.decision, DECISIONS.DENY);
  assert.match(badChain.reason, /allowedChains/);
  // A missing chain cannot satisfy a configured chain allowlist.
  const noChain = await guardrail.evaluatePayment({ ...basePayment, chain: undefined });
  assert.equal(noChain.decision, DECISIONS.DENY);
});

test('P0-3: matching scoped payment is allowed and flagged as scoped', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: scopedPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.ALLOW);
  assert.equal(result.snapshot.policyScoped, true);
});

test('P0-3: an EMPTY allowlist is deny-all (fail-closed)', async () => {
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: { ...limitPolicy, allowedRecipients: [] },
    sign: hmacSigner(),
  });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /allowedRecipients/);
});

test('P0-3: legacy policy without allowlists is flagged unscoped but still evaluated', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.ALLOW);
  assert.equal(result.snapshot.policyScoped, false);
});

// ─── P0-4: atomic daily cap (concurrent TOCTOU fix) ──────────────────────

const dailyCapPolicy = { ...limitPolicy, maxDaily: '50' };

test('P0-4: concurrent payments cannot collectively exceed maxDaily', async () => {
  // 45 of 50 already spent; only ONE 5-unit payment fits.
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: dailyCapPolicy,
    spentToday: async () => '45',
    sign: hmacSigner(),
  });
  const results = await Promise.all(
    Array.from({ length: 10 }, () => guardrail.evaluatePayment(basePayment))
  );
  const allowed = results.filter((r) => r.decision === DECISIONS.ALLOW).length;
  assert.equal(allowed, 1, `only one concurrent payment may fit the remaining cap (got ${allowed})`);
  assert.equal(results.filter((r) => r.decision === DECISIONS.DENY).length, 9);
});

test('P0-4: a caller that always reports spentToday=0 is still bounded by maxDaily', async () => {
  // The classic "compromised caller lies about spend" case: 20 × 5 against a
  // 50/day cap must allow at most 10.
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: dailyCapPolicy,
    spentToday: () => '0',
    sign: hmacSigner(),
  });
  let allowed = 0;
  for (let i = 0; i < 20; i++) {
    if ((await guardrail.evaluatePayment(basePayment)).decision === DECISIONS.ALLOW) allowed++;
  }
  assert.equal(allowed, 10, `reservations must bound the daily total (got ${allowed})`);
});

test('P0-4: a custom spend ledger can veto a payment', async () => {
  let reserved = 0;
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: limitPolicy,
    sign: hmacSigner(),
    spendLedger: {
      async pending() { return '0'; },
      async reserve() { reserved++; return { reserved: false, reason: 'custom ledger veto' }; },
      async release() {},
    },
  });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /custom ledger veto/);
  assert.equal(reserved, 1, 'the injected ledger must be consulted before evidence is produced');
});

test('P0-4: failed evidence signing releases the reservation', async () => {
  let released = null;
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: limitPolicy,
    sign: async () => { throw new Error('signer offline'); },
    spendLedger: {
      async pending() { return '0'; },
      async reserve() { return { reserved: true }; },
      async release(agentId, amount) { released = { agentId, amount }; },
    },
  });
  await assert.rejects(() => guardrail.evaluatePayment(basePayment), /signer offline/);
  assert.deepEqual(released, { agentId: 'agent-1', amount: '5' });
});

// ─── P1-5: limit without ceilings fails closed through the guardrail ─────

test('P1-5: a limit policy without ceilings is denied', async () => {
  const guardrail = createX402Guardrail({
    agentId: 'agent-1',
    policy: { type: 'limit' },
    sign: hmacSigner(),
  });
  const result = await guardrail.evaluatePayment(basePayment);
  assert.equal(result.decision, DECISIONS.DENY);
  assert.match(result.reason, /without maxPerTx\/maxDaily/);
});

test('withGuardrail blocks the payment when the guardrail denies', async () => {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  let executed = 0;
  const pay = withGuardrail(guardrail, async () => { executed++; return { status: 200 }; });
  const denied = await pay({ ...basePayment, amount: '999' });
  assert.equal(denied.allowed, false);
  assert.equal(executed, 0);
  const allowed = await pay(basePayment);
  assert.equal(allowed.allowed, true);
  assert.equal(executed, 1);
  assert.equal(allowed.response.status, 200);
  assert.equal(allowed.evaluation.snapshot.payTo, basePayment.payTo);
});

// ─── D6: verifier-side snapshot validation + replay protection ──────────

function hmacVerifier(secret = 'guardrail-test-secret') {
  return async (preimage, signature) =>
    crypto.createHmac('sha256', secret).update(preimage).digest('hex') === signature;
}

async function makeSnapshot() {
  const guardrail = createX402Guardrail({ agentId: 'agent-1', policy: limitPolicy, sign: hmacSigner() });
  return guardrail.evaluatePayment(basePayment);
}

test('D6: a freshly issued snapshot verifies and consumes its nonce', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const result = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(result.valid, true);
  assert.equal(await nonceRegistry.has(snapshot.nonce), true);
});

test('D6: replaying the same snapshot is denied', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const first = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(first.valid, true);
  const replay = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(replay.valid, false);
  assert.match(replay.reason, /already consumed/);
});

test('D6: a tampered amount invalidates the signature', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const tampered = { ...snapshot, amount: '999' };
  const result = await verifySnapshot(tampered, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(result.valid, false);
  assert.match(result.reason, /invalid snapshot signature/);
});

test('D6: an expired snapshot is rejected', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const result = await verifySnapshot(snapshot, {
    verify: hmacVerifier(),
    nonceRegistry,
    now: snapshot.expiresAt + 1,
  });
  assert.equal(result.valid, false);
  assert.match(result.reason, /expired/);
});

test('D6: a non-allow decision never verifies as authorization', async () => {
  const { snapshot } = await makeSnapshot();
  const result = await verifySnapshot({ ...snapshot, decision: DECISIONS.HOLD }, {
    verify: hmacVerifier(),
    nonceRegistry: createInMemoryNonceRegistry(),
  });
  assert.equal(result.valid, false);
  assert.match(result.reason, /not allow/);
});

test('D6: missing nonce registry fails closed', async () => {
  const { snapshot } = await makeSnapshot();
  const result = await verifySnapshot(snapshot, { verify: hmacVerifier() });
  assert.equal(result.valid, false);
  assert.match(result.reason, /nonce registry required/);
});

test('D6: a forged snapshot cannot burn a legitimate nonce (DoS guard)', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const forged = { ...snapshot, amount: '999' }; // same nonce, invalid signature
  const rejected = await verifySnapshot(forged, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(rejected.valid, false);
  assert.equal(await nonceRegistry.has(snapshot.nonce), false, 'nonce must not be consumed by a forged snapshot');
  const legit = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry });
  assert.equal(legit.valid, true);
});

test('D6: consumeNonce:false allows audit re-validation of the same evidence', async () => {
  const { snapshot } = await makeSnapshot();
  const nonceRegistry = createInMemoryNonceRegistry();
  const first = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry, consumeNonce: false });
  const second = await verifySnapshot(snapshot, { verify: hmacVerifier(), nonceRegistry, consumeNonce: false });
  assert.equal(first.valid, true);
  assert.equal(second.valid, true);
  assert.equal(await nonceRegistry.has(snapshot.nonce), false);
});

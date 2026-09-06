import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createX402Guardrail, withGuardrail, DECISIONS } from '../src/index.js';

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

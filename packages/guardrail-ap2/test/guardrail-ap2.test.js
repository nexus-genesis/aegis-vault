/**
 * aegis-guardrail-ap2 — mandate binding + co-signature tests
 *
 * Focus is on the BINDING INVARIANTS (what makes a mandate provably covered
 * — or not — by a guardrail decision), not on AP2 field names, which live
 * in the swappable serializer and will migrate with the spec.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  createAp2MandateBuilder,
  registerAp2Serializer,
  snapshotHash,
  mandatePayloadHash,
  AEGIS_AP2_BINDING_VERSION
} from '../src/index.js';

// Deterministic in-test signer (HMAC over the preimage, stand-in for a
// session/PQC/remote signer).
const SECRET = Buffer.alloc(32, 0x5e);
const sign = async (preimage) => crypto.createHmac('sha256', SECRET).update(preimage).digest('hex');
const verify = async (preimage, signature) =>
  crypto.createHmac('sha256', SECRET).update(preimage).digest('hex') === signature;

// Snapshot in the shape aegis-guardrail-x402 emits on ALLOW.
const ALLOW_SNAPSHOT = {
  v: 1,
  kind: 'x402.payment.authorization',
  agentId: 'agent-007',
  amount: '2500000', // 2.5 USDC (6 decimals)
  asset: 'USDC',
  payTo: '0xabc0000000000000000000000000000000000000',
  chain: 'base-sepolia',
  purpose: 'reorder printer paper',
  requestId: 'req-42',
  tier: 'small_auto',
  decision: 'allow',
  nonce: 'n-1',
  at: Date.now() - 1_000,
  expiresAt: Date.now() + 300_000, // unexpired for the whole test run
  signature: 'hmac-signature-here'
};

test('snapshotHash is deterministic, covers content, ignores the signature field', () => {
  const a = snapshotHash(ALLOW_SNAPSHOT);
  const b = snapshotHash({ ...ALLOW_SNAPSHOT, signature: 'DIFFERENT' });
  assert.equal(a, b, 'producer signs canonical form without signature; hash must match that preimage');
  assert.notEqual(snapshotHash({ ...ALLOW_SNAPSHOT, amount: '999' }), a);
  assert.notEqual(snapshotHash({ ...ALLOW_SNAPSHOT, nonce: 'n-2' }), a, 'nonce must be bound');
  assert.match(a, /^0x[0-9a-f]{64}$/);
});

test('[CRITICAL] only ALLOW snapshots can be bound into mandates (fail-closed)', async () => {
  const builder = createAp2MandateBuilder({ sign });
  for (const decision of ['hold', 'approval-required', 'deny', undefined]) {
    await assert.rejects(
      builder.toPaymentMandate({ ...ALLOW_SNAPSHOT, decision }),
      /not payable/
    );
  }
  await assert.rejects(
    builder.toPaymentMandate({ ...ALLOW_SNAPSHOT, signature: undefined }),
    /not signed/
  );
  await assert.rejects(
    builder.toPaymentMandate({ ...ALLOW_SNAPSHOT, expiresAt: Date.now() - 1000 }),
    /expired/
  );
});

test('toPaymentMandate produces an AP2-shaped payload with a verifiable aegis binding', async () => {
  const builder = createAp2MandateBuilder({ sign, verify });
  const mandate = await builder.toPaymentMandate(ALLOW_SNAPSHOT, {
    paymentMandateId: 'pm-1',
    merchantOrigin: 'https://merchant.example',
    paymentMethod: 'credential-token-abc'
  });

  assert.equal(mandate.payment_mandate.payment_mandate_id, 'pm-1');
  assert.equal(mandate.payment_mandate.payment_details.total, '2500000');
  assert.equal(mandate.payment_mandate.payment_details.currency, 'USDC');
  assert.equal(mandate.payment_mandate.payment_details.recipient, ALLOW_SNAPSHOT.payTo);

  const binding = mandate.aegis;
  assert.equal(binding.binding_version, AEGIS_AP2_BINDING_VERSION);
  assert.equal(binding.decision, 'allow');
  assert.equal(binding.snapshot_hash, snapshotHash(ALLOW_SNAPSHOT));
  assert.ok(binding.cosignature.signature, 'cosignature present');
  assert.ok(binding.cosignature.payload_hash, 'payload hash present');
});

test('toCheckoutMandate maps contents and total', async () => {
  const builder = createAp2MandateBuilder({ sign });
  const mandate = await builder.toCheckoutMandate(ALLOW_SNAPSHOT, {
    checkoutId: 'co-9',
    merchantOrigin: 'https://merchant.example',
    contents: [{ id: 'sku-1', label: 'Paper A4', price: '1250000' }, { id: 'sku-2', label: 'Stapler', price: '1250000' }],
    total: '2500000'
  });
  assert.equal(mandate.checkout.id, 'co-9');
  assert.equal(mandate.checkout.contents.length, 2);
  assert.equal(mandate.checkout.total, '2500000');
  assert.equal(mandate.aegis.snapshot_hash, snapshotHash(ALLOW_SNAPSHOT));
});

test('[HIGH] verifyCosignature detects payload tampering and snapshot swapping', async () => {
  const builder = createAp2MandateBuilder({ sign, verify });
  const mandate = await builder.toPaymentMandate(ALLOW_SNAPSHOT, { paymentMandateId: 'pm-1' });

  const clean = await builder.verifyCosignature(mandate, { snapshot: ALLOW_SNAPSHOT });
  assert.deepEqual(clean, { ok: true, errors: [] });

  // Tamper with the payable amount after co-signing
  const tampered = structuredClone(mandate);
  tampered.payment_mandate.payment_details.total = '999999999';
  const res1 = await builder.verifyCosignature(tampered, { snapshot: ALLOW_SNAPSHOT });
  assert.equal(res1.ok, false);
  assert.ok(res1.errors.some((e) => /payload hash mismatch/.test(e)));

  // Bind to a different authorization than the one underwriting it
  const swapped = await builder.verifyCosignature(mandate, { snapshot: { ...ALLOW_SNAPSHOT, nonce: 'other' } });
  assert.equal(swapped.ok, false);
  assert.ok(swapped.errors.some((e) => /snapshot hash mismatch/.test(e)));

  // Non-payable snapshot presented as evidence
  const denied = await builder.verifyCosignature(mandate, { snapshot: { ...ALLOW_SNAPSHOT, decision: 'deny' } });
  assert.equal(denied.ok, false);
});

test('verifyCosignature fails closed without a verify-capable builder', async () => {
  const builder = createAp2MandateBuilder({ sign });
  const mandate = await builder.toPaymentMandate(ALLOW_SNAPSHOT, {});
  const res = await builder.verifyCosignature(mandate, { snapshot: ALLOW_SNAPSHOT });
  assert.equal(res.ok, false, 'structural checks alone must NOT pass verification');
  assert.ok(res.errors.some((e) => /signature NOT verified/.test(e)));
});

test('serializers are pluggable per spec version', async () => {
  registerAp2Serializer('ap2-v1x-test', {
    checkout: (snapshot) => ({ ap2v1x: { checkout: true, snapshot_hash: snapshotHash(snapshot) } }),
    payment: (snapshot) => ({ ap2v1x: { payment: true, snapshot_hash: snapshotHash(snapshot) } })
  });
  const builder = createAp2MandateBuilder({ sign, specVersion: 'ap2-v1x-test' });
  const m = await builder.toPaymentMandate(ALLOW_SNAPSHOT, {});
  assert.equal(m.ap2v1x.payment, true);
  assert.ok(m.aegis.cosignature.signature, 'binding layer is serializer-independent');

  assert.throws(() => createAp2MandateBuilder({ sign, specVersion: 'nope' }), /unknown specVersion/);
  assert.throws(() => createAp2MandateBuilder({}), /sign\(preimage\) is required/);
  assert.throws(
    () => registerAp2Serializer('bad', { checkout: () => ({}) }),
    /checkout\(snapshot, ctx\) and payment/
  );
});

test('mandatePayloadHash excludes only the cosignature, keeps other aegis binding fields bound', async () => {
  const builder = createAp2MandateBuilder({ sign });
  const mandate = await builder.toPaymentMandate(ALLOW_SNAPSHOT, { paymentMandateId: 'pm-9' });
  const { cosignature, ...aegisRest } = mandate.aegis;
  const recomputed = mandatePayloadHash({ ...mandate, aegis: aegisRest });
  assert.equal(recomputed, cosignature.payload_hash);

  // Changing a bound binding field (e.g. claimed decision) changes the hash
  const doctored = { ...mandate, aegis: { ...aegisRest, decision: 'deny' } };
  assert.notEqual(mandatePayloadHash(doctored), cosignature.payload_hash);
});

/**
 * E3 hardening: monotonic session narrowing (权限只降不升).
 */
import test from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/pqc.js';
import {
  createSessionKey,
  narrowSession,
  checkSessionAccess,
  verifySessionSignature,
} from '../src/session.js';

const TTL = 60 * 60 * 1000; // 1h

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair();
  const parent = createSessionKey(privateKey, {
    agentId: 'agent-narrow',
    allowedContracts: ['0xA', '0xB'],
    allowedMethods: ['transfer', 'approve'],
    allowedChains: ['ethereum', 'polygon'],
    maxPerTx: '100',
    maxDaily: '1000',
    ttl: TTL,
  });
  return { publicKey, privateKey, parent };
}

test('narrowSession derives a valid narrower session (subset + lower limits)', async () => {
  const { publicKey, privateKey, parent } = await setup();
  const child = narrowSession(parent, {
    agentId: 'agent-narrow',
    allowedContracts: ['0xA'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '50',
    maxDaily: '200',
    ttl: TTL,
  }, privateKey);

  assert.equal(child.agentId, parent.agentId);
  assert.deepEqual(child.allowedContracts, ['0xA']);
  assert.equal(child.maxPerTx, '50');
  assert.ok(child.expiresAt <= parent.expiresAt);
  assert.equal(await verifySessionSignature(child, publicKey), true);

  // child actually enforces the narrower scope
  assert.equal(checkSessionAccess(child, { contract: '0xB' }).allowed, false);
  assert.equal(checkSessionAccess(child, { amount: '60' }).allowed, false); // > 50
});

test('narrowSession rejects contract whitelist widening', async () => {
  const { privateKey, parent } = await setup();
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', allowedContracts: ['0xC'], ttl: TTL }, privateKey),
    /allowedContracts widening rejected/
  );
});

test('narrowSession rejects dropping a whitelist entirely (→ unrestricted)', async () => {
  const { privateKey, parent } = await setup();
  // EXPLICIT empty list = "all contracts" — an escalation under a limited parent.
  // (Omitting the field instead inherits the parent scope and is allowed.)
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', allowedContracts: [], ttl: TTL }, privateKey),
    /allowedContracts widening rejected/
  );
  // Omitted dims inherit → this must succeed
  const child = narrowSession(parent, { agentId: 'agent-narrow', maxPerTx: '10', ttl: TTL }, privateKey);
  assert.deepEqual(child.allowedContracts, ['0xA', '0xB']);
  assert.deepEqual(child.allowedMethods, ['transfer', 'approve']);
  assert.equal(child.maxDaily, '1000');
});

test('narrowSession rejects method/chain widening', async () => {
  const { privateKey, parent } = await setup();
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', allowedMethods: ['swap'], ttl: TTL }, privateKey),
    /allowedMethods widening rejected/
  );
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', allowedChains: ['solana'], ttl: TTL }, privateKey),
    /allowedChains widening rejected/
  );
});

test('narrowSession rejects maxPerTx escalation and unlimited-under-limit', async () => {
  const { privateKey, parent } = await setup();
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', maxPerTx: '500', ttl: TTL }, privateKey),
    /maxPerTx widening rejected/
  );
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', maxDaily: '5000', ttl: TTL }, privateKey),
    /maxDaily widening rejected/
  );
});

test('narrowSession rejects unlimited child under limited parent', async () => {
  const { privateKey, parent } = await setup();
  // '0' explicitly means no limit — under a limited parent that is an escalation.
  assert.throws(
    () => narrowSession(parent, { agentId: 'agent-narrow', maxPerTx: '0', ttl: TTL }, privateKey),
    /maxPerTx widening rejected/
  );
});

test('narrowSession clamps expiry to parent expiry (never later)', async () => {
  const { privateKey, parent } = await setup();
  const child = narrowSession(parent, {
    agentId: 'agent-narrow',
    allowedContracts: ['0xA'],
    maxPerTx: '10',
    ttl: 24 * 60 * 60 * 1000, // request 24h — must clamp to parent's 1h
  }, privateKey);
  assert.ok(child.expiresAt <= parent.expiresAt + 50); // small scheduling slack
  assert.ok(child.expiresAt > Date.now());
});

test('narrowSession rejects agentId mismatch and non-session parent', async () => {
  const { privateKey, parent } = await setup();
  assert.throws(
    () => narrowSession(parent, { agentId: 'other-agent', ttl: TTL }, privateKey),
    /agentId mismatch/
  );
  assert.throws(
    () => narrowSession({ type: 'bogus' }, { agentId: 'x', ttl: TTL }, privateKey),
    TypeError
  );
});

test('narrowSession from an unrestricted parent works (narrowing from open scope)', async () => {
  const { privateKey } = await setup();
  const open = createSessionKey(privateKey, { agentId: 'agent-open', ttl: TTL }); // all-empty, '0' limits
  const child = narrowSession(open, {
    agentId: 'agent-open',
    allowedContracts: ['0xA'],
    maxPerTx: '10',
    ttl: TTL,
  }, privateKey);
  assert.deepEqual(child.allowedContracts, ['0xA']);
  assert.equal(child.maxPerTx, '10');
});
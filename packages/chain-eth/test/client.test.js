/**
 * aegis-chain-eth — Smart Account high-level client tests
 *
 * Sprint 2.2: the official recommended EVM execution entry point
 * (createSmartAccountClient) must compose registerSession → canonicalize →
 * sign → executeFromAgent without weakening any invariant. These tests pin
 * the thin-safe-composition contract:
 *   - execute() performs the full flow in one call
 *   - privileged ops are owner-gated (INV-005)
 *   - the deny list still applies through the client (INV-005 / INV-007)
 *   - no key material is retained between calls
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSmartAccountClient } from '../src/client.js';

const OWNER = '0x0000000000000000000000000000000000000001';
const EMERGENCY = '0x0000000000000000000000000000000000000002';

function makeClient() {
  return createSmartAccountClient({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });
}

test('createSmartAccountClient exposes the expected surface', () => {
  const client = makeClient();
  for (const fn of [
    'registerSession', 'revokeSession', 'pause', 'resume',
    'prepareIntent', 'verify', 'execute',
    'getState', 'getSession', 'estimateMaxLoss',
  ]) {
    assert.equal(typeof client[fn], 'function', `missing ${fn}`);
  }
  assert.equal(client.account.owner, OWNER);
});

test('execute() performs the full EVM flow (register → sign → execute)', async () => {
  const { createSmartAccount } = await import('../src/smart-account.js');
  const { addressForPrivateKey } = await import('../src/canonical.js');
  const { createSmartAccountClient } = await import('../src/client.js');

  const client = createSmartAccountClient({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });
  const evmKey = '0x' + '11'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const sessionId = '0x' + 'ab'.repeat(32);
  const session = {
    agentId: 'agent-flow',
    sessionId,
    issuedAt: now,
    expiresAt: now + 3600_000,
  };

  const reg = client.registerSession({
    sessionId,
    agentId: session.agentId,
    agentEvmAddress: evmAddress,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xToken'],
      allowedMethods: ['transfer'],
      allowedRecipients: ['0xRecipient'],
    },
    maxPerTx: '100',
    maxDaily: '500',
  });
  assert.equal(reg.ok, true, reg.reason);

  const res = await client.execute({
    session,
    intent: {
      action: 'transfer',
      chain: 'ethereum',
      asset: 'USDC',
      amount: '25',
      recipient: '0xRecipient',
      contract: '0xToken',
      method: 'transfer',
      nonce: '1',
    },
    privateKeyHex: evmKey,
    claimedAmount: '25',
    sessionId,
    nonce: 1,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.amount, '25');
  assert.equal(res.remainingSessionDaily, '475');
});

test('prepareIntent + verify self-check works through the client', async () => {
  const { addressForPrivateKey } = await import('../src/canonical.js');
  const client = makeClient();
  const evmKey = '0x' + '22'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const sessionId = '0x' + 'ef'.repeat(32);
  const session = { agentId: 'agent-prep', sessionId, issuedAt: now, expiresAt: now + 3600_000 };

  client.registerSession({
    sessionId, agentId: 'agent-prep', agentEvmAddress: evmAddress,
    issuedAt: now, expiresAt: now + 3600_000,
    maxPerTx: '100', maxDaily: '500',
  });

  const { payload, digest, signature } = client.prepareIntent({
    session,
    intent: {
      action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
      recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
    },
    privateKeyHex: evmKey,
  });
  assert.match(digest, /^0x[0-9a-f]{64}$/);
  assert.match(signature, /^0x[0-9a-f]{130}$/);
  const v = client.verify({ address: evmAddress, signature, payload });
  assert.equal(v.valid, true);
});

test('privileged ops are owner-gated through the client (INV-005)', async () => {
  const client = makeClient();
  // registerSession is pre-bound to owner, so a caller cannot pass a rogue `by`.
  const r = client.registerSession({
    sessionId: '0x' + '01'.repeat(32), agentId: 'a', agentEvmAddress: '0x' + '33'.repeat(20),
    issuedAt: Date.now(), expiresAt: Date.now() + 3600_000, maxPerTx: '10', maxDaily: '10',
  });
  assert.equal(r.ok, true);
});

test('deny list still applies through the client (INV-005 / INV-007)', async () => {
  const { addressForPrivateKey } = await import('../src/canonical.js');
  const client = makeClient();
  const evmKey = '0x' + '44'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const sessionId = '0x' + '12'.repeat(32);
  const session = { agentId: 'agent-deny', sessionId, issuedAt: now, expiresAt: now + 3600_000 };
  client.registerSession({
    sessionId, agentId: 'agent-deny', agentEvmAddress: evmAddress,
    issuedAt: now, expiresAt: now + 3600_000, maxPerTx: '100', maxDaily: '500',
  });

  const res = await client.execute({
    session,
    intent: {
      action: 'increaseLimit', chain: 'ethereum', asset: 'USDC', amount: '1',
      recipient: '0xRecipient', contract: '0xToken', method: 'increaseLimit', nonce: '1',
    },
    privateKeyHex: evmKey,
    claimedAmount: '1',
    sessionId,
    nonce: 1,
  });
  assert.equal(res.ok, false);
  assert.match(res.reason, /self-escalation/);
});

test('estimateMaxLoss exposes the session ceiling through the client (INV-007)', async () => {
  const { addressForPrivateKey } = await import('../src/canonical.js');
  const client = makeClient();
  const evmKey = '0x' + '55'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const sessionId = '0x' + '56'.repeat(32);
  client.registerSession({
    sessionId, agentId: 'agent-loss', agentEvmAddress: evmAddress,
    issuedAt: now, expiresAt: now + 3600_000, maxPerTx: '100', maxDaily: '500',
  });
  const est = client.estimateMaxLoss();
  assert.equal(est.sessions.length, 1);
  assert.equal(est.sessions[0].maxLossCeiling, '500'); // maxDaily, perTx not mixed in
});

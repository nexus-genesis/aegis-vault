/**
 * aegis-agent-sdk — smartAccount official recommended entry tests
 *
 * Sprint 2.2: the SDK facade must forward to the chain-eth implementation
 * without weakening invariants, and it must load lazily (no static import of
 * chain-eth, which would create a module init cycle).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { smartAccount } from '../src/index.js';

const OWNER = '0x0000000000000000000000000000000000000001';
const EMERGENCY = '0x0000000000000000000000000000000000000002';

test('smartAccount facade exposes the official recommended functions', () => {
  for (const fn of [
    'createSmartAccountClient',
    'signSmartAccountIntent',
    'verifySmartAccountIntent',
    'hashIntentDigest',
  ]) {
    assert.equal(typeof smartAccount[fn], 'function', `missing ${fn}`);
  }
});

test('createSmartAccountClient via SDK facade executes the full EVM flow', async () => {
  const { addressForPrivateKey } = await import('aegis-chain-eth');
  const client = await smartAccount.createSmartAccountClient({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });

  const evmKey = '0x' + '11'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const sessionId = '0x' + 'ab'.repeat(32);
  const session = { agentId: 'sdk-agent', sessionId, issuedAt: now, expiresAt: now + 3600_000 };

  const reg = client.registerSession({
    sessionId, agentId: 'sdk-agent', agentEvmAddress: evmAddress,
    issuedAt: now, expiresAt: now + 3600_000,
    whitelist: {
      allowedChains: ['ethereum'], allowedAssets: ['USDC'],
      allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'],
    },
    maxPerTx: '100', maxDaily: '500',
  });
  assert.equal(reg.ok, true, reg.reason);

  const res = await client.execute({
    session,
    intent: {
      action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
      recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
    },
    privateKeyHex: evmKey,
    claimedAmount: '25',
    sessionId,
    nonce: 1,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.amount, '25');
});

test('signSmartAccountIntent via SDK facade produces a valid self-verified signature', async () => {
  const { addressForPrivateKey } = await import('aegis-chain-eth');
  const evmKey = '0x' + '22'.repeat(32);
  const evmAddress = addressForPrivateKey(evmKey);
  const now = Date.now();
  const session = { agentId: 'a', sessionId: '0x' + 'cd'.repeat(32), issuedAt: now, expiresAt: now + 3600_000 };
  const { payload, digest, signature } = await smartAccount.signSmartAccountIntent({
    session,
    intent: {
      action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
      recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
    },
    privateKeyHex: evmKey,
  });
  assert.match(digest, /^0x[0-9a-f]{64}$/);
  const v = await smartAccount.verifySmartAccountIntent({ address: evmAddress, signature, payload });
  assert.equal(v.valid, true);
});

test('hashIntentDigest via SDK facade is fail-closed on missing fields', async () => {
  await assert.rejects(
    () => smartAccount.hashIntentDigest({ action: 'transfer' }),
    /missing/,
  );
});

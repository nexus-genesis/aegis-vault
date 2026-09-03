/**
 * Aegis Vault agent-keys — Session Key tests
 *
 * Tests the session key lifecycle:
 *   1. createSessionKey with valid parameters
 *   2. checkSessionAccess for contract/method/chain/amount checks
 *   3. Expiry enforcement
 *   4. Signature verification
 *   5. Negative/edge cases
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createSessionKey,
  checkSessionAccess,
  verifySessionSignature,
  getSessionTTL,
  isSessionExpired,
  generateKeyPair
} from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────
const TEST_AGENT = 'my-agent-01';
const TEST_CONTRACT = '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984';
const TEST_METHOD = 'swap';
const TEST_CHAIN = 'ethereum';

function validSession(issuerKey, overrides = {}) {
  return createSessionKey(issuerKey, {
    agentId: TEST_AGENT,
    allowedContracts: [TEST_CONTRACT],
    allowedMethods: [TEST_METHOD],
    allowedChains: [TEST_CHAIN],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 7 * 24 * 60 * 60 * 1000,
    ...overrides
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────
test('createSessionKey produces a valid session key token', async () => {
  const { privateKey } = await generateKeyPair();
  const session = validSession(privateKey);

  assert.equal(session.type, 'session_key');
  assert.equal(session.version, 1);
  assert.equal(session.agentId, TEST_AGENT);
  assert.ok(session.issuedAt, 'must have issuedAt');
  assert.ok(session.expiresAt > session.issuedAt, 'expiresAt must be after issuedAt');
  assert.ok(session.signature, 'must have signature');
  assert.deepEqual(session.allowedContracts, [TEST_CONTRACT]);
  assert.deepEqual(session.allowedMethods, [TEST_METHOD]);
  assert.deepEqual(session.allowedChains, [TEST_CHAIN]);
  assert.equal(session.maxPerTx, '100');
  assert.equal(session.maxDaily, '500');
});

test('checkSessionAccess.allows valid operation within scope', () => {
  // We need a real key for createSessionKey, but for checkSessionAccess
  // we just need a valid session object. We'll create one with a key.
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [TEST_CONTRACT],
    allowedMethods: [TEST_METHOD],
    allowedChains: [TEST_CHAIN],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    contract: TEST_CONTRACT,
    method: TEST_METHOD,
    chain: TEST_CHAIN,
    amount: '50'
  });
  assert.equal(result.allowed, true);
});

test('checkSessionAccess.rejects expired session', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 86400000,
    expiresAt: Date.now() - 1000, // expired
    allowedContracts: [TEST_CONTRACT],
    allowedMethods: [TEST_METHOD],
    allowedChains: [TEST_CHAIN],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    contract: TEST_CONTRACT,
    method: TEST_METHOD,
    chain: TEST_CHAIN,
    amount: '50'
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('expired'));
});

test('checkSessionAccess.rejects contract not in whitelist', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [TEST_CONTRACT],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    contract: '0x0000000000000000000000000000000000000000',
    method: TEST_METHOD,
    chain: TEST_CHAIN,
    amount: '50'
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('whitelist'));
});

test('checkSessionAccess.rejects method not in whitelist', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [TEST_METHOD],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    method: 'transfer',
    chain: TEST_CHAIN,
    amount: '50'
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('whitelist'));
});

test('checkSessionAccess.rejects chain not in whitelist', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [TEST_CHAIN],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    chain: 'polygon',
    amount: '50'
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('whitelist'));
});

test('checkSessionAccess.rejects amount exceeding maxPerTx', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, { amount: '150' });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('maxPerTx'));
});

test('checkSessionAccess.rejects amount exceeding daily limit', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, {
    amount: '60',
    spentToday: '480'
  });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('daily limit'));
});

test('verifySessionSignature.validates genuine session key', async () => {
  const { privateKey, publicKey } = await generateKeyPair();
  const session = validSession(privateKey);

  const valid = await verifySessionSignature(session, publicKey);
  assert.equal(valid, true);
});

test('verifySessionSignature.rejects tampered session key', async () => {
  const { privateKey, publicKey } = await generateKeyPair();
  const session = validSession(privateKey);

  // Tamper with the maxPerTx.
  const tampered = { ...session, maxPerTx: '999999' };
  const valid = await verifySessionSignature(tampered, publicKey);
  assert.equal(valid, false);
});

test('verifySessionSignature.rejects session with wrong issuer key', async () => {
  const { privateKey } = await generateKeyPair();
  const { publicKey: wrongKey } = await generateKeyPair();
  const session = validSession(privateKey);

  const valid = await verifySessionSignature(session, wrongKey);
  assert.equal(valid, false);
});

test('createSessionKey rejects invalid TTL', async () => {
  const { privateKey } = await generateKeyPair();
  assert.throws(() => createSessionKey(privateKey, {
    agentId: TEST_AGENT,
    ttl: 100 // too short
  }), /ttl/i);

  assert.throws(() => createSessionKey(privateKey, {
    agentId: TEST_AGENT,
    ttl: 999 * 24 * 60 * 60 * 1000 // too long
  }), /ttl/i);
});

test('getSessionTTL and isSessionExpired work correctly', () => {
  const session = {
    type: 'session_key',
    expiresAt: Date.now() + 86400000 // 1 day from now
  };
  const ttl = getSessionTTL(session);
  assert.ok(ttl > 0 && ttl <= 86400000, 'TTL should be positive and within range');
  assert.equal(isSessionExpired(session), false);

  const expiredSession = {
    type: 'session_key',
    expiresAt: Date.now() - 1000 // already expired
  };
  assert.equal(getSessionTTL(expiredSession), 0);
  assert.equal(isSessionExpired(expiredSession), true);
});

test('session key with no whitelist allows all contracts/methods/chains', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '0',
    maxDaily: '0',
    signature: 'test'
  };

  // Empty whitelist = no restriction.
  const result = checkSessionAccess(session, {
    contract: '0xanything',
    method: 'anything',
    chain: 'anything',
    amount: '0'
  });
  assert.equal(result.allowed, true);
});

test('checkSessionAccess.rejects malformed amount without throwing', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  // Non-numeric / non-integer values must be denied, not crash the caller.
  for (const bad of ['abc', '1.5', '', NaN, {}, '12abc']) {
    const result = checkSessionAccess(session, { amount: bad });
    assert.equal(result.allowed, false, `amount ${String(bad)} must be denied`);
    assert.ok(result.reason.includes('invalid'), `reason must mention invalid for ${String(bad)}`);
  }
});

test('checkSessionAccess.rejects malformed spentToday without throwing', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  const result = checkSessionAccess(session, { amount: '10', spentToday: 'not-a-number' });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('invalid'));
});

test('checkSessionAccess.rejects negative amount and spentToday', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  assert.equal(checkSessionAccess(session, { amount: '-5' }).allowed, false);
  assert.equal(checkSessionAccess(session, { amount: '5', spentToday: '-10' }).allowed, false);
});

test('checkSessionAccess.enforces maxDaily even without spentToday', () => {
  const session = {
    type: 'session_key',
    version: 1,
    agentId: TEST_AGENT,
    issuedAt: Date.now() - 1000,
    expiresAt: Date.now() + 86400000,
    allowedContracts: [],
    allowedMethods: [],
    allowedChains: [],
    maxPerTx: '100',
    maxDaily: '500',
    signature: 'test'
  };

  // A single tx larger than the whole daily cap must be denied even when
  // the caller does not track spentToday (spentToday defaults to 0).
  const result = checkSessionAccess(session, { amount: '600' });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('daily limit') || result.reason.includes('maxPerTx'));
});
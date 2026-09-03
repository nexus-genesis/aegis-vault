/**
 * aegis-chain-eth — Smart Account (P0-5) security test suite
 *
 * Covers the on-chain hard-policy layer:
 *   INV-002  amount binding (signed amount must equal claimed tx amount)
 *   INV-003  bounded sessions (expiry, whitelist, revocation)
 *   INV-005  no self-escalation (escalating actions rejected even if signed)
 *   INV-006  emergency key is brake-only
 *   INV-007  bounded blast radius (per-tx + cumulative ceilings, nonce
 *            anti-replay, quantifiable estimateMaxLoss)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createSmartAccount } from '../src/smart-account.js';
import { addressForPrivateKey, signSmartAccountIntent } from '../src/canonical.js';
import { canonicalizeAssetIntent } from 'aegis-agent-sdk';
import { PQCWallet } from 'aegis-vault';

// ─── Helpers ─────────────────────────────────────────────────────────────

const OWNER = '0x0000000000000000000000000000000000000001';
const EMERGENCY = '0x0000000000000000000000000000000000000002';

async function setupAccount(overrides = {}) {
  const wallet = await PQCWallet.generate(); // agent key
  const acct = createSmartAccount({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
    ...overrides,
  });
  const now = Date.now();
  const session = {
    agentId: 'agent-1',
    issuedAt: now,
    expiresAt: now + 60 * 60 * 1000,
  };
  return { wallet, acct, session };
}

function registerDefaultSession(acct, session, wallet, overrides = {}) {
  const r = acct.registerSession({
    by: OWNER,
    sessionId: 's1',
    agentId: session.agentId,
    agentPublicKey: wallet.publicKey,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xContract'],
      allowedMethods: ['transfer'],
      allowedRecipients: ['0xRecipient'],
    },
    maxPerTx: '100',
    maxDaily: '500',
    ...overrides,
  });
  assert.equal(r.ok, true, r.reason);
  return r;
}

/**
 * Signs an intent. When `nonce` is provided it is embedded in the signed
 * payload (the P0-5 cross-validation contract: every execution must bind its
 * nonce into the signed content, making signatures single-use).
 */
async function makeSignedIntent(session, intent, nonce) {
  const full = nonce === undefined ? intent : { ...intent, nonce };
  const canonical = canonicalizeAssetIntent(session, full);
  const sig = await session.__wallet.sign(JSON.stringify(canonical));
  return { canonical, sig };
}

// ─── Setup / register ────────────────────────────────────────────────────

test('createSmartAccount validates owner/emergencyKey/hard ceilings', () => {
  assert.throws(() => createSmartAccount({ emergencyKey: EMERGENCY }), /owner/);
  assert.throws(() => createSmartAccount({ owner: OWNER }), /emergencyKey/);
  assert.throws(
    () => createSmartAccount({ owner: OWNER, emergencyKey: EMERGENCY, policy: { type: 'limit' } }),
    /maxPerTx/
  );
  const acct = createSmartAccount({ owner: OWNER, emergencyKey: EMERGENCY, policy: { type: 'limit', maxPerTx: '1', maxDaily: '2' } });
  assert.equal(acct.policy.maxPerTx, '1');
});

test('registerSession: ONLY the owner may register (INV-005)', async () => {
  const { acct, session, wallet } = await setupAccount();
  const r = acct.registerSession({
    by: '0xAgentAttempt',
    sessionId: 'evil',
    agentId: session.agentId,
    agentPublicKey: wallet.publicKey,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    maxPerTx: '100',
    maxDaily: '500',
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /owner/i);
  assert.equal(acct.getSession('evil'), null);
});

test('registerSession: missing hard ceilings fail closed (INV-007)', async () => {
  const { acct, session, wallet } = await setupAccount();
  const r = acct.registerSession({
    by: OWNER,
    sessionId: 'nocap',
    agentId: session.agentId,
    agentPublicKey: wallet.publicKey,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /maxPerTx|ceilings/i);
});

// ─── executeFromAgent: happy path + INV-002 amount binding ───────────────

test('executeFromAgent: valid signed intent executes and accrues spend', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, true, res.reason);
  assert.ok(res.txId.startsWith('0x'));
  assert.equal(res.amount, '10');
  assert.equal(res.spentSession, '10');
  assert.equal(res.remainingSessionDaily, '490');
  assert.equal(acct.getState().executions, 1);
});

test('executeFromAgent: official EVM digest signature path mirrors Solidity', async () => {
  const acct = createSmartAccount({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });
  const session = {
    agentId: 'agent-evm',
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60 * 60 * 1000,
    sessionId: '0x' + 'ab'.repeat(32),
  };
  const evmPrivateKey = '0x' + '11'.repeat(32);
  const evmAddress = addressForPrivateKey(evmPrivateKey);
  const reg = acct.registerSession({
    by: OWNER,
    sessionId: session.sessionId,
    agentId: session.agentId,
    agentEvmAddress: evmAddress,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xContract'],
      allowedMethods: ['transfer'],
      allowedRecipients: ['0xRecipient'],
    },
    maxPerTx: '100',
    maxDaily: '500',
  });
  assert.equal(reg.ok, true, reg.reason);

  const signed = signSmartAccountIntent({
    session,
    intent: {
      action: 'transfer',
      chain: 'ethereum',
      asset: 'USDC',
      amount: '25',
      recipient: '0xRecipient',
      contract: '0xContract',
      method: 'transfer',
      nonce: '1',
    },
    privateKeyHex: evmPrivateKey,
  });
  const res = await acct.executeFromAgent({
    payload: signed.payload,
    signature: signed.signature,
    claimedAmount: '25',
    sessionId: session.sessionId,
    nonce: 1,
  });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.amount, '25');
});

test('INV-002: claimed amount diverging from signed payload amount is rejected', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '99999', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /amount mismatch/i);
});

test('INV-002: forged signature is rejected (session-bound public key used)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const attacker = await PQCWallet.generate();
  const { canonical } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  const forgedSig = await attacker.sign(JSON.stringify(canonical));
  const res = await acct.executeFromAgent({ payload: canonical, signature: forgedSig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /signature|binding/i);
});

// ─── INV-003: bounded sessions ───────────────────────────────────────────

test('INV-003: whitelist violations are rejected on-chain (chain/asset/contract/method/recipient)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const bad = [
    { action: 'transfer', chain: 'solana', asset: 'USDC', amount: '10', recipient: '0xRecipient', contract: '0xContract', method: 'transfer' },
    { action: 'transfer', chain: 'ethereum', asset: 'USDT', amount: '10', recipient: '0xRecipient', contract: '0xContract', method: 'transfer' },
    { action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10', recipient: '0xRecipient', contract: '0xOther', method: 'transfer' },
    { action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10', recipient: '0xRecipient', contract: '0xContract', method: 'swap' },
    { action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10', recipient: '0xEvil', contract: '0xContract', method: 'transfer' },
  ];
  for (let i = 0; i < bad.length; i++) {
    const { canonical, sig } = await makeSignedIntent(session, bad[i]);
    const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: i + 1 });
    assert.equal(res.ok, false, `case ${i} must be rejected`);
    assert.match(res.reason, /whitelist/i);
  }
});

test('INV-003: revoked session signatures are rejected on-chain', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  });
  const rev = acct.revokeSession({ by: EMERGENCY, sessionId: 's1' });
  assert.equal(rev.ok, true);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /revoked/i);
});

test('INV-003: expired-session payload is rejected on-chain', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  // Session already expired at registration time is rejected.
  const r = acct.registerSession({
    by: OWNER,
    sessionId: 'old',
    agentId: session.agentId,
    agentPublicKey: wallet.publicKey,
    issuedAt: Date.now() - 10000,
    expiresAt: Date.now() - 1000,
    maxPerTx: '100',
    maxDaily: '500',
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /expired/i);
});

test('INV-003: payload bound to a DIFFERENT session is rejected', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const other = { agentId: 'agent-9', issuedAt: session.issuedAt, expiresAt: session.expiresAt };
  other.__wallet = wallet;
  const { canonical, sig } = await makeSignedIntent(other, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  });
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /agentId/i);
});

// ─── INV-005: no self-escalation ─────────────────────────────────────────

test('INV-005: self-escalation actions are rejected on-chain even with a VALID signature', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  // Whitelist deliberately ALLOWS these methods — the chain layer must
  // still refuse them regardless (INV-005 is stronger than the whitelist).
  registerDefaultSession(acct, session, wallet, {
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xContract'],
      allowedMethods: ['transfer', 'increaseLimit', 'addOwner', 'upgrade', 'grantRole', 'setPolicy', 'delegatecall', 'transferOwnership', 'setMaxPerTx'],
      allowedRecipients: ['0xRecipient'],
    },
  });

  const escalationActions = [
    'increaseLimit', 'addOwner', 'upgrade', 'grantRole', 'setPolicy',
    'delegatecall', 'transferOwnership', 'setMaxPerTx', 'destroy',
  ];
  for (let i = 0; i < escalationActions.length; i++) {
    const { canonical, sig } = await makeSignedIntent(session, {
      action: escalationActions[i], chain: 'ethereum', asset: 'USDC', amount: '10',
      recipient: '0xRecipient', contract: '0xContract', method: escalationActions[i],
    });
    const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: i + 1 });
    assert.equal(res.ok, false, `action ${escalationActions[i]} must be rejected`);
    assert.match(res.reason, /self-escalation|INV-005/i);
  }
});

test('INV-005: non-escalating actions still pass the chain layer', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '5',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '5', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, true, res.reason);
});

// ─── INV-006: emergency brake-only ───────────────────────────────────────

test('INV-006: pause blocks executions; only owner can resume', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  assert.equal(acct.pause({ by: EMERGENCY }).ok, true);
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  });
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /paused/i);

  // Emergency cannot resume (brake-only).
  assert.equal(acct.resume({ by: EMERGENCY }).ok, false);
  // Owner can.
  assert.equal(acct.resume({ by: OWNER }).ok, true);
});

test('INV-006: freeze blocks executions permanently; only owner can unfreeze', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  assert.equal(acct.freeze({ by: OWNER }).ok, false, 'freeze is emergency-only');
  assert.equal(acct.freeze({ by: EMERGENCY }).ok, true);
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  });
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /frozen/i);

  // Emergency cannot unfreeze its own brake; owner can.
  assert.equal(acct.unfreeze({ by: EMERGENCY }).ok, false);
  assert.equal(acct.unfreeze({ by: OWNER }).ok, true);
});

test('INV-006: emergencyReduceLimit is reduce-only — raising is rejected', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // Raise attempts rejected.
  const raise = acct.emergencyReduceLimit({ by: EMERGENCY, sessionId: 's1', maxPerTx: '999' });
  assert.equal(raise.ok, false);
  assert.match(raise.reason, /reduce-only/i);
  const raise2 = acct.emergencyReduceLimit({ by: EMERGENCY, sessionId: 's1', maxDaily: '9999' });
  assert.equal(raise2.ok, false);

  // Lower allowed.
  const lower = acct.emergencyReduceLimit({ by: EMERGENCY, sessionId: 's1', maxPerTx: '50', maxDaily: '200' });
  assert.equal(lower.ok, true);
  assert.equal(lower.maxPerTx, '50');
  assert.equal(lower.maxDaily, '200');

  // Non-emergency cannot reduce.
  assert.equal(acct.emergencyReduceLimit({ by: OWNER, sessionId: 's1', maxPerTx: '1' }).ok, false);
});

test('INV-006: emergency key cannot move assets (no execution path exists for it)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // A signature by the EMERGENCY key is not bound to any session's agent
  // public key, so executeFromAgent rejects it (no money path for emergency).
  const emergencyWallet = await PQCWallet.generate();
  const canonical = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
    nonce: '1',
  });
  const sig = await emergencyWallet.sign(JSON.stringify(canonical));
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
});

// ─── INV-007: hard bounds + anti-replay ──────────────────────────────────

test('INV-007: nonce anti-replay — reuse and regression are rejected', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const intent = {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  };
  const { canonical, sig } = await makeSignedIntent(session, intent, 1);
  const first = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(first.ok, true);

  // Replay the exact same nonce.
  const replay = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(replay.ok, false);
  assert.match(replay.reason, /replay/i);

  // Skip ahead then regress.
  const { canonical: c2, sig: s2 } = await makeSignedIntent(session, intent, 5);
  const skip = await acct.executeFromAgent({ payload: c2, signature: s2, claimedAmount: '10', sessionId: 's1', nonce: 5 });
  assert.equal(skip.ok, true);
  const { canonical: c3, sig: s3 } = await makeSignedIntent(session, intent, 4);
  const regress = await acct.executeFromAgent({ payload: c3, signature: s3, claimedAmount: '10', sessionId: 's1', nonce: 4 });
  assert.equal(regress.ok, false);
});

test('INV-007: nonce MUST be signed into the payload — unsigned-nonce payloads fail closed (P0-5 cross-validation)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // Intent signed WITHOUT a nonce in the payload (pre-fix shape) — the
  // engine must refuse to execute it.
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  });
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /signed nonce/i);
});

test('INV-007: SAME signature with a DIFFERENT nonce is rejected — signatures are single-use (P0-5 cross-validation)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // Before the fix (PoC-confirmed): the same captured (payload, signature)
  // could be re-executed with any fresh nonce. Now the signed payload.nonce
  // pins the transaction slot.
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 10);
  const first = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 10 });
  assert.equal(first.ok, true, first.reason);
  const reuse = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 11 });
  assert.equal(reuse.ok, false);
  assert.match(reuse.reason, /signature reuse|does not match submitted nonce/i);
});

test('INV-007: per-tx ceiling is enforced (split attacks bounded)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '150',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '150', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /maxPerTx/i);
});

test('INV-007: cumulative daily ceiling enforced across multiple tx', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // 6 × 90 = 540 > session maxDaily 500 → the 6th must be rejected.
  const intent = {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '90',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  };
  for (let i = 1; i <= 5; i++) {
    const { canonical, sig } = await makeSignedIntent(session, intent, i);
    const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '90', sessionId: 's1', nonce: i });
    assert.equal(res.ok, true, `tx ${i} should pass`);
  }
  const { canonical, sig } = await makeSignedIntent(session, intent, 6);
  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '90', sessionId: 's1', nonce: 6 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /daily ceiling/i);
});

test('INV-007: account-level ceiling is an independent bound', async () => {
  const wallet = await PQCWallet.generate();
  // Account ceiling (maxDaily 100) is tighter than session ceiling (500).
  const acct = createSmartAccount({
    owner: OWNER,
    emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '100' },
  });
  const now = Date.now();
  const session = {
    agentId: 'agent-1',
    issuedAt: now,
    expiresAt: now + 60 * 60 * 1000,
    __wallet: wallet,
  };
  registerDefaultSession(acct, session, wallet);

  // Session allows up to 500; account caps at 100. Two 60s exceed 100.
  const intent = {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '60',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  };
  const { canonical: c1, sig: s1 } = await makeSignedIntent(session, intent, 1);
  assert.equal((await acct.executeFromAgent({ payload: c1, signature: s1, claimedAmount: '60', sessionId: 's1', nonce: 1 })).ok, true);
  const { canonical: c2, sig: s2 } = await makeSignedIntent(session, intent, 2);
  const res = await acct.executeFromAgent({ payload: c2, signature: s2, claimedAmount: '60', sessionId: 's1', nonce: 2 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /account daily ceiling/i);
});

test('INV-007: estimateMaxLoss quantifies the exposure bound', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  const est = acct.estimateMaxLoss();
  assert.equal(est.sessions.length, 1);
  assert.equal(est.sessions[0].sessionId, 's1');
  assert.ok(est.maxLossStatement.includes('max 500'), 'ceiling should be capped by session maxDaily');
  assert.equal(est.sessions[0].remainingDaily, '500');
});

// ─── P0-5 cross-validation: allowance surface (out-of-band spend paths) ──

test('INV-007: allowance-surface actions are rejected on-chain EVEN IF whitelisted (P0-5 cross-validation)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  // Owner (naively) whitelists the allowance methods — the chain layer must
  // still refuse them: approve/permit grant a pull-right that later executes
  // OUTSIDE executeFromAgent, where no ceiling, whitelist, or nonce applies.
  // (PoC-confirmed before the fix: approve(0xAttacker, 100) executed and the
  // attacker could pull via transferFrom with all ceilings bypassed.)
  registerDefaultSession(acct, session, wallet, {
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xContract'],
      allowedMethods: ['transfer', 'approve', 'permit', 'transferFrom', 'setApprovalForAll', 'increaseAllowance'],
      allowedRecipients: ['0xRecipient', '0xAttacker'],
    },
  });

  const dangerous = [
    { action: 'approve', method: 'approve' },
    { action: 'permit', method: 'permit' },
    { action: 'transferFrom', method: 'transferFrom' },
    { action: 'transfer', method: 'setApprovalForAll' }, // method-level variant
    { action: 'transfer', method: 'increaseAllowance' }, // method-level variant
    { action: 'swap', method: 'approve' },               // method-level variant
    // Sprint 2 cross-validation: the full allowance surface, incl. the
    // snake/camel/aliased variants the on-chain deny list must mirror.
    { action: 'approve_and_call', method: 'transfer' },  // snake alias
    { action: 'approveAndCall', method: 'transfer' },    // camel alias
    { action: 'create_allowance', method: 'transfer' },  // alias not previously covered
    { action: 'increase_allowance', method: 'transfer' },
    { action: 'increaseapproval', method: 'transfer' },
    { action: 'setApprovalForAll', method: 'transfer' },
    { action: 'transfer', method: 'permit2' },           // method-level alias
  ];
  for (let i = 0; i < dangerous.length; i++) {
    const { canonical, sig } = await makeSignedIntent(session, {
      action: dangerous[i].action, chain: 'ethereum', asset: 'USDC', amount: '10',
      recipient: '0xAttacker', contract: '0xContract', method: dangerous[i].method,
    }, i + 1);
    const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: i + 1 });
    assert.equal(res.ok, false, `case ${i} (${dangerous[i].action}/${dangerous[i].method}) must be rejected`);
    assert.match(res.reason, /allowance surface/i);
  }

  // Ordinary transfers still work.
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 100);
  const ok = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 100 });
  assert.equal(ok.ok, true, ok.reason);
});

// ─── P0-5 cross-validation: expiry after registration ────────────────────

test('INV-003: session valid at registration but expired at execution is rejected', async () => {
  const wallet = await PQCWallet.generate();
  const acct = createSmartAccount({
    owner: OWNER, emergencyKey: EMERGENCY,
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });
  const now = Date.now();
  const session = {
    agentId: 'agent-1',
    issuedAt: now,
    expiresAt: now + 80, // expires 80ms after registration
    __wallet: wallet,
  };
  registerDefaultSession(acct, session, wallet);

  // Signature obtained while the session was VALID.
  const { canonical, sig } = await makeSignedIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer',
  }, 1);
  await new Promise((r) => setTimeout(r, 120)); // let the session expire

  const res = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '10', sessionId: 's1', nonce: 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /expired/i);
});

// ─── P0-5 cross-validation: emergencyReduceLimit robustness ──────────────

test('INV-006: emergencyReduceLimit fails closed on malformed input (no exception)', async () => {
  const { wallet, acct, session } = await setupAccount();
  session.__wallet = wallet;
  registerDefaultSession(acct, session, wallet);

  // Malformed ceilings return { ok:false } instead of throwing.
  const r1 = acct.emergencyReduceLimit({ by: EMERGENCY, sessionId: 's1', maxPerTx: 'abc' });
  assert.equal(r1.ok, false);
  assert.match(r1.reason, /invalid maxPerTx/i);
  const r2 = acct.emergencyReduceLimit({ by: EMERGENCY, sessionId: 's1', maxDaily: -5 });
  assert.equal(r2.ok, false);
  // State unchanged by the failed calls.
  assert.equal(acct.getSession('s1').maxPerTx, '100');
  assert.equal(acct.getSession('s1').maxDaily, '500');
});

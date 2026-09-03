import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createAgentIdentity,
  recoverAgentIdentity,
  signAsAgent,
  signAgentAsset,
  classifySignRequest,
  SIGN_TIERS,
  spawnAgentSigner,
  canonicalizeAssetIntent,
  verifyAgentAssetSignature,
  enforceAmountBinding,
  decodeAssetIntentPayload,
  generateAddress,
  validateAddress,
  KEY_MODELS,
  SPEND_MODES,
  checkSpendAllowed,
  takeoverGuard,
  CoordinationClient,
  createMemoryTransport,
  runTaskLoop,
  TASK_STATUS
} from '../src/index.js';
import {
  createSessionKey,
  verifySessionSignature,
  signSync,
  PQCWallet
} from 'aegis-vault';

test('createAgentIdentity returns self-sovereign identity with encrypted key', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  assert.ok(identity.address.startsWith('ng1'));
  assert.equal(identity.keyModel, KEY_MODELS.SELF_SOVEREIGN);
  assert.equal(validateAddress(identity.address).valid, true);
  assert.ok(identity.envelope.cipher, 'aes-256-gcm');
  // private key never exposed
  assert.ok(!('privateKey' in identity));
});

test('recoverAgentIdentity round-trips the wallet', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  assert.equal(wallet.address, identity.address);
  const bad = recoverAgentIdentity(identity.envelope, 'wrong-password');
  assert.equal(bad, null);
});

test('signAsAgent produces verifiable signature', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const sig = await signAsAgent(wallet, { action: 'claim', taskId: 't-1' });
  assert.ok(typeof sig === 'string' && sig.length > 0);
  assert.equal(await wallet.verify({ action: 'claim', taskId: 't-1' }, sig), true);
});

test('CoordinationClient works over memory transport', async () => {
  const transport = createMemoryTransport();
  const client = new CoordinationClient(transport);
  const published = await client.publishTask({
    agent: 'agent-1',
    title: 'Research quantized models',
    description: 'Summarize latest',
    capabilities: ['research'],
    reward: 100,
    taskType: 'research'
  });
  assert.equal(published.ok, true);
  const tasks = await client.listTasks();
  assert.ok(Array.isArray(tasks.tasks));
});

test('runTaskLoop respects human takeover spend limits', async () => {
  const transport = createMemoryTransport();
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');

  // Autonomous agent: unlimited
  const autonomous = await runTaskLoop({
    agent: 'agent-1',
    wallet,
    spendConfig: { type: SPEND_MODES.UNLIMITED },
    transport,
    tasks: [{ id: 't-1', reward: 100 }]
  });
  assert.equal(autonomous.results[0].status, 'claimed');

  // Taken over: require-approval blocks spend
  const blocked = await runTaskLoop({
    agent: 'agent-1',
    wallet,
    spendConfig: { type: SPEND_MODES.REQUIRE_APPROVAL },
    transport,
    tasks: [{ id: 't-2', reward: 100 }]
  });
  assert.equal(blocked.results[0].status, 'blocked');
});

test('TASK_STATUS and takeoverGuard are exported', () => {
  assert.equal(TASK_STATUS.OPEN, 'open');
  assert.equal(takeoverGuard({ type: 'unlimited' }, { type: 'unlimited' }), true);
  assert.equal(checkSpendAllowed({ type: 'limit', maxPerTx: 10 }, { amount: 20 }).allowed, false);
});

test('classifySignRequest distinguishes metadata from asset intents (INV-002)', () => {
  // metadata: protocol bookkeeping
  assert.equal(classifySignRequest({ action: 'claim', taskId: 't-1' }).tier, SIGN_TIERS.METADATA);
  assert.equal(classifySignRequest({ action: 'submit', taskId: 't-1', submission: { summary: 'x' } }).tier, SIGN_TIERS.METADATA);
  assert.equal(classifySignRequest({ action: 'create_topic', agent: 'a1' }).tier, SIGN_TIERS.METADATA);
  assert.equal(classifySignRequest({ action: 'submit', submission: { transfer: 'completed' } }).tier, SIGN_TIERS.METADATA);
  assert.equal(classifySignRequest('opaque string').tier, SIGN_TIERS.METADATA);
  assert.equal(classifySignRequest(null).tier, SIGN_TIERS.METADATA);
  // asset: explicit asset action
  assert.equal(classifySignRequest({ action: 'transfer', amount: '50', recipient: '0x1' }).tier, SIGN_TIERS.ASSET);
  assert.equal(classifySignRequest({ action: 'approve', spender: '0x1' }).tier, SIGN_TIERS.ASSET);
  assert.equal(classifySignRequest({ action: 'swap', amount: '10', chain: 'ethereum' }).tier, SIGN_TIERS.ASSET);
  // asset: operation shape without an action field
  assert.equal(classifySignRequest({ amount: '50', recipient: '0x1' }).tier, SIGN_TIERS.ASSET);
});

test('signAsAgent rejects asset-tier payloads on the generic channel (INV-002)', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  await assert.rejects(
    signAsAgent(wallet, { action: 'transfer', amount: '50', recipient: '0x1' }),
    /asset-tier/
  );
  await assert.rejects(
    signAsAgent(wallet, { amount: '50', recipient: '0x1' }),
    /asset-tier/
  );
  // metadata still works on the generic channel
  const sig = await signAsAgent(wallet, { action: 'claim', taskId: 't-1' });
  assert.equal(await wallet.verify({ action: 'claim', taskId: 't-1' }, sig), true);
});

test('signAgentAsset requires a session key and denies out-of-scope intents (INV-003)', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const issuer = await PQCWallet.generate();
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });
  assert.equal(await verifySessionSignature(session, issuer.publicKey), true);

  // missing session → fail closed
  await assert.rejects(
    signAgentAsset({ wallet, intent: { action: 'transfer', amount: '50' } }),
    /session key/
  );

  // valid session, in-scope → signs a structured intent bound to session context
  const sig = await signAgentAsset({ wallet,
    session,
    issuerPublicKey: issuer.publicKey,
    intent: {
      action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '50',
      recipient: '0x1', contract: '0xContract', method: 'transfer',
    },
  });
  const canonical = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '50',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  // P0-4: the signature binds the DECODABLE canonical payload (not a hash).
  assert.equal(await wallet.verify(JSON.stringify(canonical), sig), true);

  // out-of-scope: amount exceeds maxPerTx → denied
  await assert.rejects(
    signAgentAsset({ wallet,
      session,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', amount: '501', contract: '0xContract', method: 'transfer' },
    }),
    /denied/
  );

  // out-of-scope: contract not whitelisted → denied
  await assert.rejects(
    signAgentAsset({ wallet,
      session,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', amount: '10', contract: '0xEvil', method: 'transfer' },
    }),
    /denied/
  );

  // forged session (maxPerTx tampered) → session signature check fails
  const forged = { ...session, maxPerTx: '999999' };
  await assert.rejects(
    signAgentAsset({ wallet,
      session: forged,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', amount: '50', contract: '0xContract', method: 'transfer' },
    }),
    /signature invalid/
  );

  // missing issuerPublicKey → fail closed (agent must not self-authorize sessions)
  await assert.rejects(
    signAgentAsset({ wallet,
      session,
      intent: { action: 'transfer', chain: 'ethereum', amount: '50', contract: '0xContract', method: 'transfer' },
    }),
    /issuerPublicKey/
  );

  // method not whitelisted → denied
  await assert.rejects(
    signAgentAsset({ wallet,
      session,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', amount: '10', contract: '0xContract', method: 'approve' },
    }),
    /denied/
  );

  // chain not whitelisted → denied
  await assert.rejects(
    signAgentAsset({ wallet,
      session,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'solana', amount: '10', contract: '0xContract', method: 'transfer' },
    }),
    /denied/
  );

  // validly signed but EXPIRED session → denied by expiry (INV-003)
  const expiredScope = {
    version: session.version,
    agentId: 'agent-1',
    issuedAt: Date.now() - 7200_000,
    expiresAt: Date.now() - 3600_000,
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
  };
  const expiredSession = {
    type: 'session_key',
    ...expiredScope,
    signature: signSync(JSON.stringify(expiredScope), issuer.privateKey).toString('hex'),
  };
  assert.equal(await verifySessionSignature(expiredSession, issuer.publicKey), true, 'fixture must be validly signed');
  await assert.rejects(
    signAgentAsset({ wallet,
      session: expiredSession,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', amount: '10', contract: '0xContract', method: 'transfer' },
    }),
    /denied/
  );
});

test('canonicalizeAssetIntent fails closed on missing/empty digest fields (no collapsed preimages)', () => {
  const session = { agentId: 'agent-1', issuedAt: 1700000000000, expiresAt: 1700003600000 };
  const full = {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '5',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  };
  // valid payload serializes (including nonce passthrough when provided)
  assert.equal(canonicalizeAssetIntent(session, full).type, 'agent_asset_intent');
  // missing/empty string dimensions must throw, not serialize to ''
  for (const f of ['action', 'chain', 'asset', 'recipient', 'contract', 'method']) {
    assert.throws(() => canonicalizeAssetIntent(session, { ...full, [f]: undefined }), new RegExp(f));
    assert.throws(() => canonicalizeAssetIntent(session, { ...full, [f]: ' ' }), new RegExp(f));
  }
  // missing amount / agentId / session / intent must throw (INV-002)
  assert.throws(() => canonicalizeAssetIntent(session, { ...full, amount: undefined }), /amount/);
  assert.throws(() => canonicalizeAssetIntent({ ...session, agentId: undefined }, full), /agentId/);
  assert.throws(() => canonicalizeAssetIntent(null, full), /session/);
  assert.throws(() => canonicalizeAssetIntent(session, null), /intent/);
});

test('signAgentAsset DEFAULT signer path: isolated subprocess signs the DECODABLE payload (P0-4)', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const issuer = await PQCWallet.generate();
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  // Spawn the isolated signer; the private key lives in the child process.
  const signer = await spawnAgentSigner({
    envelope: identity.envelope,
    password: 'agent-secret-123',
    session,
  });
  try {
    const intent = {
      action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '5',
      recipient: '0x1', contract: '0xContract', method: 'transfer',
    };
    const sig = await signAgentAsset({ signer, session, issuerPublicKey: issuer.publicKey, intent });

    // P0-4: the signature binds the DECODABLE canonical payload, not a one-way
    // hash — the on-chain verifier can decode the amount from the payload.
    const canonical = canonicalizeAssetIntent(session, intent);
    assert.equal(await wallet.verify(JSON.stringify(canonical), sig), true,
      'signer path signature must verify over JSON.stringify(canonical)');

    // The on-chain verifier accepts it and decodes the amount.
    const v = await verifyAgentAssetSignature({ payload: canonical, signature: sig, publicKey: identity.publicKeyHex });
    assert.equal(v.valid, true);
    assert.equal(v.amount, '5');
    assert.equal(v.decoded.type, 'agent_asset_intent');
  } finally {
    await signer.close();
  }
});

test('signAgentAsset signer path enforces the DERIVED worker policy independently (INV-003, P0-4)', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const issuer = await PQCWallet.generate();
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  // Worker policy derived from session ceilings: {type:'limit', maxPerTx:100, maxDaily:500}.
  const signer = await spawnAgentSigner({
    envelope: identity.envelope,
    password: 'agent-secret-123',
    session,
  });
  try {
    // P0-4: the amount is extracted from the PAYLOAD the worker signs — no
    // separate parent-supplied amount field. A compromised parent that tries
    // to sneak a large amount into the signed payload is rejected by the
    // worker-side policy (fail-closed, no amount-hash unlinkability).
    await assert.rejects(
      () => signer.signIntent({
        type: 'agent_asset_intent', action: 'transfer', chain: 'ethereum',
        amount: '501', recipient: '0x1', contract: '0xContract', method: 'transfer',
        agentId: 'agent-1', sessionIssuedAt: session.issuedAt, sessionExpiresAt: session.expiresAt,
      }),
      /exceeds maxPerTx/i
    );

    // In-ceiling amount 5 → small-auto tier → signs.
    const sig = await signer.signIntent({
      type: 'agent_asset_intent', action: 'transfer', chain: 'ethereum',
      amount: '5', recipient: '0x1', contract: '0xContract', method: 'transfer',
      agentId: 'agent-1', sessionIssuedAt: session.issuedAt, sessionExpiresAt: session.expiresAt,
    });
    assert.ok(typeof sig === 'string' && sig.startsWith('0x'));

    // Gradient tiering applies on top of the derived limit: 50 is within
    // maxPerTx(100) but lands in the medium tier → 24h timelock, not a sig.
    const timelock = await signer.signIntent({
      type: 'agent_asset_intent', action: 'transfer', chain: 'ethereum',
      amount: '50', recipient: '0x1', contract: '0xContract', method: 'transfer',
      agentId: 'agent-1', sessionIssuedAt: session.issuedAt, sessionExpiresAt: session.expiresAt,
    });
    assert.ok(timelock && typeof timelock === 'object' && timelock.timelocked === true);
    assert.equal(timelock.timelockMs, 24 * 60 * 60 * 1000);
  } finally {
    await signer.close();
  }
});

test('ON-CHAIN verifier: amount:"1" + high-value payload is rejected (INV-002, P0-4)', async () => {
  const issuer = await PQCWallet.generate();
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  // Attacker signs a LOW-value payload...
  const low = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '1',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  const sig = await signAgentAsset({
    wallet,
    session,
    issuerPublicKey: issuer.publicKey,
    intent: { action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '1', recipient: '0x1', contract: '0xContract', method: 'transfer' },
  });

  // ...then claims the transaction actually moves a HIGH amount.
  const res = await enforceAmountBinding({
    payload: low,
    claimedAmount: '1000000',
    signature: sig,
    publicKey: identity.publicKeyHex,
  });
  assert.equal(res.valid, false, 'claimed amount must not diverge from the signed payload amount');
  assert.match(res.reason, /amount mismatch/);

  // Correctly-claimed amount passes the binding check.
  const ok = await enforceAmountBinding({
    payload: low,
    claimedAmount: '1',
    signature: sig,
    publicKey: identity.publicKeyHex,
  });
  assert.equal(ok.valid, true);
  assert.equal(ok.amount, '1');
});

test('ON-CHAIN verifier: same payload with a different claimed amount is rejected (INV-002, P0-4)', async () => {
  const issuer = await PQCWallet.generate();
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  const payload = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '7',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  const sig = await wallet.sign(JSON.stringify(payload));

  // The payload carries amount=7 — any other claimed amount must fail.
  for (const claimed of ['8', '0', '100']) {
    const res = await enforceAmountBinding({
      payload, claimedAmount: claimed, signature: sig, publicKey: identity.publicKeyHex,
    });
    assert.equal(res.valid, false, `claimed=${claimed} must be rejected`);
    assert.match(res.reason, /amount mismatch/);
  }
  const ok = await enforceAmountBinding({ payload, claimedAmount: '7', signature: sig, publicKey: identity.publicKeyHex });
  assert.equal(ok.valid, true);
});

test('ON-CHAIN verifier: policy ceilings enforced as a chain-side layer (INV-003, P0-4)', async () => {
  const issuer = await PQCWallet.generate();
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  const payload = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '80',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  const sig = await wallet.sign(JSON.stringify(payload));

  // Signed payload amount matches the claim, but the policy ceiling is lower
  // — the chain-side verifier rejects independently of the signer process.
  const res = await enforceAmountBinding({
    payload,
    claimedAmount: '80',
    signature: sig,
    publicKey: identity.publicKeyHex,
    policy: { type: SPEND_MODES.LIMITED, maxPerTx: '50', maxDaily: '500' },
  });
  assert.equal(res.valid, false);
  assert.match(res.reason, /maxPerTx/);

  // Medium tier amount → requires a timelock at the chain layer too.
  const med = await enforceAmountBinding({
    payload,
    claimedAmount: '80',
    signature: sig,
    publicKey: identity.publicKeyHex,
    policy: { type: SPEND_MODES.LIMITED, maxPerTx: '100', maxDaily: '500', tierThresholds: { small: 10, medium: 50 } },
  });
  assert.equal(med.valid, false);
  assert.match(med.reason, /timelock/);
});

test('ON-CHAIN verifier: replayed payload with an EXPIRED session is rejected (INV-003, P0-4 cross-validation)', async () => {
  const issuer = await PQCWallet.generate();
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  // Simulate a signature obtained while the session was VALID (signed over
  // the canonical payload directly — the SDK gate would have allowed it),
  // then replayed on-chain AFTER the session expired.
  const payload = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
    recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  payload.sessionExpiresAt = Date.now() - 1000; // session already expired
  const sig = await wallet.sign(JSON.stringify(payload));

  const res = await enforceAmountBinding({
    payload, claimedAmount: '10', signature: sig, publicKey: identity.publicKeyHex,
  });
  assert.equal(res.valid, false, 'expired-session payload must not pass the chain-side verifier');
  assert.match(res.reason, /expired/i);

  // Payload carrying no expiry at all → fail closed.
  const noExpiry = { ...payload };
  delete noExpiry.sessionExpiresAt;
  const sig2 = await wallet.sign(JSON.stringify(noExpiry));
  const res2 = await enforceAmountBinding({
    payload: noExpiry, claimedAmount: '10', signature: sig2, publicKey: identity.publicKeyHex,
  });
  assert.equal(res2.valid, false, 'payload without sessionExpiresAt must fail closed');
  assert.match(res2.reason, /sessionExpiresAt/);
});

test('ON-CHAIN verifier: tampered payload / malformed amount fail closed (INV-002, P0-4)', async () => {
  const identity = await createAgentIdentity({ password: 'agent-secret-123' });
  const issuer = await PQCWallet.generate();
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });
  const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');
  const payload = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '5', recipient: '0x1', contract: '0xContract', method: 'transfer',
  });
  const sig = await wallet.sign(JSON.stringify(payload));

  // Signature over a DIFFERENT payload must fail.
  const tampered = { ...payload, amount: '999' };
  const bad = await verifyAgentAssetSignature({ payload: tampered, signature: sig, publicKey: identity.publicKeyHex });
  assert.equal(bad.valid, false);
  assert.match(bad.reason, /invalid signature/);

  // Missing/negative/garbage amounts in the payload fail closed at decode.
  for (const amt of [undefined, 'abc', '-5', '']) {
    const d = decodeAssetIntentPayload({ ...payload, amount: amt });
    assert.equal(d.valid, false, `amount=${amt} must be rejected`);
  }
});

test('signAgentAsset requires a signer or an explicit wallet (no silent fallback)', async () => {
  const issuer = await PQCWallet.generate();
  const session = createSessionKey(issuer.privateKey, {
    agentId: 'agent-1',
    allowedContracts: ['0xContract'],
    allowedMethods: ['transfer'],
    allowedChains: ['ethereum'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });
  await assert.rejects(
    signAgentAsset({
      session,
      issuerPublicKey: issuer.publicKey,
      intent: { action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10', recipient: '0x1', contract: '0xContract', method: 'transfer' },
    }),
    /requires a signer/
  );
});
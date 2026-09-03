/**
 * aegis-chain-eth — ChainConnection on-chain broadcast test suite
 *
 * Sprint 2.3: drives the REAL SmartAccount contract on a local EVM chain
 * (@ethereumjs/vm via test/helpers/local-chain.mjs) through ethers.js —
 * deploy → registerSession → offline sign → broadcast executeFromAgent →
 * on-chain state assertions — plus typed revert decoding (INV-002/003/005/
 * 006/007) via simulateExecuteFromAgent (eth_call).
 *
 * Skips (with a hint) when the compiled artifact is absent: it needs a local
 * `forge build --use 0.8.24` in contracts/solidity, or
 * SMART_ACCOUNT_ARTIFACT pointing at the built artifact JSON.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ethers } from 'ethers';
import { createLocalChain } from './helpers/local-chain.mjs';
import { loadSmartAccountArtifact, artifactMissingHint } from './helpers/load-artifact.mjs';
import {
  deploySmartAccount,
  createChainConnection,
  createChainProvider,
  intentToStruct,
  payloadDigest,
  decodeRevert,
} from '../src/chain-connection.js';
import {
  signSmartAccountIntent,
  addressForPrivateKey,
  hashIntentDigest,
} from '../src/canonical.js';

const artifact = loadSmartAccountArtifact();
const skipOnChain = artifact ? false : artifactMissingHint();

// BigInt-safe JSON for assertion diagnostics (revert args are bigint).
const diag = (value) => JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));

// Fixed test keys (deterministic, matches the golden fixture convention).
const OWNER_PK = '0x' + '21'.repeat(32);
const EMERGENCY_PK = '0x' + '22'.repeat(32);
const RELAYER_PK = '0x' + '33'.repeat(32);
const AGENT_PK = '0x' + '11'.repeat(32);

const owner = new ethers.Wallet(OWNER_PK);
const emergency = new ethers.Wallet(EMERGENCY_PK);
const relayer = new ethers.Wallet(RELAYER_PK);
const agentAddr = addressForPrivateKey(AGENT_PK);

const SESSION_ID = '0x' + 'ab'.repeat(32);
const MAX_PER_TX = 100n;
const MAX_DAILY = 500n;
const ACCOUNT_MAX_DAILY = 1_000_000n;

// ─── Pure mapping unit tests (no chain needed) ───────────────────────────

test('intentToStruct maps payload → IntentFields (contract rename + BigInt)', () => {
  const payload = {
    sessionId: SESSION_ID,
    action: 'transfer',
    chain: 'ethereum',
    asset: 'USDC',
    amount: '25',
    recipient: '0xRecipient',
    contract: '0xToken', // payload field is `contract`
    method: 'transfer',
    nonce: '1',
    agentId: 'agent-x',
    sessionIssuedAt: '1700000000000',
    sessionExpiresAt: '1700003600000',
  };
  const s = intentToStruct(payload);
  assert.equal(s.sessionId, SESSION_ID);
  assert.equal(s.contractAddr, '0xToken'); // → struct.contractAddr
  assert.equal(typeof s.amount, 'bigint');
  assert.equal(s.amount, 25n);
  assert.equal(typeof s.nonce, 'bigint');
  assert.equal(s.nonce, 1n);
  assert.equal(s.action, 'transfer');
});

test('intentToStruct rejects non-bytes32 sessionId', () => {
  assert.throws(
    () => intentToStruct({ sessionId: 's1', amount: '1', nonce: '1' }),
    /sessionId must be 32-byte hex/,
  );
});

test('decodeRevert shapes ethers custom errors into stable {ok:false,...}', () => {
  // Plain Error (no revert payload).
  const plain = decodeRevert(new Error('boom'));
  assert.equal(plain.ok, false);
  assert.equal(plain.errorName, null);
  assert.equal(plain.reason, 'boom');
  // ethers CallExceptionError shape with a decoded custom error.
  const rich = {
    reason: 'bad thing',
    revert: '0x1234',
    info: { error: { name: 'BadNonce', args: [1n, 0n] } },
  };
  const decoded = decodeRevert(rich);
  assert.equal(decoded.ok, false);
  assert.equal(decoded.errorName, 'BadNonce');
  assert.deepEqual(decoded.args, [1n, 0n]);
  assert.equal(decoded.revertData, '0x1234');
});

// ─── On-chain suite (skips without artifact) ─────────────────────────────

const onChain = { skip: skipOnChain };

test('deploy + registerSession + views', onChain, async () => {
  const chain = await createLocalChain({
    funded: [{ address: owner.address, balance: 10n ** 18n }],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    assert.equal(dep.ok, true, dep.reason ?? 'deploy failed');
    const conn = dep.connection;

    assert.equal(conn.address, dep.address);
    assert.equal((await provider.getCode(dep.address)).length > 100, true, 'code deployed');
    assert.equal(await conn.owner(), owner.address);
    assert.equal(await conn.emergencyKey(), emergency.address);
    assert.equal(await conn.accountMaxDaily(), ACCOUNT_MAX_DAILY);
    assert.equal(await conn.paused(), false);
    assert.equal(await conn.frozen(), false);

    // registerSession (owner).
    const nowMs = Math.floor(Date.now() / 1000) * 1000; // chain clock is seconds
    const reg = await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: 'agent-onchain',
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: {
        allowedChains: ['ethereum'],
        allowedAssets: ['USDC'],
        allowedContracts: ['0xToken'],
        allowedMethods: ['transfer'],
        allowedRecipients: ['0xRecipient'],
      },
    });
    assert.equal(reg.ok, true, reg.reason ?? 'register failed');
    assert.equal(reg.receipt.status, 1);

    const session = await conn.contract.sessions(SESSION_ID);
    assert.equal(session.agentId, 'agent-onchain');
    assert.equal(session.agentEvmAddress.toLowerCase(), agentAddr.toLowerCase());
    assert.equal(session.maxPerTx, MAX_PER_TX);
    assert.equal(session.revoked, false);
  } finally {
    await chain.stop();
  }
});

test('offline sign → broadcast executeFromAgent → on-chain state', onChain, async () => {
  const chain = await createLocalChain({
    funded: [
      { address: owner.address, balance: 10n ** 18n },
      { address: relayer.address, balance: 10n ** 18n },
    ],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    const conn = dep.connection;

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-broadcast', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'] },
    });

    // Offline sign (agent key; no chain interaction).
    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
      },
      privateKeyHex: AGENT_PK,
    });

    // Cross-check the on-chain digest BEFORE broadcasting.
    const onChainDigest = await conn.hashIntent(signed.payload);
    assert.equal(onChainDigest, signed.digest, 'on-chain hashIntent == JS hashIntentDigest');

    // Broadcast via a NEUTRAL relayer (any EOA may relay; contract auths sig).
    const res = await conn.executeFromAgent({
      payload: signed.payload,
      signature: signed.signature,
      signer: relayer.connect(provider),
    });
    assert.equal(res.ok, true, res.reason ?? 'execute failed');
    assert.equal(res.receipt.status, 1);
    assert.equal(res.amount, 25n, 'Executed.amount from event');
    assert.equal(res.txId?.length, 66, 'Executed.txId is bytes32');

    // On-chain state updates.
    assert.equal(await conn.sessionLastNonce(SESSION_ID), 1n);
    assert.equal(await conn.sessionSpentThisWindow(SESSION_ID), 25n);
    assert.equal(await conn.accountSpentThisWindow(), 25n);
    assert.equal(await conn.estimateMaxLoss(), ACCOUNT_MAX_DAILY - 25n);
    assert.equal(await conn.sessionMaxLoss(SESSION_ID), 475n); // 500 - 25
  } finally {
    await chain.stop();
  }
});

test('simulateExecuteFromAgent decodes typed reverts (INV-007/003/005/002)', onChain, async () => {
  const chain = await createLocalChain({
    funded: [{ address: owner.address, balance: 10n ** 18n }],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    const conn = dep.connection;

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-sim', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'] },
    });

    const sign = (overrides) => signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
        ...overrides,
      },
      privateKeyHex: AGENT_PK,
    });

    // Valid first — simulate OK.
    const okSig = sign({});
    const sim = await conn.simulateExecuteFromAgent({ payload: okSig.payload, signature: okSig.signature });
    assert.equal(sim.ok, true, sim.reason ?? 'simulate failed');
    assert.equal(sim.txId?.length, 66);

    // Broadcast once for real (consumes nonce=1 on-chain), so that a replay
    // of the SAME signature below hits the anti-replay guard (INV-007).
    const exec = await conn.executeFromAgent({
      payload: okSig.payload,
      signature: okSig.signature,
      signer: owner.connect(provider), // any EOA may relay
    });
    assert.equal(exec.ok, true, exec.reason ?? 'execute failed');
    assert.equal(await conn.sessionLastNonce(SESSION_ID), 1n);

    // Replay the same nonce → BadNonce (INV-007).
    const replay = await conn.simulateExecuteFromAgent({ payload: okSig.payload, signature: okSig.signature });
    assert.equal(replay.ok, false);
    assert.equal(replay.errorName, 'BadNonce', diag(replay));

    // Unregistered session → NotRegistered (INV-003).
    const otherSig = signSmartAccountIntent({
      session: { ...session, sessionId: '0x' + 'cd'.repeat(32) },
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
      },
      privateKeyHex: AGENT_PK,
    });
    const unreg = await conn.simulateExecuteFromAgent({ payload: otherSig.payload, signature: otherSig.signature });
    assert.equal(unreg.ok, false);
    assert.equal(unreg.errorName, 'NotRegistered', diag(unreg));

    // amount > maxPerTx → AmountExceedsPerTx (INV-007). nonce must increase.
    const overSig = sign({ amount: '101', nonce: '2' });
    const over = await conn.simulateExecuteFromAgent({ payload: overSig.payload, signature: overSig.signature });
    assert.equal(over.ok, false);
    assert.equal(over.errorName, 'AmountExceedsPerTx', diag(over));
    assert.equal(over.args[0], MAX_PER_TX);

    // Self-escalation action even with valid sig → SelfEscalationRejected (INV-005).
    const escSig = sign({ action: 'increaseLimit', method: 'increaseLimit', nonce: '3' });
    const esc = await conn.simulateExecuteFromAgent({ payload: escSig.payload, signature: escSig.signature });
    assert.equal(esc.ok, false);
    assert.equal(esc.errorName, 'SelfEscalationRejected', diag(esc));

    // Whitelist violation → WhitelistViolation (INV-003). nonce=4, asset not allowed.
    const wlSig = sign({ asset: 'DAI', nonce: '4' });
    const wl = await conn.simulateExecuteFromAgent({ payload: wlSig.payload, signature: wlSig.signature });
    assert.equal(wl.ok, false);
    assert.equal(wl.errorName, 'WhitelistViolation', diag(wl));

    // Forged/tampered signature → InvalidSignature (INV-002). nonce=5, bad sig.
    const badSig = sign({ nonce: '5' });
    const bad = await conn.simulateExecuteFromAgent({ payload: badSig.payload, signature: '0x' + '00'.repeat(65) });
    assert.equal(bad.ok, false);
    assert.equal(bad.errorName, 'InvalidSignature', diag(bad));
  } finally {
    await chain.stop();
  }
});

test('emergency brake: pause/freeze/resume/unfreeze + reduce-only limit', onChain, async () => {
  const chain = await createLocalChain({
    funded: [
      { address: owner.address, balance: 10n ** 18n },
      { address: emergency.address, balance: 10n ** 18n },
    ],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    const conn = dep.connection;

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-emerg', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'] },
    });

    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
      },
      privateKeyHex: AGENT_PK,
    });
    const sig = { payload: signed.payload, signature: signed.signature };

    // Pause by emergency → execution blocked with AccountPaused.
    const p = await conn.pause({ signer: emergency.connect(provider) });
    assert.equal(p.ok, true);
    assert.equal(await conn.paused(), true);
    let sim = await conn.simulateExecuteFromAgent(sig);
    assert.equal(sim.ok, false);
    assert.equal(sim.errorName, 'AccountPaused', diag(sim));

    // Resume by owner → execution admissible again.
    await conn.resume({ signer: owner.connect(provider) });
    sim = await conn.simulateExecuteFromAgent(sig);
    assert.equal(sim.ok, true, sim.reason ?? 'expected admissible after resume');

    // Emergency reduce-only: lowering is OK.
    const lower = await conn.emergencyReduceLimit({
      sessionId: SESSION_ID, maxPerTx: 50, maxDaily: 200, signer: emergency.connect(provider),
    });
    assert.equal(lower.ok, true, lower.reason ?? 'lower limit failed');
    const s = await conn.contract.sessions(SESSION_ID);
    assert.equal(s.maxPerTx, 50n);
    assert.equal(s.maxDaily, 200n);

    // Raising must be rejected on-chain (INV-006) — attempt reduce to HIGHER.
    let raiseErr = null;
    try {
      await conn.contract
        .connect(emergency.connect(provider))
        .emergencyReduceLimit.staticCall(SESSION_ID, 300n, 400n);
    } catch (err) {
      raiseErr = decodeRevert(err);
    }
    assert.ok(raiseErr, 'raise-limit should revert');
    assert.equal(raiseErr.errorName, 'SelfEscalationRejected', diag(raiseErr));

    // Freeze by emergency → AccountFrozen (execution blocked, permanent brake).
    await conn.freeze({ signer: emergency.connect(provider) });
    assert.equal(await conn.frozen(), true);
    sim = await conn.simulateExecuteFromAgent(sig);
    assert.equal(sim.ok, false);
    assert.equal(sim.errorName, 'AccountFrozen', JSON.stringify(sim));

    // Unfreeze by owner → admissible again.
    await conn.unfreeze({ signer: owner.connect(provider) });
    sim = await conn.simulateExecuteFromAgent(sig);
    assert.equal(sim.ok, true, sim.reason ?? 'expected admissible after unfreeze');
  } finally {
    await chain.stop();
  }
});

test('session expiry enforced on-chain (INV-003) via advanceTime', onChain, async () => {
  const chain = await createLocalChain({
    funded: [{ address: owner.address, balance: 10n ** 18n }],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    const conn = dep.connection;

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-expire', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'] },
    });

    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
      },
      privateKeyHex: AGENT_PK,
    });

    // Valid now.
    let sim = await conn.simulateExecuteFromAgent({ payload: signed.payload, signature: signed.signature });
    assert.equal(sim.ok, true, sim.reason ?? 'expected admissible before expiry');

    // Advance the chain clock past expiry → SessionExpired (INV-003).
    chain.advanceTime(3600_000 + 2000);
    sim = await conn.simulateExecuteFromAgent({ payload: signed.payload, signature: signed.signature });
    assert.equal(sim.ok, false);
    assert.equal(sim.errorName, 'SessionExpired', diag(sim));
  } finally {
    await chain.stop();
  }
});

test('payloadDigest / intentToStruct consistent with contract hashIntent', onChain, async () => {
  const chain = await createLocalChain({
    funded: [{ address: owner.address, balance: 10n ** 18n }],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    const conn = dep.connection;

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-digest', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '42',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '7',
      },
      privateKeyHex: AGENT_PK,
    });

    // Three independent computations must agree.
    const js = hashIntentDigest(signed.payload);
    const js2 = payloadDigest(signed.payload);
    const chainDigest = await conn.hashIntent(signed.payload);
    assert.equal(js, signed.digest);
    assert.equal(js2, signed.digest);
    assert.equal(chainDigest, signed.digest, 'JS digest == on-chain hashIntent');
  } finally {
    await chain.stop();
  }
});

test('createChainConnection attaches to a deployed contract; revoke + typed privileged reverts', onChain, async () => {
  const chain = await createLocalChain({
    funded: [
      { address: owner.address, balance: 10n ** 18n },
      { address: emergency.address, balance: 10n ** 18n },
    ],
  });
  try {
    const provider = createChainProvider(chain.url);
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });

    // ATTACH path: a fresh connection to the already-deployed address (this is
    // what a relayer / SDK consumer would use after a restart).
    const conn = createChainConnection({
      provider,
      address: dep.address,
      abi: artifact.abi,
      signer: owner.connect(provider),
    });
    assert.equal(conn.address, dep.address);
    assert.equal(await conn.owner(), owner.address);

    const nowMs = Math.floor(Date.now() / 1000) * 1000;
    const session = { agentId: 'agent-attach', sessionId: SESSION_ID, issuedAt: nowMs, expiresAt: nowMs + 3600_000 };
    const reg = await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'], allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'] },
    });
    assert.equal(reg.ok, true, reg.reason ?? 'register via attached connection failed');

    // Privileged reverts are TYPED results ({ok:false, errorName}), not throws:
    // duplicate session → SessionExists.
    const dup = await conn.registerSession({
      sessionId: SESSION_ID,
      agentId: session.agentId,
      agentEvmAddress: agentAddr,
      issuedAt: nowMs,
      expiresAt: nowMs + 3600_000,
      maxPerTx: MAX_PER_TX,
      maxDaily: MAX_DAILY,
      whitelist: {},
    });
    assert.equal(dup.ok, false);
    assert.equal(dup.errorName, 'SessionExists', diag(dup));

    // Non-emergency caller → NotEmergency (INV-006 brake authority).
    const wrongPause = await conn.pause({ signer: owner.connect(provider) });
    assert.equal(wrongPause.ok, false);
    assert.equal(wrongPause.errorName, 'NotEmergency', diag(wrongPause));

    // Valid execution through the attached connection, then revoke (owner).
    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
      },
      privateKeyHex: AGENT_PK,
    });
    const exec = await conn.executeFromAgent({ payload: signed.payload, signature: signed.signature });
    assert.equal(exec.ok, true, exec.reason ?? 'execute via attached connection failed');
    assert.equal(exec.amount, 10n);

    const rev = await conn.revokeSession({ sessionId: SESSION_ID });
    assert.equal(rev.ok, true, rev.reason ?? 'revoke failed');
    assert.equal((await conn.contract.sessions(SESSION_ID)).revoked, true);

    // Revoked session → SessionRevokedError even with a fresh valid nonce (INV-003).
    const signed2 = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '10',
        recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '2',
      },
      privateKeyHex: AGENT_PK,
    });
    const sim = await conn.simulateExecuteFromAgent({ payload: signed2.payload, signature: signed2.signature });
    assert.equal(sim.ok, false);
    assert.equal(sim.errorName, 'SessionRevokedError', diag(sim));
  } finally {
    await chain.stop();
  }
});

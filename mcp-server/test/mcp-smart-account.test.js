import { test, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, __resetSmartAccountForTest } from '../src/server.js';

// External review 2026-08-24: the default in-process LocalChain path now
// requires an explicit opt-in. These tests deliberately use the ephemeral
// local chain (its whole state dies with the process — fine for tests).
process.env.CHAIN_ALLOW_LOCAL = '1';

// Sprint 5 T4: the SMART_ACCOUNT_SIMULATION_GATE=0 opt-out was removed —
// preview-first is the only path. Every execute below is preceded by a signed
// preview that arms the gate for that exact digest (success paths), or asserts
// the fail-closed SimulationRequired outcome (paths that can never arm).

let server;
let client;
let clientTransport;
let serverTransport;

// ─── Shared Smart Account fixtures (official EVM path, Sprint 2.4 on-chain) ──
// owner/emergencyKey are PRIVILEGED PRIVATE KEYS (server-side operation keys):
// their derived addresses become the contract owner/emergency roles, and owner
// signs deploy + registerSession. The Agent's execution signing key (AGENT_PK)
// NEVER enters the process — callers submit payload + signature only.
// All three keys are funded on the booted LocalChain (see bootChainEnv).
const OWNER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil #0 (funded)
const EMERGENCY_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // anvil #1 (funded)
const SECOND_OWNER_PK = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // anvil #2 (funded)
const SECOND_EMERGENCY_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil #0 — distinct (owner,emergency) pair
const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 'test-agent';
const AGENT_PK = '0x' + '11'.repeat(32);
const ISSUED_AT = Date.now() - 1000;
const EXPIRES_AT = Date.now() + 3600_000;

const WHITELIST = {
  allowedChains: ['ethereum'],
  allowedAssets: ['USDC'],
  allowedContracts: ['0xToken'],
  allowedMethods: ['transfer'],
  allowedRecipients: ['0xRecipient'],
};

const INTENT = {
  action: 'transfer',
  chain: 'ethereum',
  asset: 'USDC',
  amount: '25',
  recipient: '0xRecipient',
  contract: '0xToken',
  method: 'transfer',
  nonce: '1',
};

const SESSION_BINDING = { agentId: AGENT_ID, sessionId: SESSION_ID, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT };

before(async () => {
  __resetSmartAccountForTest();
  server = createServer();
  [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-smart-account', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

beforeEach(() => {
  __resetSmartAccountForTest();
});

after(async () => {
  await client.close();
  await server.close();
  // Stop the on-chain LocalChain (chainEnv) so the test process can exit.
  __resetSmartAccountForTest();
});

async function callTool(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(res.content[0].text);
}

/** Create a local on-chain Smart Account with the shared fixtures. */
async function setupAccount() {
  const { addressForPrivateKey } = await import('aegis-chain-eth');
  const out = await callTool('smart_account_setup', {
    owner: OWNER_PK,
    emergencyKey: EMERGENCY_PK,
    sessionId: SESSION_ID,
    agentId: AGENT_ID,
    agentEvmAddress: addressForPrivateKey(AGENT_PK),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    maxPerTx: '100',
    maxDaily: '500',
    ...WHITELIST,
  });
  return out;
}

test('lists Smart Account tools (official EVM path)', async () => {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name);
  for (const expected of ['smart_account_setup', 'smart_account_preview', 'smart_account_execute', 'smart_account_estimate_loss']) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }
});

test('smart_account_setup creates the account + session + exposure bound', async () => {
  const out = await setupAccount();
  assert.equal(out.success, true, JSON.stringify(out));
  assert.equal(out.onChain, true);
  assert.equal(out.sessionId, SESSION_ID);
  assert.match(out.accountId, /^0x[0-9a-f]{40}$/); // lowercase hex contract address
  assert.equal(out.contractAddress, out.accountId);
  assert.equal(out.issuedAt, ISSUED_AT);
  assert.equal(out.expiresAt, EXPIRES_AT);
  assert.deepEqual(out.session, {
    agentId: AGENT_ID,
    sessionId: SESSION_ID,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    agentEvmAddress: out.session.agentEvmAddress,
  });
  assert.match(out.session.agentEvmAddress, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(out.maxLoss, '500'); // min(accountDaily 1M, sessionDaily 500)
  // External review 2026-08-24: the local chain mode must be unmistakable —
  // ephemeral:true + warning so an LLM caller can never mistake the returned
  // contract address for a persistent on-chain deployment.
  assert.equal(out.chain.mode, 'local-ephemeral');
  assert.equal(out.chain.ephemeral, true);
  assert.match(out.chain.warning, /EPHEMERAL/);
});

test('smart_account_setup fails closed without CHAIN_ALLOW_LOCAL (no silent ephemeral chain)', async () => {
  const saved = process.env.CHAIN_ALLOW_LOCAL;
  const savedRpc = process.env.CHAIN_RPC_URL;
  delete process.env.CHAIN_ALLOW_LOCAL;
  delete process.env.CHAIN_RPC_URL;
  __resetSmartAccountForTest(); // drop any memoized chain env
  try {
    const out = await callTool('smart_account_setup', {
      owner: OWNER_PK,
      emergencyKey: EMERGENCY_PK,
      sessionId: SESSION_ID,
      agentId: AGENT_ID,
      agentEvmAddress: '0x0000000000000000000000000000000000000001',
      expiresAt: EXPIRES_AT,
      maxPerTx: '100',
      maxDaily: '500',
    });
    assert.equal(out.success, false);
    assert.match(out.error, /CHAIN_ALLOW_LOCAL/);
    assert.match(out.error, /EPHEMERAL/);
  } finally {
    process.env.CHAIN_ALLOW_LOCAL = saved ?? '1'; // restore the test-file opt-in
    if (savedRpc !== undefined) process.env.CHAIN_RPC_URL = savedRpc;
    __resetSmartAccountForTest();
  }
});

test('smart_account_setup rejects a malformed sessionId (fail-closed)', async () => {
  const out = await callTool('smart_account_setup', {
    owner: OWNER_PK,
    emergencyKey: EMERGENCY_PK,
    sessionId: 'not-32-bytes',
    agentId: AGENT_ID,
    agentEvmAddress: '0x0000000000000000000000000000000000000000',
    expiresAt: EXPIRES_AT,
  });
  assert.equal(out.success, false);
  assert.match(out.error, /32-byte hex/);
});

test('smart_account_preview without signature returns wouldExecute:null + digest (no pseudo-verdict)', async () => {
  await setupAccount();
  const out = await callTool('smart_account_preview', { ...INTENT, nonce: 1 });
  assert.equal(out.success, true, JSON.stringify(out));
  // No signature → no on-chain verdict is computed (T1.3 semantics).
  assert.equal(out.wouldExecute, null, JSON.stringify(out));
  assert.match(out.digest, /^0x[0-9a-f]{64}$/);
  assert.equal(out.sessionId, SESSION_ID);
  assert.equal(out.session.issuedAt, ISSUED_AT);
  assert.equal(out.payload.sessionId, SESSION_ID);
  assert.equal(out.amount, '25');
});

test('smart_account_preview with a valid signature returns wouldExecute:true (on-chain dry-run)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });
  const out = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(out.success, true, JSON.stringify(out));
  assert.equal(out.wouldExecute, true, JSON.stringify(out));
  assert.match(out.digest, /^0x[0-9a-f]{64}$/);
  assert.equal(out.amount, '25');

  // Side-effect free: preview consumed nothing — exposure bound unchanged and
  // the SAME nonce is still usable by a real execution.
  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.success, true);
  assert.equal(est.accountRemaining, '1000000');
  assert.equal(est.sessionMaxLoss, '500');

  const exec = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(exec.success, true, JSON.stringify(exec));
  assert.equal(exec.amount, '25');
  assert.match(exec.txHash, /^0x[0-9a-f]{64}$/); // mined tx (executeFromAgent awaits receipt)
  assert.match(exec.txId, /^0x[0-9a-f]{64}$/); // keccak256(sessionId, nonce), bytes32

  // The broadcast really landed: on-chain exposure bound decremented (T1.4+T1.5).
  const post = await callTool('smart_account_estimate_loss', {});
  assert.equal(post.success, true);
  assert.equal(post.accountRemaining, '999975'); // 1M - 25
  assert.equal(post.sessionMaxLoss, '475'); // 500 - 25
});

test('implicit issuedAt is returned and can be used to reproduce a signable payload', async () => {
  const { addressForPrivateKey, signSmartAccountIntent } = await import('aegis-chain-eth');
  const sessionId = '0x' + 'cd'.repeat(32);
  const expiresAt = Date.now() + 3600_000;
  const setup = await callTool('smart_account_setup', {
    owner: OWNER_PK,
    emergencyKey: EMERGENCY_PK,
    sessionId,
    agentId: 'implicit-issued-at',
    agentEvmAddress: addressForPrivateKey(AGENT_PK),
    expiresAt,
    maxPerTx: '100',
    maxDaily: '500',
    ...WHITELIST,
  });
  assert.equal(setup.success, true, JSON.stringify(setup));
  assert.equal(typeof setup.issuedAt, 'number');
  assert.equal(setup.session.issuedAt, setup.issuedAt);
  assert.equal(setup.session.expiresAt, expiresAt);

  const preview = await callTool('smart_account_preview', {
    accountId: setup.accountId,
    sessionId,
    ...INTENT,
    nonce: 1,
  });
  assert.equal(preview.success, true, JSON.stringify(preview));
  assert.equal(preview.wouldExecute, null, JSON.stringify(preview)); // no signature
  assert.equal(preview.session.issuedAt, setup.issuedAt);
  assert.equal(preview.payload.sessionIssuedAt, setup.issuedAt);

  const signed = signSmartAccountIntent({
    session: {
      agentId: preview.session.agentId,
      sessionId: preview.session.sessionId,
      issuedAt: preview.session.issuedAt,
      expiresAt: preview.session.expiresAt,
    },
    intent: INTENT,
    privateKeyHex: AGENT_PK,
  });
  assert.deepEqual(
    { ...signed.payload, nonce: String(signed.payload.nonce) },
    { ...preview.payload, nonce: String(preview.payload.nonce) },
  );

  // T4 preview-first: arm the simulation gate with a signed preview of the
  // exact digest before executing.
  const armed = await callTool('smart_account_preview', {
    accountId: setup.accountId,
    sessionId,
    ...INTENT,
    nonce: 1,
    signature: signed.signature,
  });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', {
    accountId: setup.accountId,
    sessionId,
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(exec.success, true, JSON.stringify(exec));
});

test('smart_account_preview with a signature rejects an out-of-whitelist intent (INV-003)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const bad = { ...INTENT, chain: 'solana' };
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: bad, privateKeyHex: AGENT_PK });
  const out = await callTool('smart_account_preview', { ...bad, nonce: 1, signature: signed.signature });
  assert.equal(out.success, true);
  assert.equal(out.wouldExecute, false);
  assert.equal(out.reason, 'WhitelistViolation');
});

test('smart_account_preview with a signature rejects a self-escalation action (INV-005)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const bad = { ...INTENT, action: 'raise_limit', method: 'raise_limit' };
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: bad, privateKeyHex: AGENT_PK });
  const out = await callTool('smart_account_preview', { ...bad, nonce: 1, signature: signed.signature });
  assert.equal(out.success, true);
  assert.equal(out.wouldExecute, false);
  assert.equal(out.reason, 'SelfEscalationRejected');
});

test('smart_account_execute rejects a forged signature (INV-002)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });
  const garbageSignature = '0x' + '00'.repeat(65); // not the session key

  // T4 preview-first: the forged signature is rejected on the SAME on-chain
  // verify path during preview — wouldExecute stays false and the gate is
  // NOT armed for this digest.
  const prev = await callTool('smart_account_preview', {
    ...INTENT,
    nonce: 1,
    signature: garbageSignature,
  });
  assert.equal(prev.success, true);
  assert.equal(prev.wouldExecute, false);
  assert.equal(prev.reason, 'InvalidSignature');

  // Execute without a valid armed preview → fail-closed SimulationRequired
  // (never reaches the relayer with the forged payload).
  const out = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: garbageSignature,
  });
  assert.equal(out.success, false);
  assert.equal(out.error, 'SimulationRequired');
});

test('smart_account_execute rejects a replayed nonce (INV-007)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the exact digest once.
  const armed = await callTool('smart_account_preview', {
    ...INTENT,
    nonce: 1,
    signature: signed.signature,
  });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const first = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(first.success, true, JSON.stringify(first));

  // Same payload + signature again → nonce already consumed on-chain. The
  // armed digest still matches (same payload), so the gate passes and the
  // replay surfaces as the on-chain BadNonce.
  const replay = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(replay.success, false, JSON.stringify(replay));
  assert.equal(replay.error, 'BadNonce');

  // The revert rolled back — only the first execution counts.
  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.accountRemaining, '999975');
});

test('smart_account_execute enforces the per-tx ceiling (INV-007)', async () => {
  await setupAccount();
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const big = { ...INTENT, amount: '250', nonce: '1' };
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: big, privateKeyHex: AGENT_PK });

  // T4 preview-first: the over-ceiling amount is rejected by the SAME on-chain
  // hard-policy path during preview — gate not armed for this digest.
  const prev = await callTool('smart_account_preview', {
    ...big,
    nonce: 1,
    signature: signed.signature,
  });
  assert.equal(prev.success, true);
  assert.equal(prev.wouldExecute, false);
  assert.equal(prev.reason, 'AmountExceedsPerTx');

  // Execute can never be armed → fail-closed SimulationRequired before the
  // relayer is touched.
  const out = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(out.success, false);
  assert.equal(out.error, 'SimulationRequired');

  // Rejection is side-effect free.
  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.accountRemaining, '1000000');
  assert.equal(est.sessionMaxLoss, '500');
});

test('smart_account_estimate_loss reports account + session bounds (INV-007)', async () => {
  await setupAccount();
  const out = await callTool('smart_account_estimate_loss', {});
  assert.equal(out.success, true);
  assert.equal(out.onChain, true);
  assert.match(out.accountId, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(out.sessionId, SESSION_ID);
  // Strings — no BigInt leak, no Number rounding on wei-scale ceilings.
  for (const k of ['accountMaxDaily', 'accountRemaining', 'sessionMaxLoss']) {
    assert.equal(typeof out[k], 'string', `${k} must be a string`);
  }
  assert.equal(out.accountMaxDaily, '1000000'); // deploy-pinned
  assert.equal(out.accountRemaining, '1000000'); // nothing spent yet
  assert.equal(out.sessionMaxLoss, '500'); // session daily ceiling
});

test('multiple Smart Accounts can coexist and be selected explicitly', async () => {
  const { addressForPrivateKey, signSmartAccountIntent } = await import('aegis-chain-eth');
  const first = await setupAccount();
  const secondSessionId = '0x' + 'ef'.repeat(32);
  const second = await callTool('smart_account_setup', {
    owner: SECOND_OWNER_PK,
    emergencyKey: SECOND_EMERGENCY_PK,
    sessionId: secondSessionId,
    agentId: 'second-agent',
    agentEvmAddress: addressForPrivateKey('0x' + '22'.repeat(32)),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    maxPerTx: '100',
    maxDaily: '500',
    ...WHITELIST,
  });
  assert.equal(second.success, true, JSON.stringify(second));
  assert.notEqual(second.accountId, first.accountId);

  const firstPreview = await callTool('smart_account_preview', {
    accountId: first.accountId,
    sessionId: first.sessionId,
    ...INTENT,
    nonce: 1,
  });
  assert.equal(firstPreview.success, true, JSON.stringify(firstPreview));
  assert.equal(firstPreview.accountId, first.accountId);
  assert.equal(firstPreview.sessionId, first.sessionId);
  assert.equal(firstPreview.wouldExecute, null); // no signature

  const signed = signSmartAccountIntent({
    session: {
      agentId: AGENT_ID,
      sessionId: SESSION_ID,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
    },
    intent: INTENT,
    privateKeyHex: AGENT_PK,
  });
  // T4 preview-first: arm the FIRST account's gate (explicit accountId — two
  // accounts coexist, arming is per-account).
  const armed = await callTool('smart_account_preview', {
    accountId: first.accountId,
    sessionId: first.sessionId,
    ...INTENT,
    nonce: 1,
    signature: signed.signature,
  });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', {
    accountId: first.accountId,
    sessionId: first.sessionId,
    payload: signed.payload,
    signature: signed.signature,
  });
  assert.equal(exec.success, true, JSON.stringify(exec));
  assert.equal(exec.accountId, first.accountId);

  const secondLoss = await callTool('smart_account_estimate_loss', {
    accountId: second.accountId,
    sessionId: second.sessionId,
  });
  assert.equal(secondLoss.success, true);
  assert.equal(secondLoss.accountId, second.accountId);
  assert.equal(secondLoss.sessionId, second.sessionId);
  assert.equal(secondLoss.accountRemaining, '1000000'); // untouched account
});

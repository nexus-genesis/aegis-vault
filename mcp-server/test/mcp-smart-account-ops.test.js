/**
 * Sprint 2.7 — 可审计 / 可观测 / 交易生命周期 (ops 面) 测试
 *
 * 覆盖：
 *   T1 审计日志  — setup/preview/execute(成功+失败)/estimate_loss 均留痕，字段完整
 *                  （accountId / sessionId / payloadDigest / txHash / errorName /
 *                    broadcaster / timestamp）；AUDIT_LOG_FILE 落盘 JSON lines。
 *   T2 可观测性  — 计数器：preview 次数、execute total/success/failed、
 *                  revert 分类、nonce 冲突、超限/过期拒绝。
 *   T3 生命周期  — execute 返回 status:'confirmed'；smart_account_tx_status 重查
 *                  链上 receipt（confirmed+blockNumber / submitted）；交易台账
 *                  随 SMART_ACCOUNT_STATE_FILE 持久化。
 */
import { test, before, beforeEach, after } from 'node:test';
// External review 2026-08-24: default LocalChain path requires explicit opt-in.
process.env.CHAIN_ALLOW_LOCAL = '1';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, __resetSmartAccountForTest } from '../src/server.js';
import { loadChainState } from '../src/chain-state-store.js';
import { readFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const STATE_FILE = join(tmpdir(), `ops-state-${process.pid}-${Date.now()}.json`);
const AUDIT_FILE = join(tmpdir(), `ops-audit-${process.pid}-${Date.now()}.jsonl`);

// Sprint 5 T4: the SMART_ACCOUNT_SIMULATION_GATE=0 opt-out was removed —
// preview-first is the only path. Executes below arm the gate via signed
// previews; fail-closed paths (over-ceiling) surface as SimulationRequired
// while on-chain reverts (replay / forged signature) keep their typed errors
// when the armed digest matches.

// 持久化 + 审计落盘（local 配置面也启用，验证文件写入与台账随状态持久化）。
process.env.SMART_ACCOUNT_STATE_FILE = STATE_FILE;
process.env.AUDIT_LOG_FILE = AUDIT_FILE;

// ─── 共享 fixtures（与 mcp-smart-account.test.js 一致：local 配置面默认 anvil 密钥）──
const OWNER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil #0 (funded)
const EMERGENCY_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // anvil #1 (funded)
const RELAYER_PK = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // anvil #2 (funded, default relayer)
const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 'ops-agent';
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
  action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
  recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
};

const SESSION_BINDING = { agentId: AGENT_ID, sessionId: SESSION_ID, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT };

let server;
let client;
let clientTransport;
let serverTransport;

before(async () => {
  __resetSmartAccountForTest();
  server = createServer();
  [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-ops', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

beforeEach(() => {
  __resetSmartAccountForTest();
});

after(async () => {
  await client.close();
  await server.close();
  __resetSmartAccountForTest();
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
  if (existsSync(AUDIT_FILE)) unlinkSync(AUDIT_FILE);
});

async function callTool(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(res.content[0].text);
}

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
  assert.equal(out.success, true, JSON.stringify(out));
  return out;
}

test('lists Sprint 2.7 ops tools (audit / metrics / tx_status)', async () => {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name);
  for (const expected of ['smart_account_audit', 'smart_account_metrics', 'smart_account_tx_status']) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }
});

test('T1 audit trail records setup/preview/execute/estimate_loss with full facts', async () => {
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const setup = await setupAccount();

  const preview = await callTool('smart_account_preview', { ...INTENT, nonce: 1 });
  assert.equal(preview.wouldExecute, null);

  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the exact digest with a signed preview.
  const armed = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true, JSON.stringify(exec));

  // 失败路径同样留痕（重放：armed digest 仍匹配 → 链上 BadNonce）。
  const badExec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(badExec.success, false);
  assert.equal(badExec.error, 'BadNonce');

  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.success, true);

  const audit = await callTool('smart_account_audit', {});
  assert.equal(audit.success, true);
  const byTool = (t) => audit.entries.filter((e) => e.tool === t);

  // setup 留痕。
  const setupRows = byTool('smart_account_setup');
  assert.equal(setupRows.length, 1);
  assert.equal(setupRows[0].ok, true);
  assert.equal(setupRows[0].accountId, setup.accountId);
  assert.equal(setupRows[0].sessionId, SESSION_ID);
  assert.equal(setupRows[0].broadcaster, setup.owner);
  assert.match(setupRows[0].timestamp, /^\d{4}-\d{2}-\d{2}T/);

  // preview 留痕 ×2（无签名 wouldExecute:null + armed wouldExecute:true，均带 payloadDigest）。
  const previewRows = byTool('smart_account_preview');
  assert.equal(previewRows.length, 2);
  assert.equal(previewRows[0].wouldExecute, null);
  assert.equal(previewRows[1].wouldExecute, true);
  assert.match(previewRows[0].payloadDigest, /^0x[0-9a-f]{64}$/);

  // execute 成功留痕：payloadDigest / txHash / broadcaster = relayer（非 owner）。
  const okRows = byTool('smart_account_execute').filter((e) => e.ok === true);
  assert.equal(okRows.length, 1);
  assert.equal(okRows[0].txHash, exec.txHash);
  assert.match(okRows[0].payloadDigest, /^0x[0-9a-f]{64}$/);
  const { Wallet } = await import('ethers');
  assert.equal(okRows[0].broadcaster, new Wallet(RELAYER_PK).address, 'execute must be audited with the relayer broadcaster');

  // execute 失败留痕：errorName（T4 迁移后链上失败路径为重放 BadNonce）。
  const badRows = byTool('smart_account_execute').filter((e) => e.ok === false);
  assert.equal(badRows.length, 1);
  assert.equal(badRows[0].errorName, 'BadNonce');
  assert.equal(badRows[0].broadcaster, new Wallet(RELAYER_PK).address);

  // estimate_loss 留痕。
  assert.equal(byTool('smart_account_estimate_loss').length, 1);

  // 按 accountId 过滤可查回。
  const filtered = await callTool('smart_account_audit', { accountId: setup.accountId });
  assert.ok(filtered.entries.length >= 5);
  assert.ok(filtered.entries.every((e) => e.accountId === setup.accountId));

  // AUDIT_LOG_FILE 落盘为 JSON lines（含 execute 行）。
  assert.ok(existsSync(AUDIT_FILE), 'audit file must be written');
  const lines = readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
  assert.ok(lines.some((l) => JSON.parse(l).tool === 'smart_account_execute' && JSON.parse(l).txHash === exec.txHash));
});

test('T2 metrics reflect preview count, execute success/failed, revert, nonce conflict, limit rejection', async () => {
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  await setupAccount();

  // preview（无签名）×1
  await callTool('smart_account_preview', { ...INTENT, nonce: 1 });

  // T4 preview-first: arm the exact digest ×1（wouldExecute:true 也计数 preview）。
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });
  const armed = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  // execute 成功 ×1
  const ok = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(ok.success, true);

  // 超限 ×1（T4 迁移：preview 端 typed revert —— limit_rejected + revert 分类；
  // execute 端该 digest 永远无法 arm → fail-closed SimulationRequired）
  const big = { ...INTENT, amount: '250', nonce: '2' };
  const signedBig = signSmartAccountIntent({ session: SESSION_BINDING, intent: big, privateKeyHex: AGENT_PK });
  const bigPrev = await callTool('smart_account_preview', { ...big, nonce: 2, signature: signedBig.signature });
  assert.equal(bigPrev.wouldExecute, false);
  assert.equal(bigPrev.reason, 'AmountExceedsPerTx');
  const bigRes = await callTool('smart_account_execute', { payload: signedBig.payload, signature: signedBig.signature });
  assert.equal(bigRes.success, false);
  assert.equal(bigRes.error, 'SimulationRequired');

  // 重放 ×1（BadNonce → nonce_conflict；armed digest 仍匹配 → 到达链上）
  const replay = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(replay.success, false);
  assert.equal(replay.error, 'BadNonce');

  // 伪造签名 ×1（payload digest 与 armed 匹配 → 过门禁，链上 InvalidSignature → revert 分类）
  const forged = await callTool('smart_account_execute', { payload: signed.payload, signature: '0x' + '00'.repeat(65) });
  assert.equal(forged.success, false);
  assert.equal(forged.error, 'InvalidSignature');

  const m = (await callTool('smart_account_metrics')).metrics;
  assert.equal(m.smart_account_setup_count, 1);
  assert.equal(m.smart_account_preview_count, 3);
  assert.equal(m.smart_account_execute_total, 3); // ok + replay + forged（SimulationRequired 在门禁层，不进 execute_total）
  assert.equal(m.smart_account_execute_success, 1);
  assert.equal(m.smart_account_execute_failed, 2);
  assert.equal(m.smart_account_simulation_blocked, 1, '超限 execute 被模拟门禁拦截');
  assert.equal(m.smart_account_nonce_conflict, 1, 'BadNonce → nonce_conflict');
  assert.equal(m.smart_account_limit_rejected, 1, 'AmountExceedsPerTx（preview）→ limit_rejected');
  assert.equal(m.smart_account_revert_AmountExceedsPerTx, 1);
  assert.equal(m.smart_account_revert_BadNonce, 1);
  assert.equal(m.smart_account_revert_InvalidSignature, 1);
});

test('T3 tx lifecycle: execute returns status + tx_status re-checks on-chain receipt', async () => {
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  await setupAccount();

  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the exact digest.
  const armed = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true);
  assert.equal(exec.status, 'confirmed', 'execute must report lifecycle status');

  // 已广播 txHash → 台账有记录 + 链上重查 confirmed + blockNumber。
  const st = await callTool('smart_account_tx_status', { txHash: exec.txHash });
  assert.equal(st.success, true, JSON.stringify(st));
  assert.equal(st.recorded.length, 1);
  assert.equal(st.recorded[0].status, 'confirmed');
  assert.equal(st.recorded[0].txHash, exec.txHash);
  assert.equal(st.recorded[0].accountId, exec.accountId);
  assert.equal(st.onChain.status, 'confirmed');
  assert.match(String(st.onChain.blockNumber), /^\d+$/);
  assert.match(String(st.onChain.gasUsed), /^\d+$/);

  // 未上链 hash → submitted（无 receipt）。
  const ghost = await callTool('smart_account_tx_status', { txHash: '0x' + 'ee'.repeat(32) });
  assert.equal(ghost.success, true);
  assert.equal(ghost.recorded.length, 0);
  assert.equal(ghost.onChain.status, 'submitted');

  // txHash 缺失 → fail-closed。
  const missing = await callTool('smart_account_tx_status', {});
  assert.equal(missing.success, false);
  assert.match(missing.error, /txHash is required/);
});

test('T3 tx ledger + audit persist into the state/audit files (durable facts)', async () => {
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const setup = await setupAccount();
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the exact digest.
  const armed = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true);

  // 状态文件携带 transactions 台账（accountId / sessionId / status / txHash / blockNumber）。
  // Sprint 6 T3：落盘为行级 store 格式——断言走语义层 loadChainState()（格式无关）。
  assert.ok(existsSync(STATE_FILE), 'state file must be written');
  const raw = loadChainState();
  assert.ok(Array.isArray(raw.transactions) && raw.transactions.length >= 1);
  const tx = raw.transactions.find((t) => t.txHash === exec.txHash);
  assert.ok(tx, 'confirmed tx must be in the persisted ledger');
  assert.equal(tx.accountId, setup.accountId);
  assert.equal(tx.sessionId, SESSION_ID);
  assert.equal(tx.status, 'confirmed');
  assert.match(String(tx.blockNumber), /^\d+$/);
  assert.ok(tx.submittedAt && tx.confirmedAt);
});

/**
 * Sprint 3 — Simulation 正式化 + Policy Engine 外置化 测试
 *
 * 覆盖：
 *   T1 Simulation gate  fail-closed：required action 未经成功 signed preview → SimulationRequired；
 *                        经成功 preview → 放行；digest 不匹配 → 仍拒绝。
 *   T2 Policy Engine    SMART_ACCOUNT_POLICY_FILE 规则生效：超限 → PolicyRejected；
 *                        默认（无文件）→ 软策略放行，链上硬策略兜底。
 *   工具面              smart_account_simulation_policy / smart_account_policy 查询。
 *   可观测              metrics：simulation_blocked / policy_rejected；audit 带 gate 字段。
 */
import { test, before, beforeEach, after } from 'node:test';
// External review 2026-08-24: default LocalChain path requires explicit opt-in.
process.env.CHAIN_ALLOW_LOCAL = '1';
import assert from 'node:assert/strict';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, __resetSmartAccountForTest } from '../src/server.js';
import { classifySimulationRisk } from '../src/simulation-policy.js';
import { evaluatePolicy, policySnapshot, createDailyCumulativeStore, resolveSimulationRequirement, todayKey, policyFailMode, lastPolicyLoadError, resetPolicyEngineState } from '../src/policy-engine.js';

const STATE_FILE = join(tmpdir(), `sim-policy-state-${process.pid}-${Date.now()}.json`);
const POLICY_FILE = join(tmpdir(), `sim-policy-rules-${process.pid}-${Date.now()}.json`);

process.env.SMART_ACCOUNT_STATE_FILE = STATE_FILE;

// local 配置面（anvil 密钥，与既有测试一致）。
const OWNER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EMERGENCY_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 'sim-policy-agent';
const AGENT_PK = '0x' + '11'.repeat(32);
const ISSUED_AT = Date.now() - 1000;
const EXPIRES_AT = Date.now() + 3600_000;
const SESSION_BINDING = { agentId: AGENT_ID, sessionId: SESSION_ID, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT };

const INTENT = {
  action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
  recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
};

const WHITELIST = {
  allowedChains: ['ethereum'],
  allowedAssets: ['USDC'],
  allowedContracts: ['0xToken'],
  allowedMethods: ['transfer'],
  allowedRecipients: ['0xRecipient'],
};

let server;
let client;
let clientTransport;
let serverTransport;

before(async () => {
  __resetSmartAccountForTest();
  server = createServer();
  [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-sim-policy', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

beforeEach(() => {
  __resetSmartAccountForTest();
});

after(async () => {
  await client.close();
  await server.close();
  __resetSmartAccountForTest();
  for (const f of [STATE_FILE, POLICY_FILE]) {
    if (existsSync(f)) unlinkSync(f);
  }
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

// 延迟 import 避免模块初始化顺序问题；本地封装签名。
let _signer;
async function signSmartAccountIntentLocal(intent) {
  if (!_signer) {
    const { signSmartAccountIntent } = await import('aegis-chain-eth');
    _signer = signSmartAccountIntent;
  }
  return _signer({ session: SESSION_BINDING, intent, privateKeyHex: AGENT_PK });
}

// ─── 单元：simulation-policy 分类 ────────────────────────────────────────
test('T1 classifySimulationRisk: required / skippable / unknown fail-closed', () => {
  assert.equal(classifySimulationRisk('transfer').level, 'required');
  assert.equal(classifySimulationRisk('transfer').requiresSimulation, true);
  assert.equal(classifySimulationRisk('raise-limit').requiresSimulation, true);
  assert.equal(classifySimulationRisk('balance').requiresSimulation, false);
  assert.equal(classifySimulationRisk('view').level, 'skippable');
  // 未知 action → required（fail-closed）
  assert.equal(classifySimulationRisk('totally-unknown-action').requiresSimulation, true);
  assert.equal(classifySimulationRisk('').requiresSimulation, true);
});

// ─── 单元：policy-engine ─────────────────────────────────────────────────
test('T2 evaluatePolicy: default (no file) is permissive; file rules enforce', () => {
  try {
    // 默认：无 SMART_ACCOUNT_POLICY_FILE → 软策略放行。
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
    assert.deepEqual(evaluatePolicy({ action: 'transfer', amount: '999999' }), { allowed: true });

    // 有规则文件：enabled:false → 拒绝；maxPerTx 超限 → 拒绝；未命中 → 放行。
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [
        { action: 'transfer', enabled: true, maxPerTx: '10' },
        { action: 'withdraw', enabled: false },
      ],
    }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    const over = evaluatePolicy({ action: 'transfer', amount: '25' });
    assert.equal(over.allowed, false);
    assert.equal(over.code, 'PolicyRejected');

    const disabled = evaluatePolicy({ action: 'withdraw' });
    assert.equal(disabled.allowed, false);
    assert.equal(disabled.code, 'PolicyRejected');

    const ok = evaluatePolicy({ action: 'transfer', amount: '5' });
    assert.deepEqual(ok, { allowed: true });

    const unlisted = evaluatePolicy({ action: 'swap' });
    assert.deepEqual(unlisted, { allowed: true });

    const snap = policySnapshot();
    assert.equal(snap.rules.length, 2);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

test('T2 evaluatePolicy: BigInt-safe ceiling + malformed amount fail-closed (review fix)', () => {
  try {
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [{ action: 'transfer', enabled: true, maxPerTx: '9007199254740992' }], // 2^53
    }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    // 2^53 + 1 > 2^53：Number() 会双双舍入为 2^53（相等→放行），BigInt 精确比较 → 拒绝。
    const precision = evaluatePolicy({ action: 'transfer', amount: '9007199254740993' });
    assert.equal(precision.allowed, false, 'wei 级金额不得因 Number 精度损失而绕过限额');
    assert.equal(precision.code, 'PolicyRejected');

    // 边界值本身（等于限额）→ 放行。
    const atLimit = evaluatePolicy({ action: 'transfer', amount: '9007199254740992' });
    assert.deepEqual(atLimit, { allowed: true });

    // malformed amount（非数字）→ fail-closed 拒绝，不得静默放行。
    const malformed = evaluatePolicy({ action: 'transfer', amount: 'not-a-number' });
    assert.equal(malformed.allowed, false);
    assert.match(malformed.reason, /not numeric/);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

test('T2 loadPolicy: corrupted policy file degrades to permissive (on-chain backstop)', () => {
  try {
    writeFileSync(POLICY_FILE, '{ not valid json !!!', 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
    // 软策略回退为空表（放行）——链上硬策略兜底；行为与设计一致。
    assert.deepEqual(evaluatePolicy({ action: 'transfer', amount: '999' }), { allowed: true });
    assert.equal(policySnapshot().rules.length, 0);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── 集成：工具面 ────────────────────────────────────────────────────────
test('tools smart_account_simulation_policy / smart_account_policy exist and respond', async () => {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name);
  assert.ok(names.includes('smart_account_simulation_policy'));
  assert.ok(names.includes('smart_account_policy'));

  const sp = await callTool('smart_account_simulation_policy', { action: 'transfer' });
  assert.equal(sp.success, true);
  assert.equal(sp.risk.level, 'required');
  assert.equal(sp.policy.windowMs, 60000);

  const pol = await callTool('smart_account_policy', {});
  assert.equal(pol.success, true);
  assert.ok(Array.isArray(pol.policy.rules));
});

// ─── 集成：simulation gate fail-closed ───────────────────────────────────
test('T1 execute without a successful signed preview → SimulationRequired (fail-closed)', async () => {
  await setupAccount();
  const { payload, signature } = await signSmartAccountIntentLocal(INTENT);

  // 未经 preview 直接 execute（transfer 为 required）→ 拒绝，不走链。
  const blocked = await callTool('smart_account_execute', { payload, signature });
  assert.equal(blocked.success, false);
  assert.equal(blocked.error, 'SimulationRequired');
  assert.equal(blocked.simulation.level, 'required');

  // 指标 + 审计留痕（gate: simulation）。
  const m = (await callTool('smart_account_metrics', {})).metrics;
  assert.equal(m.smart_account_simulation_blocked, 1);
  const audit = await callTool('smart_account_audit', {});
  const gated = audit.entries.find((e) => e.gate === 'simulation');
  assert.equal(gated.errorName, 'SimulationRequired');
});

test('T1 signed preview arms the gate → execute proceeds', async () => {
  await setupAccount();
  const { payload, signature } = await signSmartAccountIntentLocal(INTENT);

  // 带签名成功 preview（wouldExecute=true，且为 required action 提供 digest 记录）。
  const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
  assert.equal(prev.success, true, JSON.stringify(prev));
  assert.equal(prev.wouldExecute, true);
  assert.equal(prev.simulation.level, 'required');

  // 同一 digest → 门禁放行，execute 成功。
  const exec = await callTool('smart_account_execute', { payload, signature });
  assert.equal(exec.success, true, JSON.stringify(exec));
  assert.equal(exec.status, 'confirmed');

  // 非 required action（balance）即使无 preview 也不拦截。
  const balance = await callTool('smart_account_preview', {
    action: 'balance', chain: 'ethereum', asset: 'USDC', amount: '0',
    recipient: '0xRecipient', contract: '0xToken', method: 'view', nonce: '2',
  });
  assert.equal(balance.success, true);
});

test('T1 digest mismatch (different intent than previewed) → still fail-closed', async () => {
  await setupAccount();
  const { payload, signature } = await signSmartAccountIntentLocal(INTENT);

  // preview 一个 intent。
  const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
  assert.equal(prev.wouldExecute, true);

  // 换一个 amount 的 payload（digest 不同）→ 门禁拒绝（未模拟该 digest）。
  const other = await signSmartAccountIntentLocal({ ...INTENT, amount: '50', nonce: '2' });
  const blocked = await callTool('smart_account_execute', { payload: other.payload, signature: other.signature });
  assert.equal(blocked.success, false);
  assert.equal(blocked.error, 'SimulationRequired');
});

// ─── 集成：policy engine gate ────────────────────────────────────────────
test('T2 policy maxPerTx rejection happens off-chain (never touches chain)', async () => {
  writeFileSync(POLICY_FILE, JSON.stringify({
    rules: [{ action: 'transfer', enabled: true, maxPerTx: '10' }],
  }), 'utf8');
  process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
  try {
    await setupAccount();
    const { payload, signature } = await signSmartAccountIntentLocal(INTENT);

    // 先成功 preview（通过 simulation gate）。
    const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
    assert.equal(prev.wouldExecute, true);

    // amount 25 > policy maxPerTx 10 → PolicyRejected（链下，不广播）。
    const rejected = await callTool('smart_account_execute', { payload, signature });
    assert.equal(rejected.success, false, JSON.stringify(rejected));
    assert.equal(rejected.error, 'PolicyRejected');
    assert.match(rejected.reason, /exceeds policy maxPerTx/);

    // 指标 + 审计（gate: policy）。
    const m = (await callTool('smart_account_metrics', {})).metrics;
    assert.equal(m.smart_account_policy_rejected, 1);
    const audit = await callTool('smart_account_audit', {});
    const gated = audit.entries.find((e) => e.gate === 'policy');
    assert.equal(gated.errorName, 'PolicyRejected');

    // 链上未发生任何 execute 广播：tx 台账为空。
    const st = await callTool('smart_account_tx_status', { txHash: '0x' + 'ee'.repeat(32) });
    assert.equal(st.recorded.length, 0);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── Sprint 5 T2.1 — maxDaily 进程内日累计 ──────────────────────────────
test('S5-T2.1 createDailyCumulativeStore: add/total/rollover-by-utc-day', () => {
  const store = createDailyCumulativeStore();
  const day = todayKey();
  const OTHER_DAY = '2020-01-01'; // 未触及的"昨日"

  assert.equal(store.total('acct1', 'transfer', day), '0');
  assert.equal(store.add('acct1', 'transfer', '40', day), '40');
  assert.equal(store.add('acct1', 'transfer', '5', day), '45');
  // 跨 action / account 隔离。
  assert.equal(store.total('acct1', 'withdraw', day), '0');
  assert.equal(store.total('acct2', 'transfer', day), '0');

  // 跨日滚动：对 account3 用 OTHER_DAY 累计后，同一日查询得到该日累计；
  // 再用今日 add（首次触及今日）→ 今日从零累计，旧日桶被剪枝但仍可读今日值。
  assert.equal(store.add('acct3', 'transfer', '10', OTHER_DAY), '10');
  // 同 key 的 acct3+transfer：加 OTHER_DAY 后再加今日，今日独立从 0 开始。
  assert.equal(store.add('acct3', 'transfer', '7', day), '7');
  assert.equal(store.total('acct3', 'transfer', day), '7');

  // acct1 的今日累计仍保留（各自独立桶，剪枝不影响 acct1）。
  assert.equal(store.total('acct1', 'transfer', day), '45');

  store.reset();
  assert.equal(store.total('acct1', 'transfer', day), '0');
});

test('S5-T2.1 evaluatePolicy maxDaily: cumulative gate fail-closed + add-on confirmed spend', () => {
  try {
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [{ action: 'transfer', enabled: true, maxPerTx: '100', maxDaily: '80' }],
    }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    // 无 store → maxDaily 不生效（soft-pass，链上兜底）；amount 在 maxPerTx 之内，仅 maxDaily 缺 store。
    assert.deepEqual(evaluatePolicy({ action: 'transfer', amount: '60' }, { rules: policySnapshot().rules }), { allowed: true });

    const store = createDailyCumulativeStore();
    const account = '0xA';
    // 初始 0：本次 50 ≤ 80 → 放行，且 verdict 携带 daily 预留信息（fix#1）。
    const pass = evaluatePolicy({ action: 'transfer', amount: '50', accountId: account }, { rules: policySnapshot().rules, store, accountId: account });
    assert.equal(pass.allowed, true);
    assert.equal(pass.daily.accountId, account);
    assert.equal(pass.daily.used, '0');
    assert.equal(pass.daily.projected, '50');
    assert.equal(pass.daily.limit, '80');
    // 已用 50 + 本次 40 = 90 > 80 → 拒绝。
    store.add(account, 'transfer', '50');
    const tooMuch = evaluatePolicy(
      { action: 'transfer', amount: '40', accountId: account },
      { rules: policySnapshot().rules, store, accountId: account },
    );
    assert.equal(tooMuch.allowed, false);
    assert.equal(tooMuch.code, 'PolicyRejected');
    assert.match(tooMuch.reason, /would exceed policy maxDaily 80/);

    // fix#4：只传 intent.accountId（不传 opts.accountId）同样生效。
    const viaIntent = evaluatePolicy(
      { action: 'transfer', amount: '40', accountId: account },
      { rules: policySnapshot().rules, store },
    );
    assert.equal(viaIntent.allowed, false);
    assert.match(viaIntent.reason, /would exceed policy maxDaily 80/);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

test('S5-T2.1 fix#1 store.subtract: rollback a reservation (floor at 0)', () => {
  const store = createDailyCumulativeStore();
  store.add('acct', 'transfer', '30');
  assert.equal(store.subtract('acct', 'transfer', '30'), '0');
  assert.equal(store.total('acct', 'transfer'), '0');
  // 减穿下限 → 钳位 0，不为负。
  store.add('acct', 'transfer', '10');
  assert.equal(store.subtract('acct', 'transfer', '99'), '0');
  assert.equal(store.total('acct', 'transfer'), '0');
  // 当日桶不存在（跨日回滚）→ null 不动账。
  assert.equal(store.subtract('ghost', 'transfer', '5'), null);
});

// ─── Sprint 5 T2.2 — requiresSimulation：只收紧、不放宽 ─────────────────
test('S5-T2.2 resolveSimulationRequirement: policy tightens, never relaxes', () => {
  const staticTable = policySnapshot().rules; // 默认空表
  // 空规则表 → 返回静态分级。
  const t = resolveSimulationRequirement('transfer', { rules: staticTable });
  assert.equal(t.requiresSimulation, true);   // transfer 静态 required
  assert.equal(t.level, 'required');

  // 静态 skippable 的 action（balance）被政策 requiresSimulation:true 收紧 → required。
  const rules = [
    { action: 'balance', enabled: true, requiresSimulation: true }, // 收紧 skippable
    { action: 'transfer', enabled: true, requiresSimulation: false }, // 试图放宽 required → 忽略
  ];
  const tightened = resolveSimulationRequirement('balance', { rules });
  assert.equal(tightened.requiresSimulation, true);
  assert.equal(tightened.level, 'required');
  assert.match(tightened.policyOverride, /tightened by policy/);

  // 试图把静态 required 放宽为 false → 仍 required（fail-closed，不放宽）；
  // override 为 'none'（policyForces 只认 ===true，false 不触发收紧也不改变裁决）。
  const notRelaxed = resolveSimulationRequirement('transfer', { rules });
  assert.equal(notRelaxed.requiresSimulation, true);
  assert.equal(notRelaxed.policyOverride, 'none');
  assert.match(notRelaxed.rationale, /value\/privilege-mutating/);

  // 静态 required 且 policy 明确 requiresSimulation:true → reinforce（双重收紧）。
  const reinforce = resolveSimulationRequirement('withdraw', {
    rules: [{ action: 'withdraw', enabled: true, requiresSimulation: true }],
  });
  assert.equal(reinforce.requiresSimulation, true);
  assert.match(reinforce.policyOverride, /reinforce/);
});

// ─── S5 fix#5 集成：policy 收紧 → 工具级真实被拦 ─────────────────────────
test('S5-T2.2 policy tightens a skippable action → execute blocked, query tool agrees', async () => {
  writeFileSync(POLICY_FILE, JSON.stringify({
    rules: [{ action: 'status', enabled: true, requiresSimulation: true }],
  }), 'utf8');
  process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
  try {
    await setupAccount();
    // 查询工具（fix#2）：答复与门禁同一合并语义 —— status 被收紧为 required。
    const q = await callTool('smart_account_simulation_policy', { action: 'status' });
    assert.equal(q.risk.requiresSimulation, true);
    assert.equal(q.risk.level, 'required');
    assert.equal(q.risk.staticLevel, 'skippable');
    assert.match(q.risk.policyOverride, /tightened by policy/);

    // 未经 preview 直接 execute（policy 收紧后 status 必须 preview）→ SimulationRequired。
    const signed = await signSmartAccountIntentLocal({ ...INTENT, action: 'status', nonce: '1' });
    const blocked = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
    assert.equal(blocked.success, false);
    assert.equal(blocked.error, 'SimulationRequired');
    assert.equal(blocked.simulation.staticLevel, 'skippable');
    assert.equal(blocked.simulation.level, 'required');
    assert.match(blocked.simulation.policyOverride, /tightened by policy/);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── S5 fix#1/#5 集成：maxDaily 预留制（门禁即占用，失败回滚） ────────────
test('S5-T2.1 maxDaily at tool level: reserve on gate, roll back on BadNonce replay, then reject over-limit', async () => {
  writeFileSync(POLICY_FILE, JSON.stringify({
    rules: [{ action: 'transfer', enabled: true, maxPerTx: '100', maxDaily: '80' }],
  }), 'utf8');
  process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
  try {
    await setupAccount();

    // 1) transfer 25 → 成功（门禁即预留 used=25）。
    const i1 = await signSmartAccountIntentLocal({ ...INTENT, amount: '25', nonce: '1' });
    const p1 = await callTool('smart_account_preview', { ...INTENT, amount: '25', nonce: 1, signature: i1.signature });
    assert.equal(p1.wouldExecute, true, JSON.stringify(p1));
    const e1 = await callTool('smart_account_execute', { payload: i1.payload, signature: i1.signature });
    assert.equal(e1.success, true, JSON.stringify(e1));

    // 2) 同一 payload 重放 → 链上 BadNonce 失败 → 预留回滚（used 仍 25）。
    const e2 = await callTool('smart_account_execute', { payload: i1.payload, signature: i1.signature });
    assert.equal(e2.success, false);

    // 3) 新 intent 55：25+55=80 ≤ 80 → 放行（若步骤 2 未回滚，50+55=105>80 会误拒）。
    const i3 = await signSmartAccountIntentLocal({ ...INTENT, amount: '55', nonce: '2' });
    const p3 = await callTool('smart_account_preview', { ...INTENT, amount: '55', nonce: 2, signature: i3.signature });
    assert.equal(p3.wouldExecute, true, JSON.stringify(p3));
    const e3 = await callTool('smart_account_execute', { payload: i3.payload, signature: i3.signature });
    assert.equal(e3.success, true, JSON.stringify(e3));

    // 4) 再 1：80+1 > 80 → PolicyRejected（off-chain，never touches chain）。
    const i4 = await signSmartAccountIntentLocal({ ...INTENT, amount: '1', nonce: '3' });
    await callTool('smart_account_preview', { ...INTENT, amount: '1', nonce: 3, signature: i4.signature });
    const e4 = await callTool('smart_account_execute', { payload: i4.payload, signature: i4.signature });
    assert.equal(e4.success, false);
    assert.equal(e4.error, 'PolicyRejected');
    assert.match(e4.reason, /would exceed policy maxDaily 80 \(used 80 \+ 1\)/);

    // 成功审计携带当日累计（预留制语义：25 → '25'，55 → '80'）。
    const audit = await callTool('smart_account_audit', {});
    const okRows = audit.entries.filter((e) => e.tool === 'smart_account_execute' && e.ok === true && e.dailyTotal);
    assert.equal(okRows.length, 2, JSON.stringify(okRows));
    assert.equal(okRows[0].dailyTotal, '25');
    assert.equal(okRows[1].dailyTotal, '80');
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── Sprint 5 T3 — Strict Fail Mode ────────────────────────────────────
test('S5-T3 policyFailMode defaults to permissive; strict only on env', () => {
  delete process.env.POLICY_FAIL_MODE;
  assert.equal(policyFailMode(), 'permissive');
  process.env.POLICY_FAIL_MODE = 'strict';
  assert.equal(policyFailMode(), 'strict');
  process.env.POLICY_FAIL_MODE = 'bogus';
  assert.equal(policyFailMode(), 'permissive');
  delete process.env.POLICY_FAIL_MODE;
});

test('S5-T3 permissive corrupted file still degrades to empty rules (on-chain backstop)', () => {
  try {
    writeFileSync(POLICY_FILE, '{not-json', 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
    delete process.env.POLICY_FAIL_MODE; // permissive
    resetPolicyEngineState();
    // permissive → 损坏文件只告警，软层放行（链上硬策略兜底），行为保持。
    assert.deepEqual(evaluatePolicy({ action: 'transfer', amount: '999' }), { allowed: true });
    // loadPolicy 刷新了错误状态（供 strict 判定），但 permissive 下不影响放行。
    assert.notEqual(lastPolicyLoadError(), null);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

test('S5-T3 strict + corrupted file → evaluatePolicy PolicyConfigError (fail-closed)', () => {
  try {
    writeFileSync(POLICY_FILE, 'not-valid-json{', 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
    process.env.POLICY_FAIL_MODE = 'strict';
    resetPolicyEngineState();
    const v = evaluatePolicy({ action: 'transfer', amount: '5' });
    assert.equal(v.allowed, false);
    assert.equal(v.code, 'PolicyConfigError');
    assert.match(v.reason, /strict fail-mode/);
    // snapshot 暴露 fail-mode + configError（policySnapshot 内部走 loadPolicy）。
    const snap = policySnapshot();
    assert.equal(snap.failMode, 'strict');
    assert.notEqual(snap.configError, null);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
    delete process.env.POLICY_FAIL_MODE;
    resetPolicyEngineState();
  }
});

test('S5-T3 strict + corrupted file → resolveSimulationRequirement treated as must-simulate', () => {
  try {
    writeFileSync(POLICY_FILE, 'not-json!', 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
    process.env.POLICY_FAIL_MODE = 'strict';
    resetPolicyEngineState();
    const r = resolveSimulationRequirement('balance'); // 静态 skippable
    assert.equal(r.requiresSimulation, true);
    assert.equal(r.level, 'required');
    assert.notEqual(r.configError, undefined);
    assert.match(r.rationale, /strict fail-mode/);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
    delete process.env.POLICY_FAIL_MODE;
    resetPolicyEngineState();
  }
});

test('S5-T3 fix#1/#3: configHealth passed → specific error carried, no stale/global state', () => {
  try {
    writeFileSync(POLICY_FILE, '{"rules": "garbage{', 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
    process.env.POLICY_FAIL_MODE = 'strict';
    resetPolicyEngineState();

    // 调用方传入单次读取的健康（ok:false + 具体 error）→ 直接采用，不再读文件、
    // 不退化为泛化文案（fix#1），也不依赖模块级 lastLoadError（fix#2 同源）。
    const v = evaluatePolicy(
      { action: 'transfer', amount: '5' },
      { configHealth: { ok: false, error: 'failed to load SMART_ACCOUNT_POLICY_FILE (x): Unexpected token g in JSON' } },
    );
    assert.equal(v.allowed, false);
    assert.equal(v.code, 'PolicyConfigError');
    assert.match(v.reason, /Unexpected token g in JSON/); // 具体 JSON 解析错误透传
    assert.match(v.reason, /strict fail-mode/);

    // 同样语义用于 resolveSimulationRequirement。
    const r = resolveSimulationRequirement('balance', { configHealth: { ok: false, error: 'boom-at-snapshot' } });
    assert.equal(r.requiresSimulation, true);
    assert.equal(r.configError, 'boom-at-snapshot');

    // 传入健康快照 ok:true（可信单次读取）→ strict 不拦截，按 rules 正常裁决。
    const okV = evaluatePolicy(
      { action: 'transfer', amount: '5' },
      { rules: [{ action: 'transfer', enabled: true, maxPerTx: '10' }], configHealth: { ok: true, error: null } },
    );
    assert.deepEqual(okV, { allowed: true });
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
    delete process.env.POLICY_FAIL_MODE;
    resetPolicyEngineState();
  }
});

test('S5-T3 tool-level: strict + corrupted file → execute rejected PolicyConfigError; snapshot query shows failMode/configError', async () => {
  writeFileSync(POLICY_FILE, 'garbage{', 'utf8');
  process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;
  process.env.POLICY_FAIL_MODE = 'strict';
  try {
    await setupAccount();
    // 查询：failMode/configError 对运维可见，且 action 未要求被错误放行。
    const q = await callTool('smart_account_policy', {});
    assert.equal(q.policy.failMode, 'strict');
    assert.notEqual(q.policy.configError, null);

    // execute：即使 action 无静态规则保护也被 strict 配置错误拒绝（fail-closed）；
    // reason 携带本次快照的具体解析错误（fix#1/#2：绑定 policyNow，非泛化文案）。
    const signed = await signSmartAccountIntentLocal({ ...INTENT, action: 'balance', nonce: '5' });
    const r = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
    assert.equal(r.success, false);
    assert.equal(r.error, 'PolicyConfigError');
    // 具体错误透传（绑定 policyNow.configError）：匹配稳定的加载前缀 + 任一 V8 解析错误指示。
    // Node 18 报 "Unexpected token g in JSON..."，新 V8 报 "Unexpected token 'g', \"garbage{\" is
    // not valid JSON"——文案随版本不同，故不锚定具体措辞，只证"具体的解析错误穿透而非泛化文案"。
    assert.match(r.reason, /failed to load SMART_ACCOUNT_POLICY_FILE.*(?:Unexpected token|not valid JSON|garbage)/);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
    delete process.env.POLICY_FAIL_MODE;
    resetPolicyEngineState();
  }
});

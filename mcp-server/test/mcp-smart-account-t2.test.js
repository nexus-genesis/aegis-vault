/**
 * Sprint 4 T2 — 持久化 / 审计补缺口 测试
 *
 * 覆盖：
 *   T2.1 simulationLog 持久化：preview 成功 arming → SMART_ACCOUNT_STATE_FILE 落盘
 *        simulations 记录（accountId/digest/at）；loadChainState 可读回（重启恢复契约）。
 *   T2.2 policy 版本快照审计：smart_account_policy 查询/execute 门禁首次评估记录
 *        policy_change（previousFingerprint null）；rules 变更 → 新 policy_change
 *        （previousFingerprint = 旧指纹，可追溯热更新）。
 *   T2.3 audit schema 校验：validateAuditEntry 对稳定字段类型严格校验
 *        （tool 必填 string；accountId/sessionId/payloadDigest/txHash/errorName 为
 *        string|null；其它类型 → violation，不静默）。
 */
import { test, before, beforeEach, after } from 'node:test';
// External review 2026-08-24: default LocalChain path requires explicit opt-in.
process.env.CHAIN_ALLOW_LOCAL = '1';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, __resetSmartAccountForTest } from '../src/server.js';
import { validateAuditEntry, AUDIT_SCHEMA } from '../src/audit-log.js';
import { loadChainState, saveChainState, getChainStateFile } from '../src/chain-state-store.js';

const STATE_FILE = join(tmpdir(), `t2-state-${process.pid}-${Date.now()}.json`);
const POLICY_FILE = join(tmpdir(), `t2-policy-${process.pid}-${Date.now()}.json`);
const TMP_STATE = join(tmpdir(), `t2-roundtrip-${process.pid}-${Date.now()}.json`);

process.env.SMART_ACCOUNT_STATE_FILE = STATE_FILE;

// local 配置面（anvil 密钥，与既有测试一致）。
const OWNER_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EMERGENCY_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 't2-agent';
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
  client = new Client({ name: 'test-t2', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

beforeEach(() => {
  __resetSmartAccountForTest();
});

after(async () => {
  await client.close();
  await server.close();
  __resetSmartAccountForTest();
  for (const f of [STATE_FILE, POLICY_FILE, TMP_STATE]) {
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

let _signer;
async function signSmartAccountIntentLocal(intent) {
  if (!_signer) {
    const { signSmartAccountIntent } = await import('aegis-chain-eth');
    _signer = signSmartAccountIntent;
  }
  return _signer({ session: SESSION_BINDING, intent, privateKeyHex: AGENT_PK });
}

// ─── T2.3 audit schema 校验（单元）───────────────────────────────────────
test('T2.3 validateAuditEntry: schema fields are strictly typed', () => {
  assert.deepEqual(Object.keys(AUDIT_SCHEMA).sort(), [
    'accountId', 'errorName', 'payloadDigest', 'sessionId', 'tool', 'txHash',
  ]);

  // 合法：tool string + 各标识字段 string 或 null。
  assert.equal(validateAuditEntry({
    tool: 'smart_account_execute', ok: false, accountId: 'a1', sessionId: null,
    payloadDigest: '0xdig', txHash: null, errorName: 'SimulationRequired',
  }).ok, true);

  // tool 缺失 / 非 string → 违规。
  assert.equal(validateAuditEntry({}).ok, false);
  assert.equal(validateAuditEntry({ tool: 42 }).ok, false);

  // 标识字段为 number / object / boolean → 违规（不静默）。
  assert.equal(validateAuditEntry({ tool: 't', accountId: 123 }).ok, false);
  assert.equal(validateAuditEntry({ tool: 't', sessionId: {} }).ok, false);
  assert.equal(validateAuditEntry({ tool: 't', txHash: true }).ok, false);
  // 标识字段 undefined（未提供）→ 允许（可空）。
  assert.equal(validateAuditEntry({ tool: 't' }).ok, true);

  // 违规时给出具体字段说明。
  const bad = validateAuditEntry({ tool: 't', errorName: 7 });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => e.startsWith('errorName')));
});

// ─── T2.1 simulations 持久化往返（单元，chain-state-store）──────────────
test('T2.1 saveChainState/loadChainState: simulations round-trip', () => {
  const savedFile = getChainStateFile();
  assert.equal(savedFile, STATE_FILE);
  saveChainState({
    chainUrl: 'http://local', profile: 'local', accounts: [],
    transactions: [],
    simulations: [{ accountId: 'a1', digest: '0xdig', at: 1234567890 }],
  });
  const state = loadChainState();
  assert.deepEqual(state.simulations, [{ accountId: 'a1', digest: '0xdig', at: 1234567890 }]);
});

// ─── T2.2 复核修复：预载规则优先（指纹=裁决同一份规则，TOCTOU 回归）─────
test('T2.2 evaluatePolicy uses preloaded rules, not a stale file re-read (review fix)', async () => {
  const { evaluatePolicy } = await import('../src/policy-engine.js');
  try {
    // 文件写 rules A（transfer 放行）。
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [{ action: 'transfer', enabled: true, maxPerTx: '100' }],
    }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    // 预载 rules B（transfer 拒绝）→ 裁决必须依据 B：若实现忽略预载参数
    // 重新读文件，会拿 A 放行 —— 指纹(基于 B)与裁决(A)失真。
    const preloaded = [{ action: 'transfer', enabled: false }];
    const verdict = evaluatePolicy({ action: 'transfer', amount: '1' }, { rules: preloaded });
    assert.equal(verdict.allowed, false, 'preloaded rules must take precedence over the file');
    assert.match(verdict.reason, /disabled by policy/);

    // 不传预载 → 照旧热读文件（向后兼容）。
    const fromFile = evaluatePolicy({ action: 'transfer', amount: '1' });
    assert.deepEqual(fromFile, { allowed: true });

    // 预载空表 → 放行（与空文件语义一致）。
    const emptyPreload = evaluatePolicy({ action: 'transfer', amount: '1' }, { rules: [] });
    assert.deepEqual(emptyPreload, { allowed: true });
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── T2.1 server 集成：preview arming 落盘 ───────────────────────────────
test('T2.1 signed preview arms the gate AND persists the simulation to state file', async () => {
  const out = await setupAccount();
  const { payload, signature } = await signSmartAccountIntentLocal(INTENT);

  const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
  assert.equal(prev.success, true, JSON.stringify(prev));
  assert.equal(prev.wouldExecute, true);

  // 状态文件已落盘 simulations（accountId/digest/at 绝对时间）。
  // Sprint 6 T3：落盘为行级 store 格式——断言走语义层 loadChainState()（格式无关）。
  assert.ok(existsSync(STATE_FILE), 'state file must exist after arming');
  const state = loadChainState();
  assert.ok(Array.isArray(state.simulations));
  const arm = state.simulations.find((s) => s.accountId === out.accountId);
  assert.ok(arm, `no simulation persisted for account ${out.accountId}`);
  assert.equal(arm.digest, prev.digest);
  assert.equal(typeof arm.at, 'number');

  // 同一 digest 仍可直接 execute（窗口内放行）。
  const exec = await callTool('smart_account_execute', { payload, signature });
  assert.equal(exec.success, true, JSON.stringify(exec));
});

// ─── T2.2 policy 版本快照审计（server 集成）──────────────────────────────
test('T2.2 smart_account_policy first query records initial policy_change; rules change re-records', async () => {
  try {
    // 首次查询（默认空规则）→ policy_change，previousFingerprint null（初始状态有据可查）。
    writeFileSync(POLICY_FILE, JSON.stringify({ rules: [] }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    const pol1 = await callTool('smart_account_policy', {});
    assert.equal(pol1.success, true);
    assert.ok(pol1.fingerprint, 'tool should expose current policy fingerprint');

    let audit = await callTool('smart_account_audit', {});
    let changes = audit.entries.filter((e) => e.tool === 'policy_change');
    assert.equal(changes.length, 1, 'first query must record the initial policy_change');
    assert.equal(changes[0].previousFingerprint, null);
    assert.equal(changes[0].fingerprint, pol1.fingerprint);

    // 热更新规则（同文件重写）→ 再查询 → 新 policy_change（previousFingerprint = 旧指纹）。
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [{ action: 'transfer', enabled: true, maxPerTx: '10' }],
    }), 'utf8');

    const pol2 = await callTool('smart_account_policy', {});
    assert.notEqual(pol2.fingerprint, pol1.fingerprint);

    audit = await callTool('smart_account_audit', {});
    changes = audit.entries.filter((e) => e.tool === 'policy_change');
    assert.equal(changes.length, 2, 'rules change must be traceable as a new policy_change');
    const second = changes[1];
    assert.equal(second.previousFingerprint, pol1.fingerprint);
    assert.equal(second.fingerprint, pol2.fingerprint);
    assert.ok(Array.isArray(second.rules) && second.rules.length === 1);
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

test('T2.2 execute gate also records policy_change (policy evolution visible on the hot path)', async () => {
  try {
    writeFileSync(POLICY_FILE, JSON.stringify({
      rules: [{ action: 'transfer', enabled: true, maxPerTx: '100' }],
    }), 'utf8');
    process.env.SMART_ACCOUNT_POLICY_FILE = POLICY_FILE;

    await setupAccount();
    const { payload, signature } = await signSmartAccountIntentLocal(INTENT);
    const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
    assert.equal(prev.wouldExecute, true);

    // execute 触发一次 evaluatePolicy → 首次评估也记 policy_change。
    const exec = await callTool('smart_account_execute', { payload, signature });
    assert.equal(exec.success, true, JSON.stringify(exec));

    const audit = await callTool('smart_account_audit', {});
    const changes = audit.entries.filter((e) => e.tool === 'policy_change');
    assert.ok(changes.length >= 1);
    // 该事件在 execute 路径上产生（context 标注）。
    const gateChange = changes.find((c) => c.context === 'smart_account_execute gate');
    assert.ok(gateChange, 'execute gate must be a source of policy_change audit');
  } finally {
    delete process.env.SMART_ACCOUNT_POLICY_FILE;
  }
});

// ─── T2.3 recordAudit 保持稳定字段类型（通过 audit 工具端到端）────────────
test('T2.3 audit entries keep stable string fields for identifiers (end-to-end)', async () => {
  await setupAccount();
  const { payload, signature } = await signSmartAccountIntentLocal(INTENT);
  const prev = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature });
  assert.equal(prev.wouldExecute, true);

  const audit = await callTool('smart_account_audit', {});
  assert.ok(audit.entries.length >= 1);
  for (const e of audit.entries) {
    assert.equal(typeof e.tool, 'string');
    for (const k of ['accountId', 'sessionId', 'payloadDigest', 'txHash', 'errorName']) {
      if (e[k] !== undefined && e[k] !== null) assert.equal(typeof e[k], 'string', `${k} must be string, got ${typeof e[k]}`);
    }
  }
});

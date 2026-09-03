/**
 * smart-account-distributed.test.js — Sprint 6 T3：行级分片 + 跨实例可见
 *
 * 验收（Sprint6计划 T3，设计定稿对应断言）：
 *   - arm 跨实例：persistSimArm（实例 A）→ 重开 backend（实例 B/重启）→
 *     loadChainState().simulations 命中同 digest；同 accountId LWW 覆盖（最新意图胜）。
 *   - 行级分片：两 accountId 各 persistAccountRow → 两行都保留（last-write-wins 修复）。
 *   - RMW union：同 accountId 两实例各开不同 session → union 两条都在。
 *   - 不变量冲突：同 accountId 不同 owner → STATE_CONFIG_CONFLICT（fail-closed，不静默取一方）。
 *   - 台账跨实例：recordTx（实例 A）→ 重开 backend → listTx 可见；生命周期同 txHash 追加。
 *   - 旧 JSON 全量状态文件 → 自动迁移 + .bak 保留。
 *   - 纯内存基线：无 env 时 recordTx/listTx/persist* 行为与 Sprint 2.6 基线一致。
 *   - 显式 sqlite 失败 fail-closed：非法路径 .sqlite → getStateBackend 抛错。
 */
import { test, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadChainState,
  saveChainState,
  persistAccountRow,
  persistSimArm,
  recordTx,
  listTx,
  initTxLedger,
  getStateBackend,
  serializeEntry,
  __resetTxLedgerForTest,
} from '../src/chain-state-store.js';
import { createSqliteStore, sqliteAvailable } from 'aegis-agent-sdk';
import { createNonceSequencer } from '../src/relayer-coordinator.js';

let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 't3-dist-')); });
after(() => {
  __resetTxLedgerForTest(); // 关闭 backend 句柄（Windows 文件锁）再清理
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
});

const SAVED_ENV = {};
beforeEach(() => {
  SAVED_ENV.file = process.env.SMART_ACCOUNT_STATE_FILE;
  SAVED_ENV.backend = process.env.NEXUS_STORE_BACKEND;
});
afterEach(() => {
  __resetTxLedgerForTest();
  if (SAVED_ENV.file === undefined) delete process.env.SMART_ACCOUNT_STATE_FILE;
  else process.env.SMART_ACCOUNT_STATE_FILE = SAVED_ENV.file;
  if (SAVED_ENV.backend === undefined) delete process.env.NEXUS_STORE_BACKEND;
  else process.env.NEXUS_STORE_BACKEND = SAVED_ENV.backend;
});

/** 内存 entry 构造（server.js smartAccounts Map 的值的最小形状）。 */
function makeEntry(accountId, overrides = {}) {
  return {
    accountId,
    contractAddress: `0xcontract-${accountId}`,
    owner: `0xowner-${accountId}`,
    emergencyKey: `0xemergency-${accountId}`,
    chainUrl: 'http://chain-a',
    profile: 'testnet',
    currentSessionId: null,
    txHashes: [],
    sessions: new Map(),
    ...overrides,
  };
}

function sessionIn(map, sessionId) {
  map.set(sessionId, { sessionId, agentId: `agent-${sessionId}`, agentEvmAddress: '0xagent', issuedAt: 1, expiresAt: 2, maxPerTx: '100', maxDaily: '1000', whitelist: { allowedChains: [], allowedAssets: [], allowedContracts: [], allowedMethods: [], allowedRecipients: [] } });
  return map;
}

const sqlitePath = (name) => join(dir, name);

test('T3.1 arm 跨实例可见 + LWW 覆盖（重启/实例 B 命中同 digest）', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('arm.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  persistSimArm('acc1', { digest: '0xdig-A', at: 1000 });
  __resetTxLedgerForTest(); // 模拟实例 B / 重启：新 backend 句柄读同一文件

  let state = loadChainState();
  assert.deepEqual(state.simulations, [{ accountId: 'acc1', digest: '0xdig-A', at: 1000 }], '实例 B 命中实例 A 的 arm');

  // LWW：同 accountId 新 preview 意图覆盖旧值（execute 须带匹配 digest，安全性
  // 与写入顺序无关——覆盖即正确）。
  persistSimArm('acc1', { digest: '0xdig-B', at: 2000 });
  __resetTxLedgerForTest();
  state = loadChainState();
  assert.deepEqual(state.simulations, [{ accountId: 'acc1', digest: '0xdig-B', at: 2000 }], 'LWW 最新意图胜出');
});

test('T3.2 行级分片：两 accountId 并发写互不覆盖（last-write-wins 修复）', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('shard.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  persistAccountRow(makeEntry('acc1', { sessions: sessionIn(new Map(), 's1') }));
  persistAccountRow(makeEntry('acc2', { sessions: sessionIn(new Map(), 's2') }));
  __resetTxLedgerForTest();

  const state = loadChainState();
  assert.equal(state.accounts.length, 2, '两行都保留（全量覆盖下后写会丢前写）');
  const ids = state.accounts.map((a) => a.accountId).sort();
  assert.deepEqual(ids, ['acc1', 'acc2']);
});

test('T3.2 同 accountId 两实例各开不同 session → RMW union 两条都在', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('union.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  persistAccountRow(makeEntry('acc1', { sessions: sessionIn(sessionIn(new Map(), 's-old'), 's-a'), currentSessionId: 's-a' }));
  // 实例 B：只见过自己开的 s-b（其内存 Map 不含 s-a）。
  persistAccountRow(makeEntry('acc1', { sessions: sessionIn(new Map(), 's-b'), currentSessionId: 's-b' }));
  __resetTxLedgerForTest();

  const state = loadChainState();
  assert.equal(state.accounts.length, 1);
  const sessionIds = state.accounts[0].sessions.map((s) => s.sessionId).sort();
  assert.deepEqual(sessionIds, ['s-a', 's-b', 's-old'], 'sessionId union 无丢失');
  assert.equal(state.accounts[0].currentSessionId, 's-b', 'currentSessionId 非空覆盖（单机 set 语义）');
});

test('T3.2 不变量冲突：同 accountId 不同 owner → STATE_CONFIG_CONFLICT（fail-closed）', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('conflict.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  persistAccountRow(makeEntry('acc1'));
  assert.throws(
    () => persistAccountRow(makeEntry('acc1', { owner: '0xdifferent-owner' })),
    (e) => e.code === 'STATE_CONFIG_CONFLICT' && /owner/.test(e.message),
    '配置漂移显式失败，绝不静默取一方',
  );
  // 冲突后既有行未被污染。
  __resetTxLedgerForTest();
  const state = loadChainState();
  assert.equal(state.accounts[0].owner, '0xowner-acc1');
});

test('T3.3 台账跨实例：recordTx 写穿 → 实例 B listTx 可见；同 txHash 生命周期追加', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('ledger.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  recordTx({ txHash: '0xtx1', accountId: 'acc1', sessionId: 's1', status: 'confirmed', submittedAt: '2026-08-23T00:00:01.000Z', confirmedAt: '2026-08-23T00:00:02.000Z' });
  recordTx({ txHash: '0xtx2', accountId: 'acc2', sessionId: 's2', status: 'failed', errorName: 'BadNonce', submittedAt: '2026-08-23T00:00:03.000Z' });
  __resetTxLedgerForTest(); // 实例 B：进程内台账为空，只能靠 store 查到

  const all = listTx({});
  assert.equal(all.length, 2, '实例 B 看到实例 A 广播的全部事实');
  const one = listTx({ txHash: '0xtx2' });
  assert.equal(one.length, 1);
  assert.equal(one[0].errorName, 'BadNonce');
  const byAcc = listTx({ accountId: 'acc1' });
  assert.equal(byAcc.length, 1);

  // 生命周期演进：同 txHash 不同 status（submitted → confirmed）都保留；
  // 同 (txHash, status) 重复记录幂等去重（取最新 submittedAt）。
  recordTx({ txHash: '0xtx1', accountId: 'acc1', sessionId: 's1', status: 'submitted', submittedAt: '2026-08-23T00:00:01.000Z' });
  recordTx({ txHash: '0xtx1', accountId: 'acc1', sessionId: 's1', status: 'confirmed', blockNumber: '42', submittedAt: '2026-08-23T00:00:01.000Z', confirmedAt: '2026-08-23T00:00:05.000Z' });
  recordTx({ txHash: '0xtx1', accountId: 'acc1', sessionId: 's1', status: 'confirmed', blockNumber: '42', submittedAt: '2026-08-23T00:00:09.000Z', confirmedAt: '2026-08-23T00:00:10.000Z' });
  const lifecycle = listTx({ txHash: '0xtx1' });
  assert.equal(lifecycle.length, 2, '生命周期事实集：submitted + confirmed（重复 confirmed 幂等去重）');
  assert.equal(lifecycle[1].status, 'confirmed');
  assert.equal(lifecycle[1].submittedAt, '2026-08-23T00:00:09.000Z', '同 status 取最新');
});

test('T3 兼容：saveChainState（全量 API）按行合并，round-trip 形状不变', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('compat.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  saveChainState({
    chainUrl: 'http://local', profile: 'local', accounts: [],
    transactions: [],
    simulations: [{ accountId: 'a1', digest: '0xdig', at: 1234567890 }],
  });
  const state = loadChainState();
  assert.deepEqual(state.simulations, [{ accountId: 'a1', digest: '0xdig', at: 1234567890 }]);
  assert.equal(state.chainUrl, 'http://local');
  assert.equal(state.profile, 'local');
  // 再 save 不同账户 → 行合并不丢第一批（虽然本批 accounts 为空，sim 行保留）。
  saveChainState({ chainUrl: 'http://local', profile: 'local', accounts: [], transactions: [], simulations: [] });
  const state2 = loadChainState();
  assert.deepEqual(state2.simulations, [{ accountId: 'a1', digest: '0xdig', at: 1234567890 }], '空 save 不清既有行');
});

test('T3 迁移：旧全量 JSON → 自动迁入行级 store + .bak 保留', () => {
  const file = sqlitePath('legacy.json');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  writeFileSync(file, JSON.stringify({
    chainUrl: 'http://legacy', profile: 'local',
    accounts: [{ accountId: 'acc-old', contractAddress: '0xc1', owner: '0xo1', emergencyKey: '0xe1', chainUrl: 'http://legacy', profile: 'local', currentSessionId: null, txHashes: [], sessions: [] }],
    transactions: [{ txHash: '0xlegacy-tx', accountId: 'acc-old', sessionId: null, status: 'confirmed', submittedAt: '2026-01-01T00:00:00.000Z' }],
    simulations: [{ accountId: 'acc-old', digest: '0xleg-dig', at: 111 }],
  }), 'utf8');

  const state = loadChainState(); // 触发 getStateBackend → 检测旧格式 → 迁移
  assert.equal(state.accounts.length, 1);
  assert.equal(state.accounts[0].accountId, 'acc-old');
  assert.equal(state.transactions.length, 1);
  assert.deepEqual(state.simulations, [{ accountId: 'acc-old', digest: '0xleg-dig', at: 111 }]);
  assert.equal(state.chainUrl, 'http://legacy');
  assert.ok(existsSync(`${file}.bak`), '原文件留 .bak');
  // .bak 内容 = 迁移前原文。
  assert.equal(JSON.parse(readFileSync(`${file}.bak`, 'utf8')).chainUrl, 'http://legacy');
  // 再次加载走新 store 格式（幂等）。
  __resetTxLedgerForTest();
  const again = loadChainState();
  assert.equal(again.accounts.length, 1);
});

test('T3 纯内存基线：无 env 时行为与 Sprint 2.6 一致', () => {
  delete process.env.SMART_ACCOUNT_STATE_FILE;
  __resetTxLedgerForTest();
  recordTx({ txHash: '0xmem', accountId: 'a', sessionId: null, status: 'confirmed', submittedAt: '2026-08-23T00:00:00.000Z' });
  assert.equal(listTx({ txHash: '0xmem' }).length, 1, '进程内台账可查');
  assert.deepEqual(loadChainState(), { chainUrl: null, profile: null, accounts: [], transactions: [], simulations: [] }, 'load 返回空态');
  persistAccountRow(makeEntry('acc-mem')); // no-op，不抛错
  persistSimArm('acc-mem', { digest: '0xd', at: 1 }); // no-op
  assert.equal(getStateBackend().type, 'local');
});

test('T3 fail-closed：显式 sqlite 非法路径 → getStateBackend 抛错（启动失败）', { skip: !sqliteAvailable }, () => {
  const notADir = join(dir, 'notadir.txt');
  writeFileSync(notADir, 'x', 'utf8');
  process.env.SMART_ACCOUNT_STATE_FILE = join(notADir, 'sub', 'state.sqlite');
  assert.throws(() => getStateBackend(), /fail-closed/, 'sqlite 构造失败显式传播，不静默降级');
});

test('T3 sqlite 双句柄直证：实例 A 行写 → 实例 B 原始句柄立即可见（无 reset）', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('dual.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  persistAccountRow(makeEntry('acc1', { sessions: sessionIn(new Map(), 's1') }));
  // 第二个"实例"直接开句柄读同一 sqlite（不经模块 memo——真正同时在线的两实例）。
  const peer = createSqliteStore({ file });
  try {
    const row = peer.read('state:account:acc1');
    assert.equal(row.accountId, 'acc1');
    assert.equal(row.sessions.length, 1);
    // peer 写 sim arm → 本实例（模块句柄）立即可见（LWW 覆盖）。
    peer.write('sim:arm:acc1', { digest: '0xpeer', at: 42 });
    assert.deepEqual(loadChainState().simulations, [{ accountId: 'acc1', digest: '0xpeer', at: 42 }]);
  } finally {
    peer.close();
  }
});

test('T3 serializeEntry：Map sessions → 数组（接线契约不变）', () => {
  const entry = makeEntry('acc-x', { sessions: sessionIn(new Map(), 'sx') });
  const s = serializeEntry(entry);
  assert.equal(s.sessions.length, 1);
  assert.equal(s.sessions[0].sessionId, 'sx');
  assert.equal(s.sessions[0].maxPerTx, '100');
});

// ─── T4.2 生产接线真值：recordTx 写 digest → 跨实例对账去重命中 ────────────

test('T4.2 recordTx 写穿 digest → isAlreadyLanded 命中（F1 回归：server.js recordTx 必须带 digest）', { skip: !sqliteAvailable }, () => {
  const file = sqlitePath('dedupe-digest.sqlite');
  process.env.SMART_ACCOUNT_STATE_FILE = file;
  // 形状与 server.js 成功路径 recordTx 完全一致（digest: payloadDigest ?? null）。
  recordTx({
    txHash: '0xdup1', accountId: 'acc1', sessionId: 's1', status: 'confirmed',
    digest: '0xD-PROD-1',
    blockNumber: '42', gasUsed: '21000', errorName: null,
    submittedAt: '2026-08-23T00:00:01.000Z', confirmedAt: '2026-08-23T00:00:02.000Z',
  });
  // 另一"实例"（独立句柄）对同一共享台账做去重查询 —— 这正是
  // executeWithRelayerResilience 广播前的 isAlreadyLanded 路径。
  const peer = createSqliteStore({ file });
  try {
    const peerRows = Object.values(peer.list('ledger:tx:'))
      .flatMap((r) => r.records || []);
    const hit = peerRows.find((r) => r.digest === '0xD-PROD-1' && r.accountId === 'acc1');
    assert.ok(hit, '共享台账行必须携带 digest（否则跨实例去重永不命中）');
    assert.equal(hit.txHash, '0xdup1');
    assert.equal(hit.status, 'confirmed');
    // 模块侧 listTx（生产 reconciler 的数据源）同样可见。
    const viaListTx = listTx({ accountId: 'acc1' }).find((r) => r.digest === '0xD-PROD-1');
    assert.ok(viaListTx, 'listTx 路径也必须能按 digest 命中');
  } finally {
    peer.close();
  }
});

// ─── T4.1/T4.3 双实例 nonce 协调（计划验收：双实例并发各 10 笔 → 无冲突） ────

test('T4 两实例共享 sqlite 并发各 10 笔 → 20 个 nonce 全局唯一（relayer EOA 无同 nonce 竞争）', { skip: !sqliteAvailable }, async () => {
  const file = sqlitePath('nonce-two-instances.sqlite');
  // 同进程两个独立 store 实例共享同一 sqlite 文件（计划 T5.1 允许的方式，
  // 等价于两个 mcp 实例各持一个句柄）。
  const storeA = createSqliteStore({ file });
  const storeB = createSqliteStore({ file });
  const seqA = createNonceSequencer(storeA);
  const seqB = createNonceSequencer(storeB);
  const CHAIN = 'http://chain-dist';
  const RELAYER = '0xrelayer-shared';
  try {
    const jobs = [];
    for (let i = 0; i < 10; i += 1) {
      jobs.push(seqA.acquireNonce(CHAIN, RELAYER, { instanceId: 'A' }));
      jobs.push(seqB.acquireNonce(CHAIN, RELAYER, { instanceId: 'B' }));
    }
    const nonces = await Promise.all(jobs);
    assert.equal(nonces.length, 20);
    assert.equal(new Set(nonces).size, 20, '20 个 nonce 必须全局唯一（零冲突）');
    // 且为 0..19 的连续序列（无跳号、无重号）。
    const sorted = [...nonces].sort((a, b) => a - b);
    assert.deepEqual(sorted, Array.from({ length: 20 }, (_, i) => i));
    // 租约审计跨实例可见：peer 视角能读到两实例的租约行（instanceId 归因）。
    const leases = storeB.list('nonce:lease:');
    const leaseEntries = Object.entries(leases)
      .filter(([k, v]) => k.includes('chain-dist') && k.includes('relayer-shared'));
    assert.equal(leaseEntries.length, 20, '每个 nonce 一条租约行，跨实例可见');
    const byInstance = { A: 0, B: 0 };
    for (const [, v] of leaseEntries) byInstance[v.instanceId] += 1;
    assert.equal(byInstance.A + byInstance.B, 20, '租约 instanceId 可归因到具体实例（F6）');
  } finally {
    storeA.close();
    storeB.close();
  }
});

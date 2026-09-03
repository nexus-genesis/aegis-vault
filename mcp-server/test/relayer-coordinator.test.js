/**
 * relayer-coordinator.test.js — Sprint 6 T4：多实例 relayer EOA nonce 协调
 *
 * 覆盖（Sprint6计划.md T4 对应）：
 *   T4.1 createNonceSequencer：共享 store 上 (chainUrl, broadcaster) 原子递增 nonce；
 *       双实例并发分配各自唯一（并发 50 次无重复）。降级：无 store → local 单机。
 *   T4.3 租约：acquire 后写 nonce:lease 记录（审计/归属实例），不阻断。
 *   T4.2 createBroadcastReconciler：按 (accountId, digest) 查已落账 → 去重短路；
 *       数字大全量查询 findLandedByDigest。
 *   executeWithRelayerResilience 集成：
 *     - 带 coordinator + 共享 store：每次广播拿到 sequencer 分配的 nonce 并透传
 *       （conn.executeFromAgent 收到非ce）；EOA nonce 冲突重试时重协调 new nonce。
 *     - dedupe 命中：不调用广播，直接返回 deduplicated 结果。
 *     - 不带 coordinator：纯 legacy 基线（ethers 自读 nonce，不传 override）。
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSqliteStore, sqliteAvailable } from 'aegis-agent-sdk';
import { createNonceSequencer, createBroadcastReconciler, isNonceConflict } from '../src/relayer-coordinator.js';
import { executeWithRelayerResilience } from '../src/relayer-operations.js';

let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 't4-nc-')); });
after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* win */ } });

const CHAIN = 'http://chain-a';
const RELAYER = '0xrelayerA';

// ─── T4.1 nonce sequencer ────────────────────────────────────────────────

test('T4.1 atomic nonce allocation yields globally-unique nonces from a shared sqlite store', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'seq.sqlite');
  const storeA = createSqliteStore({ file }); // 实例 A
  const storeB = createSqliteStore({ file }); // 实例 B（同文件 → 同族共享）
  const seqA = createNonceSequencer(storeA);
  const seqB = createNonceSequencer(storeB);

  try {
    // 两者从同一个起始，并发交替分配 → 绝无重复（跨实例唯一）。
    const got = [];
    const tasks = [];
    for (let i = 0; i < 50; i++) {
      tasks.push(seqA.acquireNonce(CHAIN, RELAYER, { instanceId: `A${i}` }));
      tasks.push(seqB.acquireNonce(CHAIN, RELAYER, { instanceId: `B${i}` }));
    }
    const res = await Promise.all(tasks);
    got.push(...res);
    assert.equal(new Set(got).size, 100, '两个实例并发分配必须 100 个全唯一 nonce');
    assert.ok(Math.max(...got) <= 99, '从 0 起单调递增 100 次 → max ≤ 99（无空洞跳变）');
  } finally {
    storeA.close();
    storeB.close();
  }
});

test('T4.1 different broadcasters have independent nonce sequences', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'seq2.sqlite');
  const store = createSqliteStore({ file });
  const seq = createNonceSequencer(store);
  try {
    const a1 = await seq.acquireNonce(CHAIN, '0xA');
    const b1 = await seq.acquireNonce(CHAIN, '0xB');
    const a2 = await seq.acquireNonce(CHAIN, '0xA');
    assert.equal(a1, 0);
    assert.equal(b1, 0, '不同 broadcaster 各自从 0 开始');
    assert.equal(a2, 1, '同 broadcaster 递增');
  } finally {
    store.close();
  }
});

test('T4.1/4.3 lease record written for audit (who owns which nonce)', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'lease.sqlite');
  const store = createSqliteStore({ file });
  const seq = createNonceSequencer(store);
  try {
    const nonce = await seq.acquireNonce(CHAIN, RELAYER, { instanceId: 'inst-1' });
    const lease = store.read(`nonce:lease:${CHAIN}:${RELAYER.toLowerCase()}:${nonce}`);
    assert.ok(lease, '租约记录已写');
    assert.equal(lease.instanceId, 'inst-1');
    assert.ok(Number.isFinite(lease.at));
  } finally {
    store.close();
  }
});

test('T4.1 sequencer degrades to single-process local when store omitted', async () => {
  const seq = createNonceSequencer(); // 无 store → local
  const n1 = await seq.acquireNonce(CHAIN, RELAYER);
  const n2 = await seq.acquireNonce(CHAIN, RELAYER);
  assert.equal(n1, 0);
  assert.equal(n2, 1);
});

// ─── F2 复核修复：链上 nonce 重同步兜底 ──────────────────────────────────

test('F2 syncAtLeast raises the floor to the chain pending count (never lowers)', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'sync.sqlite');
  const store = createSqliteStore({ file });
  const seq = createNonceSequencer(store);
  try {
    const n0 = await seq.acquireNonce(CHAIN, RELAYER);
    assert.equal(n0, 0);
    await seq.syncAtLeast(CHAIN, RELAYER, 5); // EOA 链上已有 5 笔历史
    const n1 = await seq.acquireNonce(CHAIN, RELAYER);
    assert.equal(n1, 5, '重同步后下一次分配 = 链上 pending 计数');
    await seq.syncAtLeast(CHAIN, RELAYER, 2); // 落后值 → 不回退
    const n2 = await seq.acquireNonce(CHAIN, RELAYER);
    assert.equal(n2, 6, '计数器只升不降');
  } finally {
    store.close();
  }
});

test('F2 integration: NONCE_CONFLICT retry resyncs the sequencer from chain pending count', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'resync.sqlite');
  const store = createSqliteStore({ file });
  const sequencer = createNonceSequencer(store);
  const nonceCalls = [];
  // EOA 链上 pending = 5（曾有单机运行历史），sequencer 冷启动从 0 分配 → 必冲突。
  const provider = { getTransactionCount: async () => 5 };
  const conn = fakeConn([
    { ok: false, errorName: null, reason: 'nonce too low' },
    { ok: true, txHash: '0xresynced', receipt: { status: 1, logs: [] } },
  ], { nonceCalls });
  try {
    const res = await executeWithRelayerResilience({
      conn, payload: { action: 'transfer' }, signature: '0x', relayer: {}, provider,
      opts: { maxRetries: 2, backoffMs: 1 },
      coordinator: { sequencer }, chainUrl: CHAIN, broadcaster: RELAYER, instanceId: 'RS',
    });
    assert.equal(res.ok, true);
    assert.equal(conn.calls.length, 2);
    assert.equal(nonceCalls[0], 0, '首次冷启动分配 0');
    assert.equal(nonceCalls[1], 5, '冲突后按链上 pending 重同步 → 分配 5');
  } finally {
    store.close();
  }
});

// ─── F5 复核修复：CAS 重试有上限 ─────────────────────────────────────────

test('F5 acquireNonce gives up after bounded CAS retries (no infinite spin)', async () => {
  const badStore = {
    writeAtomically: async () => { throw new Error('CAS conflict: exhausted retries'); },
    claim: async () => {},
  };
  const seq = createNonceSequencer(badStore);
  await assert.rejects(
    () => seq.acquireNonce(CHAIN, RELAYER),
    /exhausted CAS retries/,
    '持久 CAS 竞争必须在有限次数内 fail-closed 抛错（上游降级 legacy nonce）',
  );
});

// ─── T4.2 broadcast reconciler ───────────────────────────────────────────

test('T4.2 isAlreadyLanded returns a landed record by (accountId, digest)', () => {
  const ledger = [
    { txHash: '0xT1', accountId: 'acc1', digest: '0xD1', status: 'confirmed', sessionId: 's1' },
    { txHash: '0xT2', accountId: 'acc1', digest: '0xD2', status: 'confirmed', sessionId: 's1' },
  ];
  const rec = createBroadcastReconciler({ listTx: (o) => (o.accountId ? ledger.filter((r) => r.accountId === o.accountId) : ledger) });
  const hit = rec.isAlreadyLanded('acc1', '0xD1');
  assert.ok(hit);
  assert.equal(hit.txHash, '0xT1');
  assert.equal(rec.isAlreadyLanded('acc1', '0xNOPE'), null, '未落账 digest 不命中');
  assert.equal(rec.isAlreadyLanded('acc2', '0xD1'), null, '不同 accountId 不命中');
});

test('T4.2 findLandedByDigest returns all landed by digest across accounts', () => {
  const ledger = [
    { txHash: '0xT1', accountId: 'acc1', digest: '0xD1', status: 'confirmed' },
    { txHash: '0xT2', accountId: 'acc2', digest: '0xD1', status: 'failed' },
  ];
  const rec = createBroadcastReconciler({ listTx: () => ledger });
  const hits = rec.findLandedByDigest('0xD1');
  assert.equal(hits.length, 2);
});

test('T4.2 reconciler returns null when listTx missing or args absent', () => {
  const rec = createBroadcastReconciler({});
  assert.equal(rec.isAlreadyLanded('a', 'b'), null);
  assert.deepEqual(rec.findLandedByDigest('d'), []);
  assert.equal(rec.isAlreadyLanded(null, 'd'), null);
});

test('F4 RELAYER_DEDUPE_SCAN=0 disables the scan (not full scan)', () => {
  const ledger = [{ txHash: '0xT1', accountId: 'acc1', digest: '0xD1', status: 'confirmed' }];
  let scanned = 0;
  const rec = createBroadcastReconciler({ listTx: (o) => { scanned += 1; return ledger; } });
  const saved = process.env.RELAYER_DEDUPE_SCAN;
  process.env.RELAYER_DEDUPE_SCAN = '0';
  try {
    // listTx 的 slice(-limit) 在 limit=0 时 slice(-0)===slice(0) 会全量返回 ——
    // 0 的语义必须是「禁用」（不扫描），由 reconciler 显式短路保证。
    assert.equal(rec.isAlreadyLanded('acc1', '0xD1'), null, '禁用时即使有匹配行也返回 null');
    assert.deepEqual(rec.findLandedByDigest('0xD1'), []);
    assert.equal(scanned, 0, '根本不应触发 listTx 调用');
  } finally {
    if (saved === undefined) delete process.env.RELAYER_DEDUPE_SCAN;
    else process.env.RELAYER_DEDUPE_SCAN = saved;
  }
});

// ─── isNonceConflict ─────────────────────────────────────────────────────

test('isNonceConflict distinguishes EOA nonce conflict from contract BadNonce', () => {
  assert.equal(isNonceConflict({ ok: false, errorName: null, reason: 'nonce too low' }), true);
  assert.equal(isNonceConflict({ ok: false, errorName: null, reason: 'the tx doesn\'t have the correct nonce' }), true);
  assert.equal(isNonceConflict({ ok: false, errorName: 'BadNonce', reason: 'intent replay' }), false, '合约意图 nonce ≠ EOA nonce');
  assert.equal(isNonceConflict({ ok: false, errorName: null, reason: 'ECONNREFUSED' }), false);
});

// ─── executeWithRelayerResilience × coordinator 集成 ─────────────────────

function fakeConn(results, { nonceCalls = [] } = {}) {
  const calls = [];
  const conn = {
    contract: { interface: { parseLog: () => null }, runner: { provider: { getTransactionReceipt: async () => null } } },
    executeFromAgent: async (o) => {
      calls.push(o);
      nonceCalls.push(o.nonce); // 记录传入的 nonce override
      return results.shift();
    },
  };
  conn.calls = calls;
  return conn;
}

test('integration: with coordinator, broadcasts carry a sequencer-allocated unique nonce', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'int1.sqlite');
  const store = createSqliteStore({ file });
  const sequencer = createNonceSequencer(store);
  const nonceCalls = [];
  const conn = fakeConn([
    { ok: true, txHash: '0xok', receipt: { status: 1, logs: [] } },
  ], { nonceCalls });
  try {
    const res = await executeWithRelayerResilience({
      conn, payload: { accountId: 'a1', digest: '0xD' }, signature: '0x', relayer: {}, opts: { maxRetries: 2, backoffMs: 1 },
      coordinator: { sequencer }, chainUrl: CHAIN, broadcaster: RELAYER, instanceId: 'I1',
    });
    assert.equal(res.ok, true);
    assert.ok(Number.isInteger(res.coordinatedNonce));
    assert.equal(nonceCalls.length, 1);
    assert.equal(nonceCalls[0], res.coordinatedNonce, 'broadcast 收到 sequencer 分配的非ce');
    assert.equal(conn.calls[0].nonce, res.coordinatedNonce);
  } finally {
    store.close();
  }
});

test('integration: dedupe short-circuits when another instance already landed (no broadcast)', async () => {
  const ledger = [{ txHash: '0xALREADY', accountId: 'a1', digest: '0xD1', status: 'confirmed', sessionId: 's1' }];
  const reconciler = createBroadcastReconciler({ listTx: () => ledger });
  const conn = fakeConn([{ ok: true, txHash: '0xshould-not', receipt: { status: 1, logs: [] } }]);
  const res = await executeWithRelayerResilience({
    conn, payload: { accountId: 'a1', digest: '0xD1', sessionId: 's1' }, signature: '0x', relayer: {}, opts: {},
    coordinator: { reconciler },
  });
  assert.equal(res.deduplicated, true);
  assert.equal(res.txHash, '0xALREADY', '复用已落账结果');
  assert.equal(res.attempts, 0, '未发起广播');
  assert.equal(conn.calls.length, 0, '必须零广播调用');
});

test('integration: dedupe mismatch (different digest) proceeds to broadcast', async () => {
  const ledger = [{ txHash: '0xALREADY', accountId: 'a1', digest: '0xD1', status: 'confirmed' }];
  const reconciler = createBroadcastReconciler({ listTx: () => ledger });
  const conn = fakeConn([{ ok: true, txHash: '0xOK', receipt: { status: 1, logs: [] } }]);
  const res = await executeWithRelayerResilience({
    conn, payload: { accountId: 'a1', digest: '0xD2' }, signature: '0x', relayer: {}, opts: { maxRetries: 1, backoffMs: 1 },
    coordinator: { reconciler },
  });
  assert.equal(res.ok, true);
  assert.equal(res.deduplicated, undefined);
  assert.equal(conn.calls.length, 1);
});

test('integration: EOA nonce conflict retries with a fresh sequencer nonce', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'int2.sqlite');
  const store = createSqliteStore({ file });
  const sequencer = createNonceSequencer(store);
  const nonceCalls = [];
  const conn = fakeConn([
    { ok: false, errorName: null, reason: 'nonce too low' },
    { ok: true, txHash: '0xretried', receipt: { status: 1, logs: [] } },
  ], { nonceCalls });
  try {
    const res = await executeWithRelayerResilience({
      conn, payload: { accountId: 'a1', digest: '0xD' }, signature: '0x', relayer: {}, opts: { maxRetries: 2, backoffMs: 1 },
      coordinator: { sequencer }, chainUrl: CHAIN, broadcaster: RELAYER, instanceId: 'I2',
    });
    assert.equal(res.ok, true);
    assert.equal(conn.calls.length, 2);
    assert.equal(nonceCalls.length, 2);
    assert.notEqual(nonceCalls[0], nonceCalls[1], '冲突重试必须重协调 fresh nonce');
    assert.equal(res.coordinatedNonce, nonceCalls[1]);
  } finally {
    store.close();
  }
});

test('integration: legacy behavior preserved when no coordinator passed (no nonce override)', async () => {
  const conn = fakeConn([{ ok: true, txHash: '0xleg', receipt: { status: 1, logs: [] } }]);
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, opts: {},
  });
  assert.equal(res.ok, true);
  assert.equal(conn.calls[0].nonce, undefined, '无 coordinator → 不传 nonce override（ethers 自读）');
  assert.equal('nonce' in conn.calls[0], false);
});

test('integration: explicit accountId/payloadDigest drive dedupe even when payload lacks them (production wiring)', async () => {
  // 生产 canonical payload 只有 action/amount/nonce 等，不含 .accountId/.digest。
  // server.js wiring 传入显式 accountId + payloadDigest → dedupe 必须命中。
  const ledger = [{ txHash: '0xLANDED', accountId: 'prod-acc-1', digest: '0xD-PROD', status: 'confirmed', sessionId: 's1' }];
  const reconciler = createBroadcastReconciler({ listTx: () => ledger });
  const conn = fakeConn([{ ok: true, txHash: '0xshould-not', receipt: { status: 1, logs: [] } }]);
  const res = await executeWithRelayerResilience({
    conn, payload: { action: 'transfer', amount: 5, sessionId: 's1' }, signature: '0x', relayer: {}, opts: {},
    coordinator: { reconciler }, accountId: 'prod-acc-1', payloadDigest: '0xD-PROD',
  });
  assert.equal(res.deduplicated, true);
  assert.equal(res.txHash, '0xLANDED');
  assert.equal(res.accountId, 'prod-acc-1');
  assert.equal(conn.calls.length, 0, '必须零广播调用');
});

test('integration: explicit identity + sequencer allocate nonce for a payload without accountId/digest', { skip: !sqliteAvailable }, async () => {
  const file = join(dir, 'int3.sqlite');
  const store = createSqliteStore({ file });
  const sequencer = createNonceSequencer(store);
  const nonceCalls = [];
  const conn = fakeConn([{ ok: true, txHash: '0xok3', receipt: { status: 1, logs: [] } }], { nonceCalls });
  try {
    const res = await executeWithRelayerResilience({
      conn, payload: { action: 'transfer' }, signature: '0x', relayer: {}, opts: { maxRetries: 1, backoffMs: 1 },
      coordinator: { sequencer }, chainUrl: CHAIN, broadcaster: RELAYER, instanceId: 'I3',
      accountId: 'prod-acc-1', payloadDigest: '0xD3',
    });
    assert.equal(res.ok, true);
    assert.equal(conn.calls[0].nonce, res.coordinatedNonce);
    assert.equal(res.coordinatedNonce >= 0, true);
  } finally {
    store.close();
  }
});
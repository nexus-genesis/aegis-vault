/**
 * Sprint 4 T3 — Relayer 运营化 单元测试
 *
 * 覆盖：
 *   T3.1 classifyRelayerFailure：合约意图 BadNonce（重放）→ 不可重试（fail-closed）；
 *        relayer EOA nonce 冲突 → NONCE_CONFLICT 可重试；RPC/网络瞬时 → RPC_ERROR 可重试；
 *        确定性合约错误（限额/白名单/签名）→ 不可重试；未知 → 不猜测（不可重试）。
 *   T3.2 executeWithRelayerResilience：瞬时失败指数退避重试直至成功；
 *        确定性拒绝立即返回不重试；重试超限 retriesExhausted；
 *        广播后 wait 失败 → 对账 receipt（已落账复用结果，不重发）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyRelayerFailure, executeWithRelayerResilience } from '../src/relayer-operations.js';

// ─── T3.1 classifyRelayerFailure ─────────────────────────────────────────
test('T3.1 BadNonce (contract intent replay) is NOT retryable — fail-closed', () => {
  const cls = classifyRelayerFailure({ ok: false, errorName: 'BadNonce', reason: 'nonce 1 is not greater than last used 1 (replay, INV-007)' });
  assert.deepEqual(cls, { retryable: false, code: 'BadNonce' });
});

test('T3.1 relayer EOA nonce conflict is retryable (NONCE_CONFLICT)', () => {
  for (const reason of [
    'nonce too low',
    'the tx doesn\'t have the correct nonce',
    'replacement transaction underpriced',
    'transaction with same nonce already in the mempool',
  ]) {
    const cls = classifyRelayerFailure({ ok: false, errorName: null, reason });
    assert.deepEqual(cls, { retryable: true, code: 'NONCE_CONFLICT' }, `reason: ${reason}`);
  }
});

test('T3.1 RPC / network flake is retryable (RPC_ERROR)', () => {
  for (const reason of [
    'ECONNREFUSED 127.0.0.1:8545',
    'request timeout',
    'HTTP 429: Too Many Requests (rate limit)',
    'net_version failed: network error',
    'socket hang up',
  ]) {
    const cls = classifyRelayerFailure({ ok: false, errorName: null, reason });
    assert.equal(cls.retryable, true, `reason: ${reason}`);
    assert.equal(cls.code, 'RPC_ERROR', `reason: ${reason}`);
  }
});

test('T3.1 deterministic contract errors are NOT retryable', () => {
  for (const errorName of ['AmountExceedsPerTx', 'AmountExceedsDaily', 'WhitelistViolation', 'InvalidSignature', 'SessionExpired', 'AccountPaused']) {
    const cls = classifyRelayerFailure({ ok: false, errorName, reason: 'x' });
    assert.deepEqual(cls, { retryable: false, code: errorName });
  }
});

test('T3.1 unknown / unclassifiable is NOT retried (fail-closed, no guessing)', () => {
  const cls = classifyRelayerFailure({ ok: false, errorName: null, reason: 'some other reason' });
  assert.equal(cls.retryable, false);
});

// ─── T3.2 executeWithRelayerResilience ────────────────────────────────────
function fakeConn(results, { iface = null } = {}) {
  const calls = [];
  const conn = {
    contract: { interface: iface ?? { parseLog: () => null } },
    executeFromAgent: async (o) => {
      calls.push(o);
      return results.shift();
    },
  };
  conn.calls = calls;
  return conn;
}

test('T3.2 transient RPC failures retry with backoff then succeed', async () => {
  const conn = fakeConn([
    { ok: false, errorName: null, reason: 'ECONNREFUSED' },
    { ok: false, errorName: null, reason: 'request timeout' },
    { ok: true, txHash: '0xabc', receipt: { status: 1, logs: [] } },
  ]);
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, opts: { maxRetries: 3, backoffMs: 1 },
  });
  assert.equal(res.ok, true);
  assert.equal(conn.calls.length, 3, 'must have attempted 3 times');
  assert.equal(res.attempts, 3);
  assert.equal(res.retried, true);
});

test('T3.2 deterministic BadNonce is NOT retried (single attempt)', async () => {
  const conn = fakeConn([
    { ok: false, errorName: 'BadNonce', reason: 'replay' },
    { ok: true, txHash: '0xabc', receipt: { status: 1, logs: [] } },
  ]);
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, opts: { maxRetries: 3, backoffMs: 1 },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'BadNonce');
  assert.equal(res.retryable, false);
  assert.equal(conn.calls.length, 1, 'deterministic failure must not retry');
  assert.equal(res.attempts, 1);
});

test('T3.2 retries exhaust after maxRetries', async () => {
  const conn = fakeConn([
    { ok: false, errorName: null, reason: 'ECONNREFUSED' },
    { ok: false, errorName: null, reason: 'ECONNREFUSED' },
    { ok: false, errorName: null, reason: 'ECONNREFUSED' },
  ]);
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, opts: { maxRetries: 1, backoffMs: 1 },
  });
  assert.equal(res.ok, false);
  assert.equal(res.attempts, 2, 'initial + 1 retry');
  assert.equal(res.retriesExhausted, true);
  assert.equal(res.retryable, true);
});

test('T3.2 wait-failed broadcast is reconciled via receipt when already mined (no re-broadcast)', async () => {
  const iface = { parseLog: () => null };
  const conn = fakeConn([
    { ok: false, txHash: '0xlanded', waitFailed: true, reason: 'request timeout after broadcast' },
    // 若未被对账会走到这里；但 provider 命中 receipt → 直接复用结果，不再调 execute。
    { ok: true, txHash: '0xshould-not-happen', receipt: { status: 1, logs: [] } },
  ], { iface });
  const provider = {
    getTransactionReceipt: async (h) => (h === '0xlanded' ? { status: 1, logs: [] } : null),
  };
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, provider, opts: { maxRetries: 2, backoffMs: 1 },
  });
  assert.equal(res.ok, true);
  assert.equal(res.txHash, '0xlanded', 'reconciled result must reuse the landed txHash');
  assert.equal(res.reconciled, true);
  assert.equal(conn.calls.length, 1, 'already-mined tx must NOT be re-broadcast');
});

test('T3.2 wait-failed tx not yet mined falls back to retry (safe re-broadcast)', async () => {
  const conn = fakeConn([
    { ok: false, txHash: '0xmaybe', waitFailed: true, reason: 'timeout' },
    { ok: true, txHash: '0xabc', receipt: { status: 1, logs: [] } },
  ]);
  const provider = { getTransactionReceipt: async () => null };
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, provider, opts: { maxRetries: 2, backoffMs: 1 },
  });
  assert.equal(res.ok, true);
  assert.equal(res.txHash, '0xabc');
  assert.equal(conn.calls.length, 2);
  assert.equal(res.attempts, 2);
});

test('T3.2 wait-failed tx landing DURING the backoff is reconciled, not re-broadcast (review fix)', async () => {
  // 第 1 次对账（wait 失败后立即）→ 未落账；退避期间落账 → 重发前第 2 次对账命中。
  const conn = fakeConn([
    { ok: false, txHash: '0xslow', waitFailed: true, reason: 'timeout' },
    { ok: true, txHash: '0xdup', receipt: { status: 1, logs: [] } }, // 不应被执行
  ]);
  let polls = 0;
  const provider = {
    getTransactionReceipt: async () => (polls++ === 0 ? null : { status: 1, logs: [] }),
  };
  const res = await executeWithRelayerResilience({
    conn, payload: {}, signature: '0x', relayer: {}, provider, opts: { maxRetries: 2, backoffMs: 1 },
  });
  assert.equal(res.ok, true);
  assert.equal(res.txHash, '0xslow', 'must reuse the hash that landed during backoff');
  assert.equal(res.reconciled, true);
  assert.equal(conn.calls.length, 1, 'tx landed during backoff must NOT be re-broadcast');
  assert.equal(res.attempts, 1);
});

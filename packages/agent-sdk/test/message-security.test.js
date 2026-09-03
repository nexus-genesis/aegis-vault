/**
 * message-security — Sprint 3 T3 参考实现测试
 *
 * 覆盖协议层四项最小要求的四类用例：
 *   1. 正常签名/验签通过
 *   2. 篡改（payload / sender / nonce）→ 验签失败（fail-closed）
 *   3. 过期（timestamp 超窗）→ timestamp_expired
 *   4. 重放（同一 (sender, nonce) 二次提交）→ replay_detected
 * 另：版本不支持 / 缺字段 / 未来时间戳。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createMessageEnvelope,
  verifyMessageEnvelope,
  createReplayGuard,
  messagePreimage,
  messageSecurity,
} from '../src/index.js';

// 确定性"签名"：对 preimage 字节做简单摘要（仅测试用；生产注入 Dilithium2/Ed25519）。
const sign = (bytes) => 'sig-' + [...bytes].reduce((a, b) => (a * 31 + (b & 0xff)) >>> 0, 7).toString(16);
const verify = (bytes, signature) => signature === sign(bytes);

const NOW = 1_787_390_000_000;
const SENDER = 'ng1-agent-a';
const TARGET = 'ng1-service-b';
const PAYLOAD = { type: 'task_claim', taskId: 'T-42' };

test('messageSecurity namespace exports the envelope API', () => {
  for (const fn of ['createMessageEnvelope', 'verifyMessageEnvelope', 'createReplayGuard', 'messagePreimage']) {
    assert.equal(typeof messageSecurity[fn], 'function', `missing ${fn}`);
  }
});

test('valid envelope signs and verifies (identity + payload integrity)', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  assert.equal(env.version, 1);
  assert.equal(env.sender, SENDER);
  assert.equal(env.target, TARGET);
  assert.equal(typeof env.signature, 'string');
  const res = verifyMessageEnvelope({ envelope: env, verifier: verify, now: NOW });
  assert.deepEqual(res, { ok: true });
});

test('tampered payload fails closed (invalid_signature)', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const tampered = { ...env, payload: { type: 'task_claim', taskId: 'T-999' } };
  const res = verifyMessageEnvelope({ envelope: tampered, verifier: verify, now: NOW });
  assert.deepEqual(res, { ok: false, error: 'invalid_signature' });
});

test('tampered sender fails closed (invalid_signature)', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const tampered = { ...env, sender: 'ng1-attacker' };
  const res = verifyMessageEnvelope({ envelope: tampered, verifier: verify, now: NOW });
  assert.deepEqual(res, { ok: false, error: 'invalid_signature' });
});

test('expired timestamp fails closed (timestamp_expired)', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const later = NOW + 600_000; // > maxAgeMs (300s)
  const res = verifyMessageEnvelope({ envelope: env, verifier: verify, now: later });
  assert.deepEqual(res, { ok: false, error: 'timestamp_expired' });
});

test('future timestamp (clock skew beyond window) fails closed', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const res = verifyMessageEnvelope({ envelope: env, verifier: verify, now: NOW - 600_000 });
  assert.deepEqual(res, { ok: false, error: 'timestamp_expired' });
});

test('replayed (sender, nonce) fails closed (replay_detected)', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const guard = createReplayGuard();
  assert.deepEqual(verifyMessageEnvelope({ envelope: env, verifier: verify, replayGuard: guard, now: NOW }), { ok: true });
  // 同一信封（同 sender + 同 nonce）二次提交 → 重放。
  assert.deepEqual(verifyMessageEnvelope({ envelope: env, verifier: verify, replayGuard: guard, now: NOW }), {
    ok: false,
    error: 'replay_detected',
  });
});

test('same payload with a different nonce is NOT a replay', () => {
  const guard = createReplayGuard();
  const e1 = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, nonce: 'n-1', timestamp: NOW });
  const e2 = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, nonce: 'n-2', timestamp: NOW });
  assert.deepEqual(verifyMessageEnvelope({ envelope: e1, verifier: verify, replayGuard: guard, now: NOW }), { ok: true });
  assert.deepEqual(verifyMessageEnvelope({ envelope: e2, verifier: verify, replayGuard: guard, now: NOW }), { ok: true });
});

test('tampered first delivery does NOT burn the nonce (anti-poisoning, review fix)', () => {
  // 攻击场景：攻击者抢先投递同 (sender, nonce) 的篡改副本 → 验签失败被拒；
  // 随后合法原件到达 → 必须仍可通过（nonce 未被无效消息烧掉）。
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const guard = createReplayGuard();
  const tampered = { ...env, payload: { type: 'task_claim', taskId: 'T-999' } };
  assert.deepEqual(
    verifyMessageEnvelope({ envelope: tampered, verifier: verify, replayGuard: guard, now: NOW }),
    { ok: false, error: 'invalid_signature' },
  );
  assert.deepEqual(
    verifyMessageEnvelope({ envelope: env, verifier: verify, replayGuard: guard, now: NOW }),
    { ok: true },
  );
  // 真正的重放（合法原件二次提交）仍被拒绝。
  assert.deepEqual(
    verifyMessageEnvelope({ envelope: env, verifier: verify, replayGuard: guard, now: NOW }),
    { ok: false, error: 'replay_detected' },
  );
});

test('unsupported version / missing fields fail closed', () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  assert.deepEqual(verifyMessageEnvelope({ envelope: { ...env, version: 99 }, verifier: verify, now: NOW }), {
    ok: false,
    error: 'unsupported_version',
  });
  const { nonce, ...noNonce } = env;
  assert.deepEqual(verifyMessageEnvelope({ envelope: noNonce, verifier: verify, now: NOW }), {
    ok: false,
    error: 'missing_nonce',
  });
});

test('preimage is canonical and deterministic', () => {
  const env = { version: 1, sender: SENDER, target: TARGET, payload: PAYLOAD, nonce: 'n-1', timestamp: NOW };
  const a = messagePreimage(env);
  const b = messagePreimage({ ...env, payload: JSON.stringify(PAYLOAD) });
  assert.equal(a, b, 'object payload and its JSON string must produce the same preimage');
  assert.ok(a.includes('n-1') && a.includes(String(NOW)) && a.includes(SENDER));
});

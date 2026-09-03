/**
 * transport-security — Sprint 4 T1 运行时传输安全测试
 *
 * 覆盖：
 *   T1.5 service identity 目录：register / resolve / list / 未知身份 fail-closed
 *   T1.4 createReplayStore：持久化 anti-replay（文件恢复 + 上限淘汰）
 *   T1.3 createInboundVerifier：缺信封 / 未知身份 / 篡改 / 重放 / 过期 一律 fail-closed
 *   T1.1/T1.2 createHttpTransport messageSecurity：
 *       默认关（body 不变，向后兼容）；显式开 → POST 包 { envelope }；
 *       缺 signer/identity → 发送前抛错（fail-closed）
 *   T1.6 E2E：CoordinationClient → signed transport → 本地 HTTP 服务 inbound 验签 → 处理
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createIdentityDirectory,
  createReplayStore,
  createInboundVerifier,
  createMessageEnvelope,
  createHttpTransport,
  CoordinationClient,
  messageSecurity,
  serviceIdentity,
  transportSecurity,
} from '../src/index.js';

// 确定性"签名"（仅测试用；生产注入 Dilithium2/Ed25519/EVM）。
const sign = (bytes) => 'sig-' + [...bytes].reduce((a, b) => (a * 31 + (b & 0xff)) >>> 0, 7).toString(16);
const verify = (bytes, signature) => signature === sign(bytes);

const NOW = Date.now();
const SENDER = 'ng1-agent-a';
const TARGET = 'ng1-service-b';
const PAYLOAD = { type: 'task_claim', taskId: 'T-42' };

const REPLAY_FILE = join(tmpdir(), `replay-${process.pid}-${Date.now()}.json`);
const REPLAY_FILE2 = join(tmpdir(), `replay2-${process.pid}-${Date.now()}.json`);

after(() => {
  for (const f of [REPLAY_FILE, REPLAY_FILE2]) if (existsSync(f)) unlinkSync(f);
});

// ─── T1.5 service identity directory ────────────────────────────────────
test('T1.5 createIdentityDirectory: register/resolve/list; unknown -> null', () => {
  const dir = createIdentityDirectory();
  assert.equal(typeof serviceIdentity.createIdentityDirectory, 'function');
  dir.register({ id: SENDER, publicKey: '0xpub-a', algorithm: 'ed25519', verifier: verify });
  const entry = dir.resolve(SENDER);
  assert.equal(entry.id, SENDER);
  assert.equal(entry.publicKey, '0xpub-a');
  assert.equal(entry.algorithm, 'ed25519');
  assert.equal(typeof entry.verifier, 'function');
  assert.equal(dir.resolve('ng1-unknown'), null); // fail-closed 依据
  assert.deepEqual(dir.list(), [{ id: SENDER, publicKey: '0xpub-a', algorithm: 'ed25519', registeredAt: entry.registeredAt }]);
  assert.equal(dir.size, 1);
});

test('T1.5 register validates required fields (fail-fast)', () => {
  const dir = createIdentityDirectory();
  assert.throws(() => dir.register({ id: '', publicKey: '0x', verifier: verify }), /id is required/);
  assert.throws(() => dir.register({ id: 'a', publicKey: '', verifier: verify }), /publicKey is required/);
  assert.throws(() => dir.register({ id: 'a', publicKey: '0x' }), /verifier/);
});

// ─── T1.4 createReplayStore ─────────────────────────────────────────────
test('T1.4 createReplayStore: dedupe + file persistence survives reload', () => {
  const store = createReplayStore({ file: REPLAY_FILE, maxEntries: 3 });
  assert.equal(store.record(`${SENDER}:n1`), true);
  assert.equal(store.record(`${SENDER}:n1`), false); // 重复
  assert.equal(store.has(`${SENDER}:n1`), true);

  // 上限淘汰：写入第 4 个 → 最旧的 n1 被淘汰。
  store.record(`${SENDER}:n2`);
  store.record(`${SENDER}:n3`);
  store.record(`${SENDER}:n4`);
  assert.equal(store.has(`${SENDER}:n1`), false);
  assert.equal(store.has(`${SENDER}:n4`), true);

  // 新实例从文件恢复：n4 仍在（重放窗口不因重启丢失）。
  const reloaded = createReplayStore({ file: REPLAY_FILE });
  assert.equal(reloaded.has(`${SENDER}:n4`), true);
});

// ─── T1.3 createInboundVerifier ─────────────────────────────────────────
test('T1.3 inbound verifier: missing envelope / unknown identity fail-closed', () => {
  const dir = createIdentityDirectory();
  dir.register({ id: SENDER, publicKey: '0xpub', verifier: verify });
  const verifyRequest = createInboundVerifier({ directory: dir, self: TARGET });

  assert.deepEqual(verifyRequest({ plain: 'body' }), {
    ok: false, error: 'missing_envelope',
    reason: 'message security enabled: unsigned request rejected (fail-closed)',
  });
  assert.equal(verifyRequest(null).ok, false);

  const forged = createMessageEnvelope({ sender: 'ng1-attacker', target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const res = verifyRequest({ envelope: forged });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'unknown_identity');
});

test('T1.3 inbound verifier: cross-service replay rejected (wrong_target, review fix)', () => {
  // 攻击场景：截获发给 service-b 的合法签名信封，原样转发给 service-c。
  // service-c 认该 sender 且自己的 replay store 未见过该 nonce —— 若不校验
  // target === self，验签会通过（跨服务重放成功）。复核修复：wrong_target。
  const dir = createIdentityDirectory();
  dir.register({ id: SENDER, publicKey: '0xpub', verifier: verify });
  const serviceC = createInboundVerifier({ directory: dir, self: 'ng1-service-c' });
  const serviceCStore = createReplayStore();

  const intercepted = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const forwarded = serviceC({ envelope: intercepted });
  assert.equal(forwarded.ok, false);
  assert.equal(forwarded.error, 'wrong_target');
  assert.match(forwarded.reason, /cross-service replay/);
  // nonce 未被烧（fail-closed 在验签前短路）：合法发给 service-c 的消息不受影响。
  const legit = createMessageEnvelope({ sender: SENDER, target: 'ng1-service-c', payload: PAYLOAD, signer: sign, timestamp: NOW });
  assert.deepEqual(serviceC({ envelope: legit }), { ok: true, identity: SENDER, payload: PAYLOAD });
  assert.equal(serviceCStore.size, 0);

  // 构造时缺 self → fail-fast（target 校验不可静默跳过）。
  assert.throws(() => createInboundVerifier({ directory: dir }), /self .*is required/);
});

test('T1.3 inbound verifier: valid / tampered / expired / replay', () => {
  const dir = createIdentityDirectory();
  dir.register({ id: SENDER, publicKey: '0xpub', verifier: verify });
  const replayStore = createReplayStore();
  const verifyRequest = createInboundVerifier({ directory: dir, self: TARGET, replayStore });

  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW });
  const ok = verifyRequest({ envelope: env });
  assert.deepEqual(ok, { ok: true, identity: SENDER, payload: PAYLOAD });

  // 篡改 payload → invalid_signature
  const tampered = verifyRequest({ envelope: { ...env, payload: { ...PAYLOAD, taskId: 'T-999' } } });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.error, 'invalid_signature');

  // 重放（同 (sender, nonce)）→ replay_detected
  const replay = verifyRequest({ envelope: env });
  assert.equal(replay.ok, false);
  assert.equal(replay.error, 'replay_detected');

  // 过期 → timestamp_expired
  const expiredEnv = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: NOW - 600_000 });
  const expired = verifyRequest({ envelope: expiredEnv });
  assert.equal(expired.ok, false);
  assert.equal(expired.error, 'timestamp_expired');
});

// ─── T1.1/T1.2 createHttpTransport messageSecurity ──────────────────────
test('T1.1 default transport (no messageSecurity) sends plain body (backward compat)', async () => {
  const seen = [];
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    seen.push(JSON.parse(raw));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const baseURL = `http://127.0.0.1:${port}`;
  try {
    const transport = createHttpTransport({ baseURL });
    await transport.post('/api/tasks', { agent_identity: SENDER, title: 'plain' });
    // 未开启 → 服务端收到的是原始 body（无 envelope 包裹）。
    assert.equal(seen[0].agent_identity, SENDER);
    assert.equal(seen[0].envelope, undefined);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('T1.1 enabled but missing signer/identity → throws before sending (fail-closed)', () => {
  assert.throws(
    () => createHttpTransport({ baseURL: 'http://x', messageSecurity: { identity: SENDER } }),
    /requires identity \+ signer/,
  );
});

test('T1.6 E2E: CoordinationClient -> signed transport -> inbound-verified HTTP server', async () => {
  const dir = createIdentityDirectory();
  dir.register({ id: SENDER, publicKey: '0xpub', verifier: verify });
  const replayStore = createReplayStore({ file: REPLAY_FILE2 });
  const verifyRequest = createInboundVerifier({ directory: dir, self: TARGET, replayStore });

  const received = [];
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    const verdict = verifyRequest(body);
    if (!verdict.ok) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: verdict.error, reason: verdict.reason }));
      return;
    }
    received.push(verdict.payload);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, echo: verdict.payload }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseURL = `http://127.0.0.1:${server.address().port}`;

  try {
    const transport = createHttpTransport({
      baseURL,
      messageSecurity: { identity: SENDER, signer: sign, target: TARGET },
    });
    const client = new CoordinationClient(transport);

    // 签名任务发布 → 服务端验签通过 → 拿到原始 payload。
    const res = await client.publishTask({
      agent: SENDER,
      title: 'Signed task',
      description: 'via message security',
      capabilities: ['analysis'],
      reward: 10,
      taskType: 'analysis',
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(received.length, 1);
    assert.equal(received[0].agent_identity, SENDER);
    assert.equal(received[0].title, 'Signed task');

    // 未签名请求（模拟恶意客户端直接 POST 明文）→ 403 missing_envelope。
    const plain = await fetch(`${baseURL}/api/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_identity: SENDER, title: 'unsigned' }),
    });
    assert.equal(plain.status, 403);
    const plainBody = await plain.json();
    assert.equal(plainBody.error, 'missing_envelope');
  } finally {
    await new Promise((r) => server.close(r));
  }
});

// ─── 导出面 ─────────────────────────────────────────────────────────────
test('index exports messageSecurity/serviceIdentity/transportSecurity namespaces', () => {
  for (const fn of ['createMessageEnvelope', 'verifyMessageEnvelope', 'createReplayGuard', 'messagePreimage']) {
    assert.equal(typeof messageSecurity[fn], 'function');
  }
  for (const fn of ['createIdentityDirectory']) assert.equal(typeof serviceIdentity[fn], 'function');
  for (const fn of ['createReplayStore', 'createInboundVerifier']) assert.equal(typeof transportSecurity[fn], 'function');
  assert.equal(typeof transportSecurity.createReplayStore, 'function');
  assert.equal(typeof createInboundVerifier, 'function');
});

/**
 * transport-mtls-e2e.test.js — Sprint 5 T5.2：signed transport + replay guard + mTLS 全链路 E2E
 *
 * 验证「传输层 (mTLS) → 应用层 (message-security 信封) → 防重放 (replay store)」
 * 三层在同一请求上组合，且每一层独立 fail-closed、互不替代：
 *   1. 三层全通过  → 200 + 原始 payload 交达
 *   2. 传输层缺证书 → 握手被拒（不及应用层）
 *   3. 传输层通过但应用层无信封（明文）→ missing_envelope（证书合法仍拒）
 *   4. 有效信封 + 有效证书，重放同一信封 → replay_detected（防重放 over mTLS）
 *   5. replay store 持久化 → 服务端重启后重放仍被拒（窗口不因重启重置）
 *   6. 跨服务 target 重放 → wrong_target（发给他人的信封不可在本服务放行）
 *
 * 全部本地自签 CA，不起真实网络。证书经 scripts/lib/x509.mjs 生成。
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCa, issueLeaf, generateEd25519Keypair } from '../../../scripts/lib/x509.mjs';
import { createMtlsServer, createMtlsClient } from '../src/mtls-server.js';
import { createIdentityDirectory, createReplayStore, createInboundVerifier, createMessageEnvelope } from '../src/index.js';

const DNS = ['localhost'];
const IP = ['127.0.0.1'];

// 确定性"签/验"（测试用；生产注入 Dilithium2/Ed25519/EVM）。
const sign = (bytes) => 'sig-' + [...bytes].reduce((a, b) => (a * 31 + (b & 0xff)) >>> 0, 7).toString(16);
const verify = (bytes, signature) => signature === sign(bytes);

const SENDER = 'ng1-agent-e2e';
const TARGET = 'ng1-mtls-service';
const PAYLOAD = { type: 'task_claim', taskId: 'T-77', n: 1 };

const REPLAY_FILE = join(tmpdir(), `mtls-e2e-replay-${process.pid}-${Date.now()}.json`);

let ca;
let serverCert, serverKey;
let clientGood, clientOther;

// E2E server 组装：mTLS 层之上叠 inbound verifier（应用层）+ replay store（防重放）。
let srv;
let received;
let verifyRequest;
let replayStoreVar;

before(async () => {
  ca = createCa();
  const serverKp = generateEd25519Keypair();
  const serverLeaf = issueLeaf({ ca, keypair: serverKp, cn: 'localhost', eku: ['serverAuth'], dns: DNS, ip: IP });
  serverCert = serverLeaf.cert;
  serverKey = serverKp.privatePem;

  const k1 = generateEd25519Keypair();
  clientGood = issueLeaf({ ca, keypair: k1, cn: 'e2e-client', eku: ['clientAuth'], dns: DNS, ip: IP });
  const k2 = generateEd25519Keypair();
  clientOther = issueLeaf({ ca, keypair: k2, cn: 'other-client', eku: ['clientAuth'], dns: DNS, ip: IP });
});

/** 组装一个可在 onRequest 内消费信封的服务实例（可多次创建以模拟重启）。 */
function bootMtlsService() {
  const dir = createIdentityDirectory();
  dir.register({ id: SENDER, publicKey: '0xpub-e2e', verifier: verify });
  replayStoreVar = createReplayStore({ file: REPLAY_FILE });
  verifyRequest = createInboundVerifier({ directory: dir, self: TARGET, replayStore: replayStoreVar });
  received = [];

  const server = createMtlsServer({
    cert: serverCert,
    key: serverKey,
    ca: ca.cert,
    audit: () => {},
    onRequest: ({ req, res }) => {
      let raw = '';
      req.on('data', (c) => { raw += c; });
      req.on('end', () => {
        const body = raw ? JSON.parse(raw) : {};
        const verdict = verifyRequest(body);
        res.setHeader('content-type', 'application/json');
        if (!verdict.ok) {
          res.statusCode = 403;
          res.end(JSON.stringify({ ok: false, error: verdict.error, reason: verdict.reason }));
          return;
        }
        received.push(verdict.payload);
        res.statusCode = 200;
        res.end(JSON.stringify({ ok: true, identity: verdict.identity, payload: verdict.payload }));
      });
    },
  });
  return server;
}

async function start() { srv = bootMtlsService(); srv._port = await srv.listen(); }
async function restart() { await srv.close(); srv = bootMtlsService(); srv._port = await srv.listen(); }

beforeEach(async () => {
  received = [];
  if (srv) await srv.close();
  srv = bootMtlsService();
  srv._port = await srv.listen();
});

after(async () => {
  if (srv) await srv.close();
  if (existsSync(REPLAY_FILE)) unlinkSync(REPLAY_FILE);
});

const url = (path) => `https://127.0.0.1:${srv._port}${path}`;

/** 经 mTLS 发送一个信封（传输层 + 应用层同时验证）。 */
function clientFor(leaf) {
  return createMtlsClient({ ca: ca.cert, cert: leaf.cert, key: leaf.keypair.privatePem });
}

function wrap(envelope) { return { envelope }; }

test('T5.2-1 三层全通过：mTLS + 签名信封 + 防重放 → 200，payload 交达 + 身份正确', async () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now() });
  const res = await clientFor(clientGood)(url('/claim'), wrap(env));
  assert.equal(res.status, 200, JSON.stringify(res.data));
  assert.equal(res.data.identity, SENDER);
  assert.deepEqual(res.data.payload, PAYLOAD);
  assert.equal(received.length, 1);
  // replay store 记下了 (sender, nonce)：窗口生效。
  assert.equal(replayStoreVar.has(`${SENDER}:${env.nonce}`), true);
});

test('T5.2-2 传输层缺客户端证书 → 握手被拒（mTLS 独立 fail-closed，不及应用层）', async () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now() });
  // 无客户端证书（伪造 PEM）→ 握手层直接拒绝。
  const noCert = createMtlsClient({ ca: ca.cert, cert: '-----BEGIN CERTIFICATE-----\nam9w\n', key: '-----BEGIN PRIVATE KEY-----\na2V4\n' });
  let rejected = false;
  try { await noCert(url('/claim'), wrap(env)); } catch { rejected = true; }
  assert.equal(rejected, true, '无有效 mTLS 客户端证书的请求应被传输层拒绝');
  assert.equal(received.length, 0);
});

test('T5.2-3 传输层通过但无信封（明文）→ missing_envelope（应用层 fail-closed，证书合法仍拒）', async () => {
  // 合法 mTLS 客户端，但 body 未包 envelope → 即使证书认证通过也拒。
  const res = await clientFor(clientGood)(url('/claim'), { agent_identity: SENDER, title: 'plain-over-tls' });
  assert.equal(res.status, 403);
  assert.equal(res.data.error, 'missing_envelope');
  assert.equal(received.length, 0);
});

test('T5.2-4 重放同一信封 over mTLS → replay_detected', async () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now() });
  const call = clientFor(clientGood);
  const first = await call(url('/claim'), wrap(env));
  assert.equal(first.status, 200);
  // 同一信封（同 nonce）再次发送 → 应用层防重放拦截。
  const replay = await call(url('/claim'), wrap(env));
  assert.equal(replay.status, 403);
  assert.equal(replay.data.error, 'replay_detected');
  assert.equal(received.length, 1);
});

test('T5.2-5 replay store 持久化：服务端重启后重放仍被拒（窗口不因重启重置）', async () => {
  const env = createMessageEnvelope({ sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now() });
  // 首次在"旧进程"消费并落盘。
  const first = await clientFor(clientGood)(url('/claim'), wrap(env));
  assert.equal(first.status, 200);

  // 重启服务端（内存 state 清空，仅留 replay 文件）。
  await restart();
  // 用新进程的 inverse（同一文件恢复窗口）。同一信封重放仍被拒。
  const replay = await clientFor(clientGood)(url('/claim'), wrap(env));
  assert.equal(replay.status, 403);
  assert.equal(replay.data.error, 'replay_detected');
});

test('T5.2-6 跨服务 target 重放 → wrong_target（发给他人信封不可在本服务放行）', async () => {
  // 截获发给另一服务的合法签名信封，原样发给本服务。
  const envToOther = createMessageEnvelope({ sender: SENDER, target: 'ng1-another-service', payload: PAYLOAD, signer: sign, timestamp: Date.now() });
  const res = await clientFor(clientGood)(url('/claim'), wrap(envToOther));
  assert.equal(res.status, 403);
  assert.equal(res.data.error, 'wrong_target');
  assert.match(res.data.reason, /cross-service replay/);
  assert.equal(received.length, 0);
});
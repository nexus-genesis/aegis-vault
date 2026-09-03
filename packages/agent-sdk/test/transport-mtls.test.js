/**
 * transport-mtls.test.js — Sprint 5 T1.2/T1.3 + T5.1：TLS 1.3 / mTLS 传输层安全验收
 *
 * 覆盖（全部 fail-closed，全部用本地自签 CA，不起真实网络）：
 *   1. 有效 mTLS 客户端 → 200 + 身份 CN 正确
 *   2. 无有效客户端证书 → 握手被拒（rejectUnauthorized）
 *   3. 不受信任 CA 签发的客户端证书（伪造/外部 CA）→ 握手被拒
 *   4. 过期客户端证书 → 握手被拒
 *   5. TLS 1.2 客户端 → 握手被拒（强制 TLS 1.3）
 *   6. 纯文本 HTTP → 非 TLS，握手失败
 *   7. 过期服务端证书 → 客户端拒绝（服务端凭据失效 fail-closed）
 *   8. 握手成功/失败均落审计（event: mtls_handshake）
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createCa, issueLeaf, generateEd25519Keypair } from '../../../scripts/lib/x509.mjs';
import { createMtlsServer, createMtlsClient } from '../src/mtls-server.js';

const DNS = ['localhost'];
const IP = ['127.0.0.1'];

let ca;                 // 受信任根 CA
let foreignCa;          // 不受信任的外部 CA（伪造签名用）
let serverCert, serverKey, serverKeypair;
let client1, client2;
let expiredClient, foreignClient;
let audited = [];
let srv;

before(async () => {
  ca = createCa();
  foreignCa = createCa({ cn: 'Untrusted Foreign CA' });

  serverKeypair = generateEd25519Keypair();
  const serverLeaf = issueLeaf({ ca, keypair: serverKeypair, cn: 'localhost', eku: ['serverAuth'], dns: DNS, ip: IP });
  serverCert = serverLeaf.cert;
  serverKey = serverKeypair.privatePem;

  const k1 = generateEd25519Keypair();
  client1 = issueLeaf({ ca, keypair: k1, cn: 'one-client', eku: ['clientAuth'], dns: DNS, ip: IP });
  const k2 = generateEd25519Keypair();
  client2 = issueLeaf({ ca, keypair: k2, cn: 'two-client', eku: ['clientAuth'], dns: DNS, ip: IP });

  // 过期客户端证书
  const kExp = generateEd25519Keypair();
  expiredClient = issueLeaf({
    ca, keypair: kExp, cn: 'expired-client', eku: ['clientAuth'], dns: DNS, ip: IP,
    notBefore: Date.now() - 2 * 86400000, notAfter: Date.now() - 86400000,
  });

  // 外部 CA 签发的"伪造"客户端
  const kForged = generateEd25519Keypair();
  foreignClient = issueLeaf({ ca: foreignCa, keypair: kForged, cn: 'forged-client', eku: ['clientAuth'], dns: DNS, ip: IP });

  srv = createMtlsServer({
    cert: serverCert,
    key: serverKey,
    ca: ca.cert,
    audit: (entry) => { audited.push(entry); },
    onRequest: ({ res, identity }) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ identity }));
    },
  });
  srv._port = await srv.listen();
});

after(async () => { await srv.close(); });

const url = (path) => `https://127.0.0.1:${srv._port}${path}`;
const expectRejected = async (promise) => {
  let rejected = false;
  try { await promise; } catch { rejected = true; }
  assert.equal(rejected, true, '期望握手/请求被拒绝（fail-closed），但意外成功');
};

test('1/8 有效客户端经 mTLS 成功，身份=CN', async () => {
  const call = createMtlsClient({ ca: ca.cert, cert: client1.cert, key: client1.keypair.privatePem });
  const res = await call(url('/whoami'));
  assert.equal(res.status, 200);
  assert.equal(res.data.identity, 'one-client');

  const call2 = createMtlsClient({ ca: ca.cert, cert: client2.cert, key: client2.keypair.privatePem });
  const res2 = await call2(url('/whoami'));
  assert.equal(res2.data.identity, 'two-client');
});

test('2/8 无有效客户端证书 → 握手中断（fail-closed）', async () => {
  const call = createMtlsClient({ ca: ca.cert, cert: '-----BEGIN CERTIFICATE-----\nbm9w\n', key: '-----BEGIN PRIVATE KEY-----\na2V4\n' });
  await expectRejected(call(url('/whoami')));
});

test('3/8 外部/伪造 CA 签发的客户端证书 → 握手被拒（fail-closed）', async () => {
  const call = createMtlsClient({ ca: ca.cert, cert: foreignClient.cert, key: foreignClient.keypair.privatePem });
  await expectRejected(call(url('/whoami')));
});

test('4/8 过期客户端证书 → 握手被拒（fail-closed）', async () => {
  const call = createMtlsClient({ ca: ca.cert, cert: expiredClient.cert, key: expiredClient.keypair.privatePem });
  await expectRejected(call(url('/whoami')));
});

test('5/8 只支持 TLS 1.2 的客户端 → 握手失败（强制 TLS 1.3）', async () => {
  const call = createMtlsClient({
    ca: ca.cert, cert: client1.cert, key: client1.keypair.privatePem,
    tls: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
  });
  await expectRejected(call(url('/whoami')));
});

test('6/8 纯文本 HTTP 请求 → 不是 TLS，握手失败', async () => {
  await new Promise((resolveRej, rejectRej) => {
    const req = http.request({ hostname: '127.0.0.1', port: srv._port, path: '/', method: 'GET' }, (res) => {
      rejectRej(new Error(`HTTP 竟然连上了 TLS 端口 status=${res.statusCode}`));
    });
    req.on('error', () => resolveRej());
    req.on('timeout', () => { req.destroy(); resolveRej(); });
    req.setTimeout(2000);
    req.end();
  });
});

test('7/8 过期服务端证书 → 客户端拒绝（服务端凭据失效 fail-closed）', async () => {
  const expiredLeaf = issueLeaf({
    ca, keypair: generateEd25519Keypair(), cn: 'localhost', eku: ['serverAuth'], dns: DNS, ip: IP,
    notBefore: Date.now() - 2 * 86400000, notAfter: Date.now() - 86400000,
  });
  const bad = createMtlsServer({
    cert: expiredLeaf.cert, key: expiredLeaf.keypair.privatePem, ca: ca.cert,
    audit: () => {}, onRequest: ({ res }) => res.end('{}'),
  });
  const port = await bad.listen();
  try {
    const call = createMtlsClient({ ca: ca.cert, cert: client1.cert, key: client1.keypair.privatePem });
    await expectRejected(call(`https://127.0.0.1:${port}/whoami`));
  } finally {
    await bad.close();
  }
});

test('8/8 成功与失败握手均落审计（mtls_handshake）', () => {
  const events = audited.filter((e) => e.event === 'mtls_handshake');
  assert.ok(events.length >= 2, '应有成功/失败两类握手审计');
  assert.ok(events.some((e) => e.identity === 'one-client' && e.ok !== false), '成功握手应记录身份');
  // 失败握手应记录 ok:false 且不泄漏内部细节
  const failures = events.filter((e) => e.ok === false);
  assert.ok(failures.length >= 1, '应有失败握手审计');
  for (const f of failures) {
    assert.match(f.error, /^tls_/); // 只暴露类别
  }
});
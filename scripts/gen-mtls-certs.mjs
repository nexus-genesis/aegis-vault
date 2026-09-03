#!/usr/bin/env node
/**
 * gen-mtls-certs.mjs — 生成 mTLS 证书（纯 node:crypto，无需系统 openssl）
 *
 * 两种模式：
 *   dev（默认）：自签随机根 CA + server/client1/client2，落盘 certs/mtls/。仅开发/测试。
 *   production：证书由「受控 CA」签发（不再自签随机 CA）——CA 证书+私钥通过
 *               secret-store 引用（env:/file:/${...}）注入；客户端证书身份（CN）绑定
 *               到 agent identity（--identity，对应 service-identity.js 目录条目）。
 *               CA 私钥绝不被写盘（留在 secret store），仅写出叶子证书与密钥。
 *
 * 用法：
 *   node scripts/gen-mtls-certs.mjs [outDir]                       # 开发自签
 *   node scripts/gen-mtls-certs.mjs --mode production \
 *       --ca-cert 'env:MTLS_CA_CERT' --ca-key 'file:./certs/prod-ca-key.pem' \
 *       --identity 'agent-service' --cn 'svc.prod.example.org' [--out ./certs/mtls-prod]
 *
 * 生产安全提示：缺 CA 引用 / 引用无法解析 → 拒绝生成（fail-closed），绝不回退到自签随机 CA。
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { createCa, issueLeaf, generateEd25519Keypair, loadCa } from './lib/x509.mjs';
import { createSecretResolver } from '../mcp-server/src/secret-store.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const get = (name) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] !== undefined ? args[i + 1] : undefined;
};
// 兼容旧用法：第 1 个位置参数仍视为 outDir（dev 模式）。
const OUT_DIR = get('--out') || (args[0] && !args[0].startsWith('--') ? resolve(process.cwd(), args[0]) : null)
  || resolve(__dirname, '..', 'certs', 'mtls');
const MODE = (get('--mode') || 'dev').toLowerCase();

function ensureDir(p) { mkdirSync(p, { recursive: true }); }

/** 用 node:crypto 校验证书可解析、且叶子可被目标公钥（CA）信任。 */
function verify({ ca, caPub, items }) {
  const trust = (leafCert, issuerPubKey) => new X509Certificate(leafCert).verify(issuerPubKey);
  const results = items.map(({ name, leaf, issuerKey }) => [name, trust(leaf, issuerKey)]);
  results.push(['CA 可由自身公钥验签（自签根）', trust(ca, caPub)]);
  for (const [name, ok] of results) {
    if (!ok) throw new Error(`自检失败: ${name}`);
  }
  return results.map(([name]) => `  [ok] ${name}`);
}

/** 开发模式：自签随机 CA + server/client1/client2。 */
function devMode() {
  ensureDir(OUT_DIR);
  const ca = createCa();
  const dnDefault = ['localhost'];
  const ipDefault = ['127.0.0.1', '::1'];

  const serverKey = generateEd25519Keypair();
  const server = issueLeaf({ ca, keypair: serverKey, cn: 'localhost', eku: ['serverAuth'], dns: dnDefault, ip: ipDefault });
  const clientKey1 = generateEd25519Keypair();
  const client1 = issueLeaf({ ca, keypair: clientKey1, cn: 'one-client', eku: ['clientAuth'], dns: dnDefault, ip: ipDefault });
  const clientKey2 = generateEd25519Keypair();
  const client2 = issueLeaf({ ca, keypair: clientKey2, cn: 'two-client', eku: ['clientAuth'], dns: dnDefault, ip: ipDefault });

  writeFileSync(resolve(OUT_DIR, 'ca.pem'), ca.cert);
  writeFileSync(resolve(OUT_DIR, 'ca-key.pem'), ca.keypair.privatePem);
  writeFileSync(resolve(OUT_DIR, 'server-cert.pem'), server.cert);
  writeFileSync(resolve(OUT_DIR, 'server-key.pem'), server.keypair.privatePem);
  writeFileSync(resolve(OUT_DIR, 'client1-cert.pem'), client1.cert);
  writeFileSync(resolve(OUT_DIR, 'client1-key.pem'), client1.keypair.privatePem);
  writeFileSync(resolve(OUT_DIR, 'client2-cert.pem'), client2.cert);
  writeFileSync(resolve(OUT_DIR, 'client2-key.pem'), client2.keypair.privatePem);

  console.log(`[dev] mTLS 证书生成到 ${OUT_DIR}:`);
  console.log('  ca.pem / ca-key.pem          根 CA（自签）');
  console.log('  server-cert.pem / server-key.pem   服务端（serverAuth）');
  console.log('  client1-cert.pem / client1-key.pem  客户端1（clientAuth）');
  console.log('  client2-cert.pem / client2-key.pem  客户端2（clientAuth）');
  console.log('自检:');
  for (const line of verify({ ca: ca.cert, caPub: ca.keypair.publicKey, items: [
    { name: 'server 由 CA 签发', leaf: server.cert, issuerKey: ca.keypair.publicKey },
    { name: 'client1 由 CA 签发', leaf: client1.cert, issuerKey: ca.keypair.publicKey },
    { name: 'client2 由 CA 签发', leaf: client2.cert, issuerKey: ca.keypair.publicKey },
  ] })) console.log(line);
  console.log('\n注意：本证书仅用于开发/测试，不要用于生产。');
}

/** 生产模式：受控 CA 签发，身份绑定到 --identity。 */
function productionMode() {
  const refCert = get('--ca-cert');
  const refKey = get('--ca-key');
  const identity = get('--identity');
  const serverCn = get('--cn') || 'localhost';
  if (!refCert || !refKey) {
    console.error('[prod] FAIL — 生产模式必须提供 --ca-cert 与 --ca-key（受控 CA，经 secret-store 引用）。\n'
      + '      绝不回退到自签随机 CA（fail-closed）。');
    process.exit(1);
  }
  const resolver = createSecretResolver();
  const caCert = resolver.resolveSecretRef(refCert);
  const caKey = resolver.resolveSecretRef(refKey);
  if (!caCert || !caKey) {
    console.error('[prod] FAIL — 无法从 secret-store 解析受控 CA 证书/私钥（引用未解析）。');
    process.exit(1);
  }
  ensureDir(OUT_DIR);
  const ca = loadCa({ cert: caCert, key: caKey });
  const serverKey = generateEd25519Keypair();
  const server = issueLeaf({ ca, keypair: serverKey, cn: serverCn, eku: ['serverAuth'], dns: [serverCn], ip: ['127.0.0.1'] });
  const clientKey = generateEd25519Keypair();
  // 客户端身份绑定到 service identity（CN=identity，service-identity.js 目录条目）。
  const clientCn = identity || 'agent-service';
  const client = issueLeaf({ ca, keypair: clientKey, cn: clientCn, eku: ['clientAuth'], dns: [clientCn], ip: [] });

  writeFileSync(resolve(OUT_DIR, 'ca.pem'), ca.cert);             // 公钥 CA 落盘供 mTLS 信任
  writeFileSync(resolve(OUT_DIR, 'server-cert.pem'), server.cert);
  writeFileSync(resolve(OUT_DIR, 'server-key.pem'), server.keypair.privatePem);
  writeFileSync(resolve(OUT_DIR, 'client-cert.pem'), client.cert);
  writeFileSync(resolve(OUT_DIR, 'client-key.pem'), client.keypair.privatePem);
  // 刻意不写 ca-key.pem：CA 私钥保留在 secret store，绝不被本脚本落盘。

  console.log(`[prod] mTLS 证书（受控 CA 签发）生成到 ${OUT_DIR}:`);
  console.log(`  ca.pem                    受控 CA 公钥证书（信任锚点）`);
  console.log(`  server-cert.pem/server-key.pem  服务端（serverAuth, CN=${serverCn}）`);
  console.log(`  client-cert.pem/client-key.pem   客户端（clientAuth, 身份=${clientCn}）`);
  console.log('  (未写 ca-key.pem —— CA 私钥留存在 secret store)');
  console.log('自检:');
  for (const line of verify({ ca: ca.cert, caPub: ca.publicKey, items: [
    { name: 'server 由受控 CA 签发', leaf: server.cert, issuerKey: ca.publicKey },
    { name: 'client(身份) 由受控 CA 签发', leaf: client.cert, issuerKey: ca.publicKey },
  ] })) console.log(line);
  console.log(`\n[prod] 证书身份已绑定到 service identity: ${clientCn}`);
}

main();
function main() {
  if (MODE === 'production') return productionMode();
  return devMode();
}
/**
 * secret-store.test.js — Sprint 7 T5 生产证书/密钥接入验收
 *
 * T5.2 secret-store SPI：
 *   - createSecretResolver() 默认 env 后端：plain 原样返回 / env: 读 env / file: 读文件。
 *   - backend='kms' 未提供 provider → SECRET_KMS_NOT_CONFIGURED（fail-closed，
 *     零隐式依赖，不捆绑任何具体 KMS）。
 *   - provider 注入可插拔。
 * T5.1 生产 mTLS 证书签发（gen-mtls-certs --mode production）：
 *   - 缺受控 CA 引用 → 拒绝（exit 1，绝不回退自签随机 CA）。
 *   - 提供受控 CA（经 file: secret-ref）→ 签发 server + 客户端，客户端 CN=--identity
 *     （绑定 service identity），且不写 ca-key.pem（CA 私钥留 secret store）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  createSecretResolver,
  resolveSecretRef,
  isSecretRef,
} from '../src/secret-store.js';
import { buildChainEnvConfig } from '../src/chain-config.js';
import { createCa } from '../../scripts/lib/x509.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const GEN = fileURLToPath(new URL('../../scripts/gen-mtls-certs.mjs', import.meta.url));

test('T5.2 env 后端：plain 原样返回（direct 密钥 env）', () => {
  const r = createSecretResolver();
  assert.equal(r.resolveSecretRef('0xabcd1234'), '0xabcd1234');
});

test('T5.2 env 后端：env: 引用读 process.env', () => {
  process.env.SEC_OWNER_TEST = '0xfromenv';
  try {
    const r = createSecretResolver();
    assert.equal(r.resolveSecretRef('env:SEC_OWNER_TEST'), '0xfromenv');
    assert.equal(r.resolveSecretRef('${env:SEC_OWNER_TEST}'), '0xfromenv');
  } finally {
    delete process.env.SEC_OWNER_TEST;
  }
});

test('T5.2 env 后端：file: 引用读文件内容（trim）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-sec-'));
  const f = join(dir, 'key.txt');
  writeFileSync(f, '  0xfilekey\n  ');
  try {
    assert.equal(createSecretResolver().resolveSecretRef(`file:${f}`), '0xfilekey');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T5.2 kms 后端未提供 provider → fail-closed SECRET_KMS_NOT_CONFIGURED', () => {
  assert.throws(() => createSecretResolver({ backend: 'kms' }), (e) => e.code === 'SECRET_KMS_NOT_CONFIGURED');
});

test('T5.2 provider 注入可插拔（KMS 占位实现）', () => {
  const provider = (ref) => ref === 'kms:chain-owner' ? '0xkmsresolved' : undefined;
  const r = createSecretResolver({ backend: 'kms', provider });
  assert.equal(r.resolveSecretRef('kms:chain-owner'), '0xkmsresolved');
});

test('T5.2 isSecretRef 识别 env:/file:/${...}', () => {
  assert.equal(isSecretRef('env:X'), true);
  assert.equal(isSecretRef('file:p'), true);
  assert.equal(isSecretRef('${env:X}'), true);
  assert.equal(isSecretRef('0xhexkey'), false);
});

test('T5.2 chain-config 走 resolver：file: 引用解析为真实密钥，缺省 env 直读不变', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-sec-'));
  const owner = join(dir, 'owner.key');
  writeFileSync(owner, '0x1111111111111111111111111111111111111111111111111111111111111111');
  process.env.CHAIN_RPC_URL = 'https://rpc.test';
  process.env.CHAIN_OWNER_PK = `file:${owner}`;
  process.env.CHAIN_EMERGENCY_PK = '0x2222222222222222222222222222222222222222222222222222222222222222';
  process.env.CHAIN_RELAYER_PK = '0x3333333333333333333333333333333333333333333333333333333333333333';
  try {
    // 无 resolver：file: 路径原样当密钥 → 非 anvil → 通过（不解析）。
    const direct = buildChainEnvConfig({ profile: 'testnet' });
    assert.equal(direct.ownerPk, `file:${owner}`);
    // 有 resolver：file: 引用解析为真实密钥值。
    const resolved = buildChainEnvConfig({ profile: 'testnet', secretResolver: createSecretResolver() });
    assert.equal(resolved.ownerPk, '0x1111111111111111111111111111111111111111111111111111111111111111');
  } finally {
    delete process.env.CHAIN_RPC_URL;
    delete process.env.CHAIN_OWNER_PK;
    delete process.env.CHAIN_EMERGENCY_PK;
    delete process.env.CHAIN_RELAYER_PK;
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── T5.1 生产 mTLS 证书签发（子进程） ──────────────────────────────────────
function mkProdCa() {
  const dir = mkdtempSync(join(tmpdir(), 'ng-ca-'));
  const ca = createCa({ cn: 'Prod Root CA' });
  writeFileSync(join(dir, 'ca.pem'), ca.cert);
  writeFileSync(join(dir, 'ca-key.pem'), ca.keypair.privatePem);
  return dir;
}

test('T5.1 production 缺受控 CA 引用 → 拒绝（exit 1，不回退自签）', () => {
  const out = mkdtempSync(join(tmpdir(), 'ng-prod-'));
  const r = spawnSync(process.execPath, [GEN, '--mode', 'production', '--out', out], {
    encoding: 'utf8', env: { ...process.env },
  });
  assert.equal(r.status, 1);
  assert.match(r.stdout + r.stderr, /fail-closed|--ca-cert/);
  rmSync(out, { recursive: true, force: true });
});

test('T5.1 production 受控 CA 签发：sever/client + 身份绑定 + 不写 ca-key.pem', () => {
  const caDir = mkProdCa();
  const out = mkdtempSync(join(tmpdir(), 'ng-prod-'));
  try {
    const r = spawnSync(process.execPath, [
      GEN, '--mode', 'production',
      '--ca-cert', `file:${join(caDir, 'ca.pem')}`,
      '--ca-key', `file:${join(caDir, 'ca-key.pem')}`,
      '--identity', 'agent-service-01', '--cn', 'svc.prod.example.org', '--out', out,
    ], { encoding: 'utf8', env: { ...process.env } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(existsSync(join(out, 'client-cert.pem')));
    assert.ok(existsSync(join(out, 'server-cert.pem')));
    assert.ok(existsSync(join(out, 'ca.pem')), '信任锚点 ca.pem 应落盘');
    // CA 私钥绝不写盘：产物里不得包含 ca-key.pem。
    assert.ok(!existsSync(join(out, 'ca-key.pem')), 'CA 私钥不得落盘');
    // 客户端证书 CN = 服务身份（service identity 绑定）。
    assert.match(readFileSync(join(out, 'client-cert.pem'), 'utf8'), /BEGIN CERTIFICATE/);
  } finally {
    rmSync(caDir, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
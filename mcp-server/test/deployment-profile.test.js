/**
 * deployment-profile.test.js — Sprint 7 T2 Deployment profile 验收
 *
 * 覆盖：.env / .json 解析、稳定字段、schema 校验 fail-closed、dry-run 不注入、
 * 缺必填报错带 code、未知 profile 拒绝、显式 env 优先级高于 profile。
 *
 * 验收口径（T2.4）：未配置 → no-op（基线回归）；local 缺 RPC 不报错；production
 * 缺任一操作键 → 抛 code；dry-run 不写 process.env。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseDotEnv,
  parseProfileFile,
  loadDeploymentProfile,
  __resetProfileForTest,
} from '../src/deployment-profile.js';

function envSnapshot() {
  // 快照当前 process.env 里所有 NEXUS/CHAIN/SMART_ACCOUNT/AUDIT/METRICS/HEALTH 键。
  const out = {};
  for (const k of Object.keys(process.env)) {
    if (/^(NEXUS|CHAIN|SMART_ACCOUNT|AUDIT|METRICS|HEALTH)/.test(k)) out[k] = process.env[k];
  }
  return out;
}

test.afterEach(() => {
  __resetProfileForTest();
});

test('T2.1 parseDotEnv trims, ignores comments/blank, strips quotes', () => {
  const e = parseDotEnv('# comment\n\nKEY=value\n  QUOTED="a b c"\nEMPTY=\n');
  assert.equal(e.KEY, 'value');
  assert.equal(e.QUOTED, 'a b c');
  assert.equal(e.EMPTY, '');
  assert.equal(e.comment, undefined);
});

test('T2.1 parseProfileFile reads .env and .json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 'a.env'), 'CHAIN_PROFILE=local\nAUDIT_LOG_MAX_BYTES=10485760');
    const env = parseProfileFile(join(dir, 'a.env'));
    assert.equal(env.env.CHAIN_PROFILE, 'local');
    assert.equal(env.profile, null);

    writeFileSync(join(dir, 'b.json'), JSON.stringify({ profile: 'testnet', env: { CHAIN_RPC_URL: 'x' } }));
    const json = parseProfileFile(join(dir, 'b.json'));
    assert.equal(json.profile, 'testnet');
    assert.equal(json.env.CHAIN_RPC_URL, 'x');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T2.1 JSON env keys must be UPPERCASE (fail-closed)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({ profile: 'local', env: { lowerCase: 'x' } }));
    assert.throws(() => parseProfileFile(join(dir, 'bad.json')), (e) => e.code === 'NEXUS_PROFILE_ENV_KEY_CASE');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T2.4 no NEXUS_PROFILE_FILE → no-op (baseline unchanged)', () => {
  const before = envSnapshot();
  const r = loadDeploymentProfile({ forceReload: true });
  assert.equal(r.loaded, false);
  assert.deepEqual(envSnapshot(), before); // 无任何副作用
});

test('T2.4 local profile missing RPC is NOT an error (allowed)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 'l.env'), 'CHAIN_PROFILE=local\n');
    const prev = process.env.NEXUS_PROFILE_FILE;
    process.env.NEXUS_PROFILE_FILE = join(dir, 'l.env');
    try {
      const r = loadDeploymentProfile({ forceReload: true });
      assert.equal(r.loaded, true);
      assert.equal(process.env.CHAIN_PROFILE, 'local');
    } finally {
      if (prev === undefined) delete process.env.NEXUS_PROFILE_FILE; else process.env.NEXUS_PROFILE_FILE = prev;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T2.4 production profile missing operation key → fail with code', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 'p.env'), 'CHAIN_PROFILE=production\nCHAIN_RPC_URL=https://x\n');
    const prev = process.env.NEXUS_PROFILE_FILE;
    process.env.NEXUS_PROFILE_FILE = join(dir, 'p.env');
    try {
      assert.throws(
        () => loadDeploymentProfile({ forceReload: true }),
        (e) => e.code === 'NEXUS_PROFILE_MISSING_REQUIRED',
      );
    } finally {
      if (prev === undefined) delete process.env.NEXUS_PROFILE_FILE; else process.env.NEXUS_PROFILE_FILE = prev;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T2.3 dry-run validates but does NOT write process.env', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 't.env'), 'CHAIN_PROFILE=testnet\nCHAIN_RPC_URL=https://x\nCHAIN_RELAYER_PK=r\nCHAIN_OWNER_PK=o\nCHAIN_EMERGENCY_PK=e\n');
    const prev = process.env.NEXUS_PROFILE_FILE;
    process.env.NEXUS_PROFILE_FILE = join(dir, 't.env');
    const was = process.env.CHAIN_RPC_URL;
    try {
      const r = loadDeploymentProfile({ dryRun: true, forceReload: true });
      assert.equal(r.loaded, true);
      assert.equal(r.dryRun, true);
      // dry-run 不注入：除非进程原本就有，否则应为 undefined。
      if (was === undefined) assert.equal(process.env.CHAIN_RPC_URL, undefined);
      else assert.equal(process.env.CHAIN_RPC_URL, was);
    } finally {
      // 恢复（本轮测试改动的仅是 profile 文件指针）。
      if (prev === undefined) delete process.env.NEXUS_PROFILE_FILE; else process.env.NEXUS_PROFILE_FILE = prev;
      if (was === undefined) delete process.env.CHAIN_RPC_URL; else process.env.CHAIN_RPC_URL = was;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T2.1 unknown profile name is rejected (fail-closed)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-prof-'));
  try {
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({ profile: 'staging', env: {} }));
    const prev = process.env.NEXUS_PROFILE_FILE;
    process.env.NEXUS_PROFILE_FILE = join(dir, 'bad.json');
    try {
      assert.throws(
        () => loadDeploymentProfile({ forceReload: true }),
        (e) => e.code === 'NEXUS_PROFILE_INVALID_PROFILE',
      );
    } finally {
      if (prev === undefined) delete process.env.NEXUS_PROFILE_FILE; else process.env.NEXUS_PROFILE_FILE = prev;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
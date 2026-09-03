/**
 * release-preflight.test.js — Sprint 7 T4.3 验收
 *
 * preflight 发布门禁的 CLI 级验收（子进程调用 scripts/release-preflight.mjs）：
 *   - 缺操作密钥（production profile，keys 注释掉）→ 拒绝（exit 1，含 FAIL）。
 *   - 满足（local 默认，无必填约束）→ 通过（exit 0）。
 *   - --strict-chain + 占位 RPC → 仍可编译运行（exit 0，chain=WARN 而非 FAIL）。
 *
 * 用子进程而非 in-process import，保证不把 mcp-server 模块加载进测试父进程，
 * 与 baseline 隔离。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const PREFLIGHT = fileURLToPath(new URL('../../scripts/release-preflight.mjs', import.meta.url));
const PROD_PROFILE = fileURLToPath(new URL('../examples/profile.production.env', import.meta.url));

function run(args, env) {
  return spawnSync(process.execPath, [PREFLIGHT, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('T4.1 production profile 缺操作密钥 → preflight 拒绝（exit 1）', () => {
  const r = run([], { NEXUS_PROFILE_FILE: PROD_PROFILE });
  assert.equal(r.status, 1, '缺密钥必须阻断发布');
  assert.match(r.stdout + r.stderr, /PREFLIGHT FAIL/);
  assert.match(r.stdout + r.stderr, /NEXUS_PROFILE_MISSING_REQUIRED/);
});

test('T4.1 local 默认（无可缺必填项）→ preflight 通过（exit 0）', () => {
  const r = run([], {});
  assert.equal(r.status, 0, 'local 默认应可发布');
  assert.match(r.stdout + r.stderr, /PREFLIGHT PASS/);
});

test('T4.1 6 包版本 lockstep 检查通过（当前仓库版本一致）', () => {
  const r = run([], {});
  assert.equal(r.status, 0);
  assert.match(r.stdout + r.stderr, /全部发布包交叉引用与版本 lockstep/);
});

test('review-F: 占位符密钥/RPC（REPLACE_WITH_*）非空也必须阻断发布（exit 1）', () => {
  const r = run([], {
    CHAIN_PROFILE: 'testnet',
    CHAIN_RPC_URL: 'https://sepolia.infura.io/v3/REPLACE_WITH_REAL',
    CHAIN_RELAYER_PK: 'REPLACE_WITH_REAL_RELAYER',
  });
  assert.equal(r.status, 1, '占位符值必须阻断发布');
  assert.match(r.stdout + r.stderr, /占位符检测/);
  assert.match(r.stdout + r.stderr, /PREFLIGHT FAIL/);
});

test('review-B: 绝对路径 SMART_ACCOUNT_STATE_FILE 探测真实目录（不误拼 ROOT）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-pf-'));
  try {
    // 绝对可写目录 + .sqlite（共享后端判定）→ [C] 应 PASS。修复前 join(ROOT, 绝对路径)
    // 拼出无效目录 → mkdirSync 抛错 → 共享后端 FAIL（exit 1）。
    const r = run([], { SMART_ACCOUNT_STATE_FILE: join(dir, 'state.sqlite') });
    assert.equal(r.status, 0, '绝对可写目录的共享 store 检查应 PASS');
    assert.match(r.stdout + r.stderr, /PREFLIGHT PASS/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
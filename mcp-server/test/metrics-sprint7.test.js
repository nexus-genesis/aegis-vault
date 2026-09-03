/**
 * metrics-sprint7.test.js — Sprint 7 T1 部署可观测验收
 *
 * 覆盖：
 *   T1.1 /metrics HTTP 端点（METRICS_HTTP_PORT gate）— 开启格式正确、关闭不监听。
 *   T1.2 指标维度 — 进程级 gauge / store 标签 / 链上健康采样。
 *   T1.3 审计日志体积上限 + 轮转（AUDIT_LOG_MAX_BYTES → `.1` 滚动）。
 *
 * 验收口径（Sprint 7 关键约束）：开启 vs 关闭行为差异最小化；关闭时端口不监听；
 * /metrics 绝不碰 MCP stdout（GET /metrics 返回 Prometheus text，不写 stdout）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  startMetricsServer,
  renderMetrics,
  registerSampler,
  bindChainHealthProvider,
  collectMetrics,
  __resetSamplersForTest,
  __resetChainHealthForTest,
} from '../src/metrics.js';
import { incr, snapshot, __resetMetricsForTest } from '../src/observability.js';

test.afterEach(() => {
  __resetSamplersForTest();
  __resetChainHealthForTest();
  __resetMetricsForTest();
});

test('T1.1 renderMetrics emits Prometheus text 0.0.4 format with TYPE + value rows', () => {
  incr('smart_account_execute_total');
  const body = renderMetrics(snapshot);
  // 进程级 gauge 必须在（基准维度）。
  assert.match(body, /# TYPE process_start_time_seconds gauge/);
  assert.match(body, /^process_start_time_seconds /m);
  // 计数器从其快照带入（命名稳定：smart_account_ 前缀去掉后保留语义）。
  assert.match(body, /^# TYPE smart_account_execute_total counter/m);
  assert.match(body, /^smart_account_execute_total 1$/m);
  // 以空行结尾（Prometheus 惯例：末尾空串 join 出一个换行）。
  assert.ok(body.endsWith('\n'));
});

test('T1.1 startMetricsServer returns null when no port (gate off, no listening)', () => {
  assert.equal(startMetricsServer({ port: '', snapshot }), null);
  assert.equal(startMetricsServer({ port: '   ', snapshot }), null);
});

test('T1.1 startMetricsServer serves /metrics on loopback when METRICS_HTTP_PORT set', async () => {
  const server = startMetricsServer({ port: '0', snapshot }); // port 0 = 随机可用端口
  assert.ok(server);
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address();
  const res = await fetch(`http://127.0.0.1:${port}/metrics`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/plain/);
  const text = await res.text();
  assert.match(text, /^# TYPE process_start_time_seconds gauge/m);
  // 404 对非 metrics 路径。
  const res404 = await fetch(`http://127.0.0.1:${port}/nope`);
  assert.equal(res404.status, 404);
  await new Promise((resolve) => server.close(resolve));
});

test('T1.1 review-E: metrics 端口冲突 → 结构化错误日志，进程存活不崩溃', async () => {
  const blocker = http.createServer(() => {});
  await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
  const { port } = blocker.address();
  const server = startMetricsServer({ port: String(port), snapshot });
  assert.ok(server);
  // EADDRINUSE 异步到达：无 error handler 时是 uncaught exception（进程崩溃）。
  // 等待一拍后仍活着即通过（error handler 接管并落 stderr 结构化日志）。
  await new Promise((r) => setTimeout(r, 120));
  await new Promise((r) => server.close(r));
  await new Promise((r) => blocker.close(r));
});

test('T1.2 review-A: collectMetrics 汇总计数器 + gauge（告警引擎喂给面），未绑 provider 时 chain gauge 缺席', () => {
  incr('relayer_nonce_conflict');
  const handle = bindChainHealthProvider({ async getBlockNumber() { throw new Error('down'); } }, 60000);
  handle.markDown();
  const m = collectMetrics(snapshot);
  // 计数器（裸名，alerting 默认规则 relayer_nonce_conflict 同名寻址）。
  assert.equal(m.relayer_nonce_conflict, 1);
  // 绑定 provider → chain gauge 进告警面（up=0：仅失败采样 + markDown）。
  assert.equal(m.chain_rpc_up, 0);
  // 进程 gauge 同面。
  assert.ok(Number.isFinite(m.process_rss_bytes));
  // 未绑定 provider → chain gauge 缺席（local/进程内链部署不被 chain_rpc_down 误报
  // critical），计数器不受影响。
  __resetChainHealthForTest();
  const m2 = collectMetrics(snapshot);
  assert.equal(m2.chain_rpc_up, undefined);
  assert.equal(m2.relayer_nonce_conflict, 1);
});

test('T1.2 process-level gauges present and heap/rss are finite numbers', () => {
  const body = renderMetrics(snapshot);
  for (const m of ['process_start_time_seconds', 'process_heap_bytes', 'process_heap_total_bytes', 'process_rss_bytes']) {
    const line = body.split('\n').find((l) => l.startsWith(`${m} `));
    assert.ok(line, `missing gauge ${m}`);
    const value = Number(line.split(' ')[1]);
    assert.ok(Number.isFinite(value), `${m} should be numeric`);
  }
});

test('T1.2 registered sampler output appears in /metrics (store backend labels)', () => {
  registerSampler(() => [
    { metric: 'store_backend', value: 1, type: 'gauge', label: { backend: 'sqlite' } },
    { metric: 'store_shared', value: 1, type: 'gauge' },
  ]);
  const body = renderMetrics(snapshot);
  assert.match(body, /# TYPE store_backend\{backend="sqlite"\} gauge/);
  assert.match(body, /^store_backend\{backend="sqlite"\} 1$/m);
  assert.match(body, /^store_shared 1$/m);
});

test('T1.2 chain health sampler defaults to up=0 when no provider (no external dep)', () => {
  const body = renderMetrics(snapshot);
  assert.match(body, /^chain_rpc_up 0$/m);
  assert.match(body, /^chain_last_block_ts 0$/m);
});

test('T1.2 bindChainHealthProvider resolves to up=1 + block ts on success', () => {
  let calls = 0;
  const fakeProvider = {
    async getBlockNumber() { calls += 1; return 42; },
  };
  const handle = bindChainHealthProvider(fakeProvider, 5);
  // 立即采样一次（同步返回 handle）→ 手动 resolve 模拟成功。
  handle.resolve(42);
  const body = renderMetrics(snapshot);
  assert.match(body, /^chain_rpc_up 1$/m);
  assert.ok(Number(lineValue(body, 'chain_last_block_ts')) > 0, 'block ts should be set');
  assert.match(body, /^chain_last_block_number 42$/m);
  // 手动 markDown → up 回落为 0.5（1 成功 1 失败）。
  handle.markDown();
  const body2 = renderMetrics(snapshot);
  assert.match(body2, /^chain_rpc_up 0\.5$/m);
});

function lineValue(body, metric) {
  const line = body.split('\n').find((l) => l.startsWith(`${metric} `));
  return line ? line.split(' ')[1] : '';
}

test('T1.3 audit log rotates to .1 when AUDIT_LOG_MAX_BYTES exceeded', async () => {
  const { recordAudit, getAuditFile, __resetAuditForTest } = await import('../src/audit-log.js');
  const { writeFileSync, existsSync, unlinkSync, mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'ng-audit-'));
  const file = join(dir, 'audit.jsonl');
  const prevFile = process.env.AUDIT_LOG_FILE;
  const prevMax = process.env.AUDIT_LOG_MAX_BYTES;
  try {
    // 预写一个已超限的旧文件，再触发一次落盘 → 应滚动为 .1。
    writeFileSync(file, 'x'.repeat(2048), 'utf8');
    process.env.AUDIT_LOG_FILE = file;
    process.env.AUDIT_LOG_MAX_BYTES = '1024';
    __resetAuditForTest();
    recordAudit({ tool: 'smart_account_execute', accountId: 'acc-1', sessionId: null, payloadDigest: 'd', txHash: '0x1', errorName: null });
    assert.equal(existsSync(`${file}.1`), true, '.1 滚动文件应生成');
    assert.equal((await import('node:fs')).statSync(file).size < 1024, true, '新卷应重置');
  } finally {
    if (prevFile === undefined) delete process.env.AUDIT_LOG_FILE; else process.env.AUDIT_LOG_FILE = prevFile;
    if (prevMax === undefined) delete process.env.AUDIT_LOG_MAX_BYTES; else process.env.AUDIT_LOG_MAX_BYTES = prevMax;
    __resetAuditForTest();
    try { unlinkSync(file); } catch { /* 无妨 */ }
    try { unlinkSync(`${file}.1`); } catch { /* 无妨 */ }
    try { (await import('node:fs')).rmdirSync(dir); } catch { /* 无妨 */ }
  }
});

test('T1.3 review-D: 第二次超限仍滚动（Windows 下 rename 到已存在 .1 须先删旧卷）', async () => {
  const { recordAudit, __resetAuditForTest } = await import('../src/audit-log.js');
  const { writeFileSync, existsSync, statSync, unlinkSync, mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'ng-audit2-'));
  const file = join(dir, 'audit.jsonl');
  const prevFile = process.env.AUDIT_LOG_FILE;
  const prevMax = process.env.AUDIT_LOG_MAX_BYTES;
  try {
    process.env.AUDIT_LOG_FILE = file;
    process.env.AUDIT_LOG_MAX_BYTES = '1024';
    __resetAuditForTest();
    // 第一卷超限 → 滚动为 .1。
    writeFileSync(file, 'x'.repeat(2048), 'utf8');
    recordAudit({ tool: 'smart_account_execute' });
    assert.equal(existsSync(`${file}.1`), true, '第一次滚动应生成 .1');
    // 第二卷再次超限 → 必须再次滚动。修复前（Windows）：rename 到已存在 .1 抛
    // EPERM 被 catch 吞掉 → 当前文件持续增长（> 1024），轮转永久失效。
    writeFileSync(file, 'y'.repeat(2048), 'utf8');
    recordAudit({ tool: 'smart_account_execute' });
    assert.equal(existsSync(`${file}.1`), true);
    assert.ok(statSync(`${file}.1`).size > 0, '.1 应为第二卷内容（重新滚动而非残留）');
    assert.ok(statSync(file).size < 1024, '第三卷应重置（否则轮转已静默失效）');
  } finally {
    if (prevFile === undefined) delete process.env.AUDIT_LOG_FILE; else process.env.AUDIT_LOG_FILE = prevFile;
    if (prevMax === undefined) delete process.env.AUDIT_LOG_MAX_BYTES; else process.env.AUDIT_LOG_MAX_BYTES = prevMax;
    __resetAuditForTest();
    try { unlinkSync(file); } catch { /* 无妨 */ }
    try { unlinkSync(`${file}.1`); } catch { /* 无妨 */ }
    try { (await import('node:fs')).rmdirSync(dir); } catch { /* 无妨 */ }
  }
});
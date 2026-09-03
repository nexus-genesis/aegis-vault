/**
 * health.js — Sprint 7 T3.1/T3.2: /health 端点 + 启动依赖自检
 *
 * 可选开启（HEALTH_HTTP_PORT gate），默认关闭 → 不监听端口，行为与基线一致。
 *
 * 语义（区分存活与就绪，供 LB 摘流）：
 *   - liveness：进程存活（GET /health/live 或 ?live=1）。永不返回 503（进程
 *     活着就是 live）。
 *   - readiness：核心依赖自检（RPC 可连 / store 可写 / policy 文件可读 /
 *     artifact 绑定）。任一 fail → HTTP 503（load balancer 摘流）。
 *
 * 设计约束：
 *   - /health 走独立 loopback HTTP 端口，绝不碰 MCP stdout 协议通道。
 *   - fail-safe：检查失败 → 标记不 ready 并输出结构化 detail（stderr JSON line），
 *     不抛异常、不静默假装成功。
 *   - fail-closed（T3.2）：HEALTH_STRICT_STARTUP=1 且 readiness 任一依赖致命失败
 *     → 拒绝启动（抛错），与配置 fail-closed 同向。默认（非 strict）启动不因
 *     依赖暂时不可用而阻塞 —— 但 readiness 坚决返回 503。
 *   - 检查器由调用方注入（RPC/provider、store、artifact、policy 文件），本模块
 *     不感知具体实现，保持零隐式依赖。
 */
import http from 'node:http';
import { logStructured } from './observability.js';

let checkers = []; // [{ name, fn }]

/**
 * 注册一个 readiness 检查器。
 * @param {object} desc
 * @param {string} desc.name - 稳定标识（供健康探针/告警使用）
 * @param {() => Promise<{ok:boolean, detail?:string}> | {ok:boolean, detail?:string}} desc.fn
 * @param {boolean} [desc.fatal] 若为 true，strict-startup 模式下失败将阻止启动
 */
export function registerHealthCheck(desc) {
  checkers.push({ name: desc.name, fn: desc.fn, fatal: !!desc.fatal });
}

/**
 * 运行全部 readiness 检查。
 * @returns {Promise<{ ready: boolean, checks: Array<{name:string, ok:boolean, detail?:string}> }>}
 */
export async function runHealthChecks() {
  const results = [];
  for (const { name, fn, fatal } of checkers) {
    try {
      const r = await fn();
      results.push({ name, ok: !!r.ok, detail: r.detail, fatal });
    } catch (err) {
      results.push({ name, ok: false, detail: String(err?.message || err), fatal });
    }
  }
  const ready = results.every((r) => r.ok);
  if (!ready) {
    // 结构化通知运维（stderr JSON line，不碰 stdout）。
    logStructured('health_unready', {
      checks: results.map((r) => ({ name: r.name, ok: r.ok, detail: r.detail ?? null })),
    });
  }
  return { ready, checks: results };
}

/**
 * 可选启动 strict 自检：任一 fatal 检查失败 → 抛错拒绝启动。
 * @returns {Promise<void>}
 */
export async function assertStrictStartup() {
  if (process.env.HEALTH_STRICT_STARTUP !== '1') return;
  const { checks } = await runHealthChecks();
  const failed = checks.filter((c) => c.fatal && !c.ok);
  if (failed.length) {
    const err = new Error(
      `HEALTH_STRICT_STARTUP=1: fatal startup dependency(s) unhealthy: ${failed.map((c) => c.name).join(', ')}.`,
    );
    err.code = 'HEALTH_STRICT_STARTUP_FAILED';
    throw err;
  }
}

function renderHealth(state, { ready, checks }) {
  const body = {
    status: ready ? 'ok' : 'unhealthy',
    ready,
    checks,
    ts: new Date().toISOString(),
  };
  return {
    statusCode: state === 'liveness' ? 200 : (ready ? 200 : 503),
    body: JSON.stringify(body, null, 2),
  };
}

/**
 * 可选启动 /health HTTP 服务器（HEALTH_HTTP_PORT gate）。
 * @param {object} [opts]
 * @param {string} [opts.port] 默认读 process.env.HEALTH_HTTP_PORT
 * @returns {import('node:http').Server|null} 未开启 → null
 */
export function startHealthServer({ port } = {}) {
  const p = (port ?? process.env.HEALTH_HTTP_PORT ?? '').trim();
  if (!p) return null;
  const server = http.createServer(async (req, res) => {
    // F3 — 绝不把健康探针写入 stdout；这里都是 GET 只读。
    try {
      const url = (req.url || '/').split('?')[0];
      const mode = url.endsWith('/live') ? 'liveness' : url.endsWith('/ready') ? 'readiness' : null;
      if (req.method !== 'GET' || (mode === null && url !== '/' && url !== '/health')) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
      }
      const isLiveness = mode === 'liveness';
      const { ready, checks } = isLiveness ? { ready: true, checks: [] } : await runHealthChecks();
      const { statusCode, body } = renderHealth(mode ?? 'readiness', { ready, checks });
      res.writeHead(statusCode, { 'content-type': 'application/json' });
      res.end(body);
    } catch (err) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(err?.message || err) }));
    }
  });
  // 复核修复 E：可选健康端口故障（EADDRINUSE 等）绝不能以 unhandled 'error'
  // 事件拖垮 MCP 协议进程 —— 结构化记录（stderr）并降级为「健康探针缺席」。
  // readiness 判定本身不受影响（依赖检查器照常可经 runHealthChecks 编程调用）。
  server.on('error', (err) => {
    logStructured('health_http_error', { error: String(err?.message || err), code: err?.code || null });
  });
  server.listen(Number(p), '127.0.0.1');
  return server;
}

/** 测试隔离。 */
export function __resetHealthChecksForTest() {
  checkers = [];
}
/**
 * metrics.js — Prometheus 文本格式的 HTTP /metrics 端点 (Sprint 7 T1.1/T1.2)
 *
 * 可选开启（METRICS_HTTP_PORT gate），默认关闭 → 不监听任何端口，行为与
 * Sprint 5/6 基线保持一致（零隐式依赖，CI 无外部服务仍全绿）。
 *
 * 设计约束（Sprint 7 关键约束 2）：
 *   - /metrics 走独立 loopback HTTP 端口，绝不碰 MCP stdout 协议通道。
 *   - 只读（GET），不引入任何第三方依赖（node:http 内置）。
 *
 * 输出 Prometheus text 格式：
 *     # TYPE nexus_<name> counter
 *     nexus_smart_account_execute_total 42
 *
 * 维度：
 *   - 复用 observability.js 的计数器面（snapshot()）。
 *   - 进程级 gauge（采样）：hash_process_start_time_seconds /
 *     process_heap_bytes / process_heap_total_bytes / process_rss_bytes。
 *   - 注册式采样函数（registerSampler）让 T1.2 的链上健康、协调器、store
 *     标签由各自模块按需注入，本模块不感知具体实现。
 */
import http from 'node:http';
import { logStructured } from './observability.js';

let listeners = [];

// ---- 链上健康监控（T1.2：chain_rpc_up / chain_last_block_ts）----------
// 绑定 provider 后，后台每隔 intervalMs 采样一次链上最新区块号与 RPC 可用性，
// 渲染 /metrics 时作为 gauge 返回。未绑定任何 provider → 输出两个 gauge 的
// 缺省值（up=0, last_ts=0），无需外部链也能全绿（可选维度，零隐式依赖）。
let chainState = { ups: 0, downs: 0, lastBlockTs: 0 };
let chainPoller = null;
// 复核修复 A：是否绑定过外部 provider。/metrics 渲染保持缺省 up=0（显式可见），
// 但告警引擎（collectMetrics）只在绑定时输出 chain_* gauge —— 否则 local/进程内
// 链部署会因缺省 up=0 被默认规则 chain_rpc_down 误报 critical。
let chainBound = false;

/**
 * 绑定一个 Ethers provider 用于链上健康监控。幂等：重复调用只初始化一次轮询。
 * @param {object} provider - 提供 getBlockNumber(): Promise<number> 的 provider
 * @param {number} [intervalMs] 采样间隔（默认 15s；测试可传入更小值）
 * @returns {{ resolve: (n: number) => void, markDown: () => void }} 手动控制句柄
 */
export function bindChainHealthProvider(provider, intervalMs = 15000) {
  if (!provider || typeof provider.getBlockNumber !== 'function') return null;
  chainBound = true;
  if (chainPoller) clearInterval(chainPoller);
  chainPoller = setInterval(poll, intervalMs);
  if (chainPoller.unref) chainPoller.unref(); // 不阻塞进程退出
  async function poll() {
    try {
      // eslint-disable-next-line no-await-in-loop
      const n = await provider.getBlockNumber();
      chainState.ups += 1;
      chainState.lastBlockTs = Date.now();
      if (typeof n === 'number') chainState.lastBlock = n;
    } catch {
      chainState.downs += 1;
    }
  }
  poll(); // 立即采样一次
  return {
    resolve: (n) => { chainState.ups += 1; chainState.lastBlockTs = Date.now(); chainState.lastBlock = n; },
    markDown: () => { chainState.downs += 1; },
  };
}

/** 链上健康采样器：输出 gauge（成功/失败比 + 最新区块时间戳）。 */
function chainHealthSampler() {
  const total = chainState.ups + chainState.downs;
  const up = total === 0 ? 0 : chainState.ups / total;
  return [
    { metric: 'chain_rpc_up', value: up, type: 'gauge' },
    { metric: 'chain_last_block_ts', value: chainState.lastBlockTs, type: 'gauge' },
    { metric: 'chain_last_block_number', value: Number(chainState.lastBlock ?? 0), type: 'gauge' },
  ];
}

/** 测试隔离：停止轮询并复位链状态。 */
export function __resetChainHealthForTest() {
  if (chainPoller) { clearInterval(chainPoller); chainPoller = null; }
  chainState = { ups: 0, downs: 0, lastBlockTs: 0 };
  chainBound = false;
}

/**
 * 注册一个采样器。每个采样器返回 { metric, value, type?, label? } 数组，
 * type ∈ 'counter' | 'gauge'（默认 counter），label 追加为 `{k="v",...}`。
 * @param {() => Array<{metric:string,value:number,type?:string,label?:object}>} fn
 */
export function registerSampler(fn) {
  listeners.push(fn);
}

/** 进程级 gauge 采样。 */
function processGauges() {
  const mem = process.memoryUsage();
  const up = process.uptime();
  return [
    { metric: 'process_start_time_seconds', value: Math.floor(Date.now() / 1000 - up) * 1.0, type: 'gauge' },
    { metric: 'process_heap_bytes', value: mem.heapUsed, type: 'gauge' },
    { metric: 'process_heap_total_bytes', value: mem.heapTotal, type: 'gauge' },
    { metric: 'process_rss_bytes', value: mem.rss, type: 'gauge' },
  ];
}

/** 把 observability 计数器快照转成 Prometheus 行。 */
function counterRows(snap) {
  return Object.entries(snap).map(([name, val]) => ({
    metric: `smart_account_${name.replace('smart_account_', '')}`,
    value: val,
    type: 'counter',
  }));
}

function formatLabel(label) {
  if (!label || Object.keys(label).length === 0) return '';
  const inner = Object.entries(label)
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
    .join(',');
  return `{${inner}}`;
}

/** 渲染 /metrics 响应体。 */
export function renderMetrics(snapshotFn) {
  let rows = [
    ...counterRows(snapshotFn()),
    ...processGauges(),
    ...chainHealthSampler(), // 链上健康——统一作为 base 维度（无 provider → 缺省 up=0）
  ];
  for (const sample of listeners) {
    try {
      rows = rows.concat(sample());
    } catch {
      /* 采样器异常不影响主指标渲染 */
    }
  }
  // 去重 + 稳定输出：同名同 label 只保留一条（先写优先——base 维度在前，
  // 采样器输出的重复项被丢弃）。
  const seen = new Set();
  const lines = [];
  for (const r of rows) {
    const label = `${r.metric}${formatLabel(r.label)}`;
    if (seen.has(label)) continue;
    seen.add(label);
    const type = r.type === 'gauge' ? 'gauge' : 'counter';
    lines.push(`# TYPE ${label} ${type}`);
    lines.push(`${label} ${r.value}`);
  }
  lines.push('');
  return lines.join('\n');
}

/**
 * 汇总一份「告警引擎可用」的扁平指标映射 { metric: value }（复核修复 A）。
 *
 * 与 renderMetrics 同源（计数器 + 进程 gauge + 链上健康 + 采样器），但只保留
 * **无标签裸名**键 —— alerting 规则按裸名取值（默认规则 chain_rpc_down 的
 * chain_rpc_up / relayer_nonce_conflict 均为裸名）。只喂 observability 的
 * snapshot() 会让 gauge 类指标（chain_rpc_up 等）永远缺席 → 默认 critical
 * 规则不可达。
 *
 * 未绑定 provider 时不输出 chain_* gauge：缺省 up=0 会让无外部链的部署被
 * chain_rpc_down 误报 critical（观测缺位 ≠ 链故障）。
 *
 * @param {() => object} snapshotFn - observability.snapshot（计数器快照）
 * @returns {Record<string, number>}
 */
export function collectMetrics(snapshotFn) {
  const map = {};
  // 计数器：保留 snapshot() 原始键名（告警规则的寻址面——execute_* 规则用
  // smart_account_execute_* 前缀键，relayer_* 规则用裸键；不套用 /metrics 渲染
  // 的 smart_account_ 归一前缀，否则 relayer_* 规则失配）。
  for (const [k, v] of Object.entries(snapshotFn() || {})) {
    const n = Number(v);
    if (Number.isFinite(n)) map[k] = n;
  }
  const put = (rows) => {
    for (const r of rows) {
      if (!r || typeof r.metric !== 'string') continue;
      if (r.label && Object.keys(r.label).length > 0) continue; // 带标签项不进告警面（裸名才可寻址）
      const v = Number(r.value);
      if (Number.isFinite(v)) map[r.metric] = v;
    }
  };
  put(processGauges());
  if (chainBound) put(chainHealthSampler());
  for (const sample of listeners) {
    try { put(sample()); } catch { /* 采样器异常不影响收集 */ }
  }
  return map;
}

/**
 * 可选启动 /metrics HTTP 服务器。
 * @param {{port:string, snapshot:()=>object}} opts
 * @returns {import('node:http').Server|null} 未开启 → null
 */
export function startMetricsServer({ port, snapshot }) {
  const p = (port || '').trim();
  if (!p) return null;
  const server = http.createServer((req, res) => {
    if (req.method !== 'GET' || (req.url !== '/' && req.url !== '/metrics')) {
      res.writeHead(404);
      res.end('Not found\n');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    res.end(renderMetrics(snapshot));
  });
  // 复核修复 E：可选观测端口故障（EADDRINUSE 等）绝不能以 unhandled 'error'
  // 事件拖垮 MCP 协议进程 —— 结构化记录（stderr）并降级为「观测缺席」。
  server.on('error', (err) => {
    logStructured('metrics_http_error', { error: String(err?.message || err), code: err?.code || null });
  });
  server.listen(Number(p), '127.0.0.1');
  return server;
}

/** 测试隔离。 */
export function __resetSamplersForTest() {
  listeners = [];
}
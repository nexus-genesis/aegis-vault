/**
 * observability.js — Smart Account 最小可观测性 (Sprint 2.7 T2)
 *
 * 零外部依赖的计数器面 + 结构化日志（stderr JSON lines，stdio 安全）。
 *
 * 指标命名（对运维稳定）：
 *   smart_account_setup_count
 *   smart_account_preview_count
 *   smart_account_execute_total / success / failed
 *   smart_account_revert_{errorName}        — revert 分类
 *   smart_account_nonce_conflict            — BadNonce
 *   smart_account_limit_rejected            — 超限/过期拒绝
 *   smart_account_rpc_error                 — RPC/网络错误
 */
const counters = new Map();

/** 计数器 +1（或 +n）。 */
export function incr(name, n = 1) {
  counters.set(name, (counters.get(name) || 0) + n);
}

/** 当前全部计数器快照（按名称排序，输出稳定）。 */
export function snapshot() {
  return Object.fromEntries(
    [...counters.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
  );
}

/** 结构化日志（stderr JSON line）。 */
export function logStructured(event, fields = {}) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

/** 测试隔离：清空计数器。 */
export function __resetMetricsForTest() {
  counters.clear();
}

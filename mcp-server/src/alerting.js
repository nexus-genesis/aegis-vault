/**
 * alerting.js — Sprint 7 T3.3: 告警规则引擎
 *
 * 可选开启（ALERT_RULES_FILE gate），默认关闭 → 不读取任何规则、不消费指标、
 * 行为与基线逐字节一致（零隐式依赖）。
 *
 * 规则格式（JSON）：
 *   {
 *     "rules": [
 *       {
 *         "name": "chain_rpc_down",
 *         "metric": "chain_rpc_up",        // Prometheus 指标名（/metrics 同名）
 *         "op": "<",                        // < | > | <= | >= | == | !=
 *         "threshold": 0.5,
 *         "forSec": 30,                     // 观察窗口（秒）
 *         "severity": "warning"             // info | warning | critical
 *       }
 *     ]
 *   }
 *
 * 判定：调 evaluateRules({ metrics, state })——metrics 为快照或采样器输出的
 * { metric -> number } 映射，state 为规则命中时间跟踪 { ruleName -> { since } }。
 * 命中 → 写结构化告警事件（stderr JSON line + 可选 recordAudit），并返回命中详情。
 *
 * 内置默认规则（无文件时若 ALERT_RULES_ENABLE_DEFAULTS=1）：
 *   - chain_rpc_up < 0.5 持续 30s（critical）
 *   - relayer_nonce_conflict > 0 且窗口内突增（warning）
 *   - execute 失败率（smart_account_execute_failed / total）> 0.5 持续 30s（warning）
 */
import { readFileSync, existsSync } from 'node:fs';
import { logStructured } from './observability.js';
import { recordAudit } from './audit-log.js';

let rules = null;          // 缓存解析后的规则
let state = {};            // { ruleName: { since } }

/**
 * 读取 + 解析 ALERT_RULES_FILE。未设置 → 依 ALERT_RULES_ENABLE_DEFAULTS 决定
 * 是否使用内置默认规则。幂等（只解析一次）。
 * @returns {Array<object>}
 */
export function loadRules() {
  if (rules) return rules;
  const file = (process.env.ALERT_RULES_FILE || '').trim();
  if (file) {
    if (!existsSync(file)) {
      const e = new Error(`ALERT_RULES_FILE not found: ${file}`);
      e.code = 'ALERT_RULES_NOT_FOUND';
      throw e;
    }
    let raw;
    try {
      raw = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      const e = new Error(`ALERT_RULES_FILE invalid JSON: ${file} (${err.message})`);
      e.code = 'ALERT_RULES_INVALID_JSON';
      throw e;
    }
    rules = Array.isArray(raw?.rules) ? raw.rules : [];
    return rules;
  }
  rules = process.env.ALERT_RULES_ENABLE_DEFAULTS === '1' ? defaultRules() : [];
  return rules;
}

/** 内置默认规则。 */
export function defaultRules() {
  return [
    { name: 'chain_rpc_down', metric: 'chain_rpc_up', op: '<', threshold: 0.5, forSec: 30, severity: 'critical' },
    { name: 'relayer_nonce_conflicts', metric: 'relayer_nonce_conflict', op: '>=', threshold: 5, forSec: 0, severity: 'warning' },
    { name: 'execute_failure_rate', metric: 'smart_account_execute_failure_rate', op: '>', threshold: 0.5, forSec: 30, severity: 'warning' },
  ];
}

function satisfies(value, op, threshold) {
  switch (op) {
    case '<': return value < threshold;
    case '>': return value > threshold;
    case '<=': return value <= threshold;
    case '>=': return value >= threshold;
    case '==': return value === threshold;
    case '!=': return value !== threshold;
    default: return false;
  }
}

/**
 * 主入口：传入规范化 metrics 映射 { metric: number }（由调用方从 snapshot +
 * 采样器汇总而来），返回当前命中列表并写入告警事件。
 * @param {object} opts
 * @param {Record<string, number>} opts.metrics
 * @returns {Array<{name:string, severity:string, value:number, threshold:number, op:string}>}
 */
export function evaluateAlerts({ metrics }) {
  const rs = loadRules();
  const now = Date.now();
  const fired = [];
  for (const rule of rs) {
    if (!rule?.metric) continue;
    // 对每个 rule，优先用「自带派生值」，否则用同名指标直读。
    let value = Number(metrics[rule.metric]);
    if (!Number.isFinite(value)) value = NaN;
    // execute 失败率派生：fail / total。
    if (rule.metric === 'smart_account_execute_failure_rate') {
      const fail = Number(metrics.smart_account_execute_failed ?? 0);
      const total = Number(metrics.smart_account_execute_total ?? 0);
      value = total > 0 ? fail / total : 0;
    }
    if (!Number.isFinite(value)) continue;
    const hit = satisfies(value, rule.op ?? '<', Number(rule.threshold));
    if (!hit) { delete state[rule.name]; continue; }
    const prev = state[rule.name];
    const forSec = Number(rule.forSec ?? 0);
    // 需要持续窗口命中才触发。
    if (forSec > 0 && prev && now - prev.since < forSec * 1000) continue;
    if (!prev) state[rule.name] = { since: now };
    // 触发（含一次即时命中 when forSec=0）。
    if (forSec === 0 || (prev && now - prev.since >= forSec * 1000)) {
      const alertEvent = {
        alert: rule.name,
        severity: rule.severity ?? 'warning',
        metric: rule.metric,
        value,
        threshold: Number(rule.threshold),
        op: rule.op,
        at: now,
      };
      logStructured('alert_fired', alertEvent);
      try { recordAudit({ tool: 'alert', ...alertEvent }); } catch { /* 告警审计失败不阻断 */ }
      fired.push(alertEvent);
      // 触发后重置计时（避免同窗口重复刷屏）。
      state[rule.name] = { since: now };
    }
  }
  return fired;
}

/** 测试隔离。 */
export function __resetAlertingForTest() {
  rules = null;
  state = {};
}
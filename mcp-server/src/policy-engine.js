/**
 * Policy Engine 外置化 (Sprint 3 T2)
 *
 * 把策略从"写死在 Smart Account / JS 里"抽成链下软策略层：
 *
 *   Policy Engine（链下软策略，可热更新）
 *       ↓ 决策
 *   Signer/Relayer（relayer 广播）
 *       ↓ 提交
 *   Smart Account（链上硬策略最终裁决）
 *
 * 语义：
 *   - 软策略默认放行（空规则 = 不拦截），链上硬策略始终兜底 → 默认行为不变。
 *   - 命中规则且不满足（如 over maxPerTx / disabled action）→ 链下直接拒绝
 *     `PolicyRejected`，省 gas、不浪费链上调用。
 *   - maxDaily：进程内日累计（Sprint 5 T2.1）。单机滚动窗口，超限 → 链下拒绝；
 *     成功广播后由调用方 `addDailyCumulative` 累加。多实例共享状态留待 Sprint 6。
 *   - requiresSimulation：策略可覆盖静态风险表（Sprint 5 T2.2），方向只能收紧
 *     不能放宽（见 resolveSimulationRequirement）。
 *   - 规则表每次调用重读 `SMART_ACCOUNT_POLICY_FILE`（JSON），支持热更新；
 *     未设置该 env 时用内置默认规则。
 *   - 失败模式（Sprint 5 T3）：默认 `POLICY_FAIL_MODE=permissive`（文件损坏 →
 *     回退空表，软层放行、链上硬策略兜底，与既往一致，仅 stderr 告警）。
 *     设置 `POLICY_FAIL_MODE=strict` → 文件缺失/损坏/缺 rules 数组一律
 *     fail-closed：evaluatePolicy 返回 `PolicyConfigError`，模拟查询视为
 *     required（最保守）。strict 不改变 permissive 的默认行为。
 *
 * 规则文件格式（JSON）：
 *   {
 *     "rules": [
 *       { "action": "transfer", "enabled": true, "requiresSimulation": true,
 *         "maxPerTx": "100", "maxDaily": "500" },
 *       { "action": "withdraw", "enabled": false }
 *     ]
 *   }
 */
import { readFileSync } from 'node:fs';
import { classifySimulationRisk } from './simulation-policy.js';

/** 内置默认规则：空表 = 软策略全放行（链上硬策略兜底）。 */
const DEFAULT_RULES = [];

// Sprint 5 T3 — 最近一次策略加载结果的镜像（string|null），供诊断/直调查询。
// server.js 门禁的 strict 判定不依赖它：绑定每请求单次读取的快照健康
// （policySnapshot().health / opts.configHealth），见 loadPolicyWithHealth。
let lastLoadError = null;

/** 当前失败模式：'strict' 或 'permissive'（默认）。 */
export function policyFailMode() {
  return process.env.POLICY_FAIL_MODE === 'strict' ? 'strict' : 'permissive';
}

/**
 * 尝试读取规则表。
 * @returns {{ ok: boolean, rules: Array|null, error?: string }}
 *   ok=false 表示文件缺失/损坏/无 rules 数组（含具体 error 文案）。
 */
function readPolicyResult() {
  const file = process.env.SMART_ACCOUNT_POLICY_FILE;
  if (!file) return { ok: true, rules: DEFAULT_RULES };
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (Array.isArray(parsed.rules)) return { ok: true, rules: parsed.rules };
    return { ok: false, rules: DEFAULT_RULES, error: `SMART_ACCOUNT_POLICY_FILE (${file}) has no 'rules' array` };
  } catch (err) {
    return { ok: false, rules: DEFAULT_RULES, error: `failed to load SMART_ACCOUNT_POLICY_FILE (${file}): ${err.message}` };
  }
}

/**
 * 单次读取：规则 + 配置健康（S5-T3 fix#1/#3）。
 * 调用方（server.js 门禁）拿这一份结果同时用于「strict 判定 + 裁决规则 + 审计」，
 * 每请求只读一次文件；evaluatePolicy / resolveSimulationRequirement 可经 opts
 * 复用该健康结果（configHealth），不重读。
 * @returns {{ rules: Array, health: { ok: boolean, error: string|null } }}
 */
export function loadPolicyWithHealth() {
  const { ok, rules, error } = readPolicyResult();
  const health = { ok, error: ok ? null : (error ?? 'policy config invalid') };
  lastLoadError = health.error;
  if (!ok) {
    process.stderr.write(`[policy] WARNING: ${health.error} — soft policy is permissive, on-chain hard policy still backstops\n`);
  }
  return { rules, health };
}

/**
 * 读取当前生效规则表（permissive 语义）。
 * - 设置 SMART_ACCOUNT_POLICY_FILE 时读取该 JSON（每次调用重读 → 热更新）；
 * - 文件缺失/损坏 → 软策略回退为空表（设计决策：软层不拦截，链上硬策略仍兜底，
 *   默认行为不变）。但绝不静默：向 stderr 输出告警，运维必须能观察到
 *   "限额策略已失效"这一事实。
 * - strict 模式调用方应改用 loadPolicyWithHealth()（一次读取同时拿规则与健康）。
 * @returns {Array<{action:string, enabled?:boolean, requiresSimulation?:boolean, maxPerTx?:string, maxDaily?:string}>}
 */
export function loadPolicy() {
  return loadPolicyWithHealth().rules;
}

/** 最近一次策略加载是否失败（strict 模式据此 fail-closed）。 */
export function lastPolicyLoadError() {
  return lastLoadError;
}

/** 测试/重置：清除最近加载错误状态。 */
export function resetPolicyEngineState() {
  lastLoadError = null;
}

/**
 * BigInt 安全求和（maxDaily 日累计用）：金额是字符串（wei 级可能超出
 * Number.MAX_SAFE_INTEGER），BigInt 精确相加；任一侧无法解析（malformed）→
 * 返回 null，由上层 fail-closed 拒绝（不静默放行）。
 * @returns {bigint|null} 两数之和；无法解析时 null
 */
function sumBigintSafe(a, b) {
  try {
    return BigInt(a) + BigInt(b);
  } catch {
    return null;
  }
}

/** UTC 当日日期键（"YYYY-MM-DD"），maxDaily 滚动窗口按自然日滚动。 */
export function todayKey(date = new Date()) {
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${date.getUTCFullYear()}-${p(date.getUTCMonth() + 1)}-${p(date.getUTCDate())}`;
}

/**
 * maxDaily 进程内日累计 store（Sprint 5 T2.1）。
 * 按 accountId+action 各自累计，key = `${accountId}::${action}`，内部再按 UTC 日
 * 分桶（bucket[day]）。跨日自动从零累计；仅保留当日桶（无界增长不适用，早于今日
 * 的历史桶在首见今日 add 时剪枝）。
 * 单机语义——多实例共享状态留待 Sprint 6。
 */
export function createDailyCumulativeStore() {
  // key = `${accountId}::${action}`, value = Map<day, string>
  const buckets = new Map();

  function key(accountId, action) { return `${accountId}::${action}`; }

  function bucket(accountId, action) {
    let b = buckets.get(key(accountId, action));
    if (!b) { b = new Map(); buckets.set(key(accountId, action), b); }
    return b;
  }

  return {
    /** 当前已累计（未命中/无当日记录 → 返回 '0'）。 */
    total(accountId, action, day = todayKey()) {
      const b = buckets.get(key(accountId, action));
      return b ? (b.get(day) || '0') : '0';
    },
    /**
     * 累加一笔，返回新的当日累计（字符串）。
     * 首次触及今日时会剪枝掉非当日旧桶（跨日自动清零）。
     * @returns {string} 成功返回新累计；malformed 返回 null
     */
    add(accountId, action, amount, day = todayKey()) {
      const b = bucket(accountId, action);
      const prev = b.get(day) || '0';
      const next = sumBigintSafe(prev, amount);
      if (next === null) return null;
      b.set(day, next.toString());
      // 剪枝：只保留当日（跨日滚动后旧桶无运营意义，且避免无界增长）。
      for (const d of [...b.keys()]) if (d !== day) b.delete(d);
      return next.toString();
    },
    /**
     * 回滚一笔预留（S5-T2.1 fix#1：链上失败/未确认时归还额度）。
     * 当日桶不存在（如跨日回滚）→ 返回 null 不动账（误差方向偏严格，安全）。
     * @returns {string|null} 回滚后的当日累计；无法回滚时 null
     */
    subtract(accountId, action, amount, day = todayKey()) {
      const b = buckets.get(key(accountId, action));
      if (!b) return null;
      const prev = b.get(day);
      if (prev === undefined) return null;
      const next = sumBigintSafe(prev, `-${amount}`);
      if (next === null) return null;
      const clamped = next < 0n ? 0n : next; // 防御性下限：不为负
      b.set(day, clamped.toString());
      return clamped.toString();
    },
    /** 清空（测试用）。 */
    reset() { buckets.clear(); },
  };
}

/**
 * 金额比较（BigInt 优先）：金额在本系统中是字符串（wei 级可能超出
 * Number.MAX_SAFE_INTEGER），Number() 会丢精度。整数串走 BigInt 精确比较；
 * 非整数走 Number 兜底；任一侧无法解析（malformed）→ 返回 null，
 * 由上层 fail-closed 拒绝（不静默放行）。
 * @returns {boolean|null} true=超限 false=未超限 null=无法解析
 */
function amountExceeds(amount, limit) {
  try {
    return BigInt(amount) > BigInt(limit);
  } catch {
    const a = Number(amount);
    const l = Number(limit);
    if (Number.isNaN(a) || Number.isNaN(l)) return null;
    return a > l;
  }
}

/**
 * 链下软策略评估。
 * @param {object} intent { action, amount, accountId, chain, asset, recipient, method }
 * @param {object} [opts]
 * @param {Array} [opts.rules] 已加载的规则表（跳过重读）。调用方（server.js execute
 *   门禁）先做一次读取并同时用于「指纹审计 + 评估」——避免两次独立读取之间文件被
 *   热更新导致审计指纹与实际裁决规则不一致（TOCTOU）。
 * @param {object} [opts.store] createDailyCumulativeStore() 实例。仅当规则有
 *   maxDaily 且传入 store 时进行日累计检查；否则视为 soft-pass（链上硬策略兜底）。
 * @param {string} [opts.accountId] 日累计的所属账户。S5 fix#4：intent.accountId
 *   与 opts.accountId 任传其一即可（intent 优先），消除双重传参脚枪。
 * @returns {{ allowed: true, daily?: { accountId, action, amount, used, limit, projected } }}
 *   或 {{ allowed: false, code: 'PolicyRejected', reason: string }}。
 *   `daily` 仅在 maxDaily 检查实际发生且放行时携带——调用方据此立即预留额度
 *   （消 check-then-act 竞态），链上失败再回滚。
 */
export function evaluatePolicy(intent = {}, { rules, store, accountId: optsAccountId, configHealth } = {}) {
  const { action, amount } = intent;
  const accountId = intent.accountId ?? optsAccountId;

  // Sprint 5 T3 — strict 模式下策略加载失败 → fail-closed（绝不放行）。
  // 健康来源（fix#1/#3）：优先复用调用方单次读取的 configHealth（server.js 门禁
  // 传入，每请求只读一次文件）；直调场景无 configHealth 时自行读一次。
  // 错误文案用本次健康结果的具体 error（不退化为泛化字符串）。裁决规则仍以
  // 调用方传入的 rules（同一快照）为准——健康检查不参与裁决，杜绝 TOCTOU。
  if (policyFailMode() === 'strict') {
    const health = configHealth ?? readPolicyResult();
    if (!health.ok) {
      return {
        allowed: false,
        code: 'PolicyConfigError',
        reason: `PolicyEngine strict fail-mode: ${health.error ?? 'policy config invalid'} — refusing to evaluate (fail-closed)`,
      };
    }
  }

  const effective = Array.isArray(rules) ? rules : loadPolicy();
  if (!Array.isArray(effective) || effective.length === 0) return { allowed: true };

  const rule = effective.find((r) => r && r.action === action);
  if (!rule) return { allowed: true }; // 未命中规则 → 软策略不拦截，链上兜底

  if (rule.enabled === false) {
    return { allowed: false, code: 'PolicyRejected', reason: `action '${action}' is disabled by policy` };
  }

  if (rule.maxPerTx !== undefined && amount !== undefined && amount !== null) {
    const exceeds = amountExceeds(amount, rule.maxPerTx);
    if (exceeds === null) {
      return {
        allowed: false,
        code: 'PolicyRejected',
        reason: `action '${action}' amount ${JSON.stringify(amount)} or maxPerTx ${JSON.stringify(rule.maxPerTx)} is not numeric (fail-closed)`,
      };
    }
    if (exceeds) {
      return {
        allowed: false,
        code: 'PolicyRejected',
        reason: `action '${action}' amount ${amount} exceeds policy maxPerTx ${rule.maxPerTx}`,
      };
    }
  }

  // Sprint 5 T2.1 — maxDaily 进程内日累计。仅当调用方提供了 store（累计依赖
  // 执行历史的账户级状态）且规则带 maxDaily 时检查。缺 store → soft-pass，
  // 链上硬策略（最大每日损失上限）始终兜底。放行时携带 daily 预留信息，
  // 调用方（server.js 门禁）据此在同一段内立即 add 预留，链上失败再回滚
  // （消 check-then-act 竞态，见 store.subtract）。
  if (rule.maxDaily !== undefined && store && accountId && amount !== undefined && amount !== null) {
    const used = store.total(accountId, action);                 // '0' 或累计串
    const sum = sumBigintSafe(used, amount);                     // 已用 + 本次
    if (sum === null) {
      return {
        allowed: false,
        code: 'PolicyRejected',
        reason: `action '${action}' cumulative amount ${JSON.stringify(used)} or amount ${JSON.stringify(amount)} is not numeric (fail-closed)`,
      };
    }
    const exceeds = amountExceeds(sum.toString(), rule.maxDaily);
    if (exceeds === null) {
      return {
        allowed: false,
        code: 'PolicyRejected',
        reason: `action '${action}' is not numeric (maxDaily=${JSON.stringify(rule.maxDaily)}) (fail-closed)`,
      };
    }
    if (exceeds) {
      return {
        allowed: false,
        code: 'PolicyRejected',
        reason: `action '${action}' would exceed policy maxDaily ${rule.maxDaily} (used ${used} + ${amount})`,
      };
    }
    return {
      allowed: true,
      daily: {
        accountId, action,
        amount: String(amount),
        used, limit: String(rule.maxDaily),
        projected: sum.toString(),
      },
    };
  }

  return { allowed: true };
}

/**
 * Sprint 5 T2.2 — 合并 policy 规则的 requiresSimulation 覆盖到静态风险分级。
 * 方向只能收紧不能放宽（保守取并集）：
 *   - 静态分级已 required → 不可被 policy 降级（绝不放宽）；
 *   - policy 明示 requiresSimulation:true → 强制 required（收紧）；
 *   - policy 明示 requiresSimulation:false 仅对静态 skippable 有效（放宽被忽略）。
 * @param {string} action
 * @param {object} [opts]
 * @param {Array} [opts.rules] 已加载规则表（跳过重读，复用单次读取）
 * @returns {{ action, requiresSimulation, level, staticLevel, policyOverride, rationale }}
 */
export function resolveSimulationRequirement(action, { rules, configHealth } = {}) {
  // Sprint 5 T3 — strict 且策略加载失败 → 最保守：强制要求模拟（fail-closed）。
  // 健康来源同 evaluatePolicy（fix#1/#3）：复用调用方单次读取的 configHealth，
  // 错误文案用本次具体 error。
  const staticRisk = classifySimulationRisk(action);
  if (policyFailMode() === 'strict') {
    const health = configHealth ?? readPolicyResult();
    if (!health.ok) {
      return {
        action,
        requiresSimulation: true,
        level: 'required',
        staticLevel: staticRisk.level,
        policyOverride: 'none',
        configError: health.error ?? 'policy config invalid',
        rationale: `PolicyEngine strict fail-mode: ${health.error ?? 'policy config invalid'} — treating as must-simulate (fail-closed)`,
      };
    }
  }
  const effective = Array.isArray(rules) ? rules : loadPolicy();
  const rule = effective.find((r) => r && r.action === action);

  // 静态是否要求模拟。
  const staticRequired = staticRisk.requiresSimulation === true;
  // policy 是否明示要求模拟（收紧触发器，只看 === true）。
  const policyForces = rule && rule.requiresSimulation === true;

  const requiresSimulation = staticRequired || policyForces;
  return {
    action,
    requiresSimulation,
    level: requiresSimulation ? 'required' : 'skippable',
    staticLevel: staticRisk.level,
    policyOverride: policyForces
      ? (staticRequired ? 'reinforce (static already required)' : 'require (tightened by policy)')
      : 'none',
    rationale: requiresSimulation
      ? (policyForces
        ? `action '${action}' requires simulation (policy + static, fail-closed)`
        : staticRisk.rationale)
      : staticRisk.rationale,
  };
}

/** 当前生效规则表快照（供 smart_account_policy 查询/审计）。单次读取。 */
export function policySnapshot() {
  const { rules, health } = loadPolicyWithHealth();
  return {
    source: process.env.SMART_ACCOUNT_POLICY_FILE || 'default (empty)',
    rules,
    failMode: policyFailMode(),
    health,
    configError: health.error,
  };
}

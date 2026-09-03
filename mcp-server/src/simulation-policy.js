/**
 * simulation-policy.js — Simulation 正式化 (Sprint 3 T1)
 *
 * 把 smart_account_preview 从"雏形三态"升级为正式风险分析层：明确哪些 action
 * 必须经成功模拟、哪些可跳过、未知 action 一律 fail-closed。
 *
 * 语义：
 *   - required  action → 未经"成功模拟且未过期"不得广播（fail-closed，省 gas、防误投）
 *   - skippable action → 只读/无害，可跳过模拟
 *   - unknown  action → 一律 required（fail-closed：宁可拦，不可放）
 */
export const SIMULATION_WINDOW_MS = 60_000;

/** 资金/特权类：必须经成功模拟才可广播。 */
export const SIMULATION_REQUIRED_ACTIONS = new Set([
  'transfer',
  'transferFrom',
  'approve',
  'withdraw',
  'deposit',
  'swap',
  'bridge',
  'raise-limit',
  'add-owner',
  'remove-owner',
  'upgrade',
  'grant-role',
  'revoke-role',
  'pause',
  'freeze',
]);

/** 只读/无害类：可跳过模拟。 */
export const SIMULATION_SKIPPABLE_ACTIONS = new Set([
  'balance',
  'view',
  'getBalance',
  'getAllowance',
  'listSessions',
  'info',
  'status',
]);

/**
 * 对 action 做模拟风险分级。
 * @param {string} action
 * @returns {{ level: 'required'|'skippable', requiresSimulation: boolean, rationale: string }}
 */
export function classifySimulationRisk(action) {
  if (!action || typeof action !== 'string') {
    return { level: 'required', requiresSimulation: true, rationale: 'unknown action → fail-closed (require simulation)' };
  }
  const key = action.trim();
  if (SIMULATION_REQUIRED_ACTIONS.has(key)) {
    return { level: 'required', requiresSimulation: true, rationale: 'value/privilege-mutating action → must pass a successful simulation first' };
  }
  if (SIMULATION_SKIPPABLE_ACTIONS.has(key)) {
    return { level: 'skippable', requiresSimulation: false, rationale: 'read-only / harmless action → simulation skippable' };
  }
  return { level: 'required', requiresSimulation: true, rationale: 'action not in known lists → fail-closed (require simulation)' };
}

/** 当前策略表快照（供 smart_account_simulation_policy 查询）。 */
export function simulationPolicySnapshot() {
  return {
    windowMs: SIMULATION_WINDOW_MS,
    required: [...SIMULATION_REQUIRED_ACTIONS].sort(),
    skippable: [...SIMULATION_SKIPPABLE_ACTIONS].sort(),
  };
}

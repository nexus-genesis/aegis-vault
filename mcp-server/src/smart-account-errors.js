/**
 * smart-account-errors.js — Smart Account 链上错误归一化 (Sprint 2.6 T3)
 *
 * 把 chain-eth 的 decodeRevert / decodeFailure 输出统一成 MCP 对外稳定错误模型，
 * 让调用方拿到固定语义（error code），而不依赖散落的 errorName/reason 拼接。
 *
 * 固定错误模型（与 SmartAccount.sol 自定义错误一一对应）：
 *   NotOwner / NotEmergency / AccountPaused / AccountFrozen / NotRegistered /
 *   SessionRevokedError / SessionExpired / InvalidSignature / BadNonce /
 *   AmountExceedsPerTx / AmountExceedsDaily / WhitelistViolation /
 *   SelfEscalationRejected / AllowanceSurfaceRejected / SessionExists /
 *   InvalidSession / NoAccountCeiling
 *
 * 非合约错误（RPC/网络/序列化）映射为通用 code：
 *   RPC_ERROR         — JSON-RPC 层错误（连接、超时、限额）
 *   INVALID_PAYLOAD   — 意图序列化失败（intentToStruct 抛错）
 *   UNKNOWN_REVERT    — revert 但无法解析 selector
 */

// 合约自定义错误全集（固定语义，顺序即文档顺序）。
export const SMART_ACCOUNT_ERRORS = [
  'NotOwner',
  'NotEmergency',
  'AccountPaused',
  'AccountFrozen',
  'NotRegistered',
  'SessionRevokedError',
  'SessionExpired',
  'InvalidSignature',
  'BadNonce',
  'AmountExceedsPerTx',
  'AmountExceedsDaily',
  'WhitelistViolation',
  'SelfEscalationRejected',
  'AllowanceSurfaceRejected',
  'SessionExists',
  'InvalidSession',
  'NoAccountCeiling',
];

// 通用错误 code（非合约自定义错误）。
export const GENERIC_ERRORS = {
  RPC_ERROR: 'RPC_ERROR',
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  UNKNOWN_REVERT: 'UNKNOWN_REVERT',
};

/**
 * 归一化一个 chain-eth 调用结果到 MCP 固定错误模型。
 *
 * @param {object} res - executeFromAgent / simulateExecuteFromAgent 返回值
 * @param {string} [fallbackCode] - 完全无法归一时使用的通用 code
 * @returns {{
 *   error: string,       // 固定错误 code
 *   errorName: string|null, // 原始合约错误名（可能为 null）
 *   reason: string|null, // 人类可读原因
 *   revertData: string|null,
 * }}
 */
export function normalizeChainError(res, fallbackCode = GENERIC_ERRORS.UNKNOWN_REVERT) {
  const errorName = res?.errorName ?? null;
  const reason = res?.reason ?? null;
  const revertData = res?.revertData ?? null;

  // 合约自定义错误 → 直接作为固定 code（errorName 已是稳定语义）。
  if (errorName && SMART_ACCOUNT_ERRORS.includes(errorName)) {
    return { error: errorName, errorName, reason, revertData };
  }
  // JSON-RPC 层错误：reason 含典型 RPC 特征（连接、超时、限额、net_version 等）。
  if (reason && /(net_version|eth_call|network|ECONNREFUSED|timeout|exceeded|429|rate limit|RPC)/i.test(reason)) {
    return { error: GENERIC_ERRORS.RPC_ERROR, errorName, reason, revertData };
  }
  // 已解码出错误名但不在固定集合（未来合约新增错误）→ 保留原名。
  if (errorName) {
    return { error: errorName, errorName, reason, revertData };
  }
  return { error: fallbackCode, errorName, reason, revertData };
}

/**
 * 构造一个 MCP 工具错误返回体（isError: true）。
 *
 * @param {object} res - chain-eth 调用结果
 * @param {string} [fallbackCode]
 * @returns {{ content: [{ type: 'text', text: string }], isError: boolean }}
 */
export function chainErrorResponse(res, fallbackCode) {
  const { error, errorName, reason, revertData } = normalizeChainError(res, fallbackCode);
  return {
    content: [{ type: 'text', text: JSON.stringify({
      success: false,
      error,
      errorName,
      reason,
      ...(revertData ? { revertData } : {}),
    }, null, 2) }],
    isError: true,
  };
}

/**
 * message-security.js — Agent-to-Agent 消息安全最小参考实现 (Sprint 3 T3)
 *
 * 这是 RFC（docs/SMART_ACCOUNT_TRANSPORT_SECURITY_RFC.md）的参考实现，
 * 非完整协议。覆盖协议层的四项最小要求：
 *   1. 消息签名     — 注入式 signer/verifier（生产可接 Dilithium2 / Ed25519 / EVM）
 *   2. nonce        — 消息唯一标识，配合防重放
 *   3. timestamp    — 新鲜度窗口（过期拒绝）
 *   4. anti-replay  — 已见 (sender, nonce) 拒绝重放（LRU 上限）
 *
 * 设计约束：零依赖、纯函数、不绑定具体签名后端、与 CoordinationClient
 * 正交（后者目前是纯 HTTP，无消息安全；本模块提供挂载点）。
 */

const ENVELOPE_VERSION = 1;

/** 默认时间新鲜度窗口（毫秒）。 */
export const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * 构建消息签名预像（canonical 拼接）。收发双方必须生成完全一致的 preimage，
 * 否则验签失败 —— 因此所有字段按固定顺序、以 '\n' 分隔。
 * payload 以 JSON.stringify 序列化（对象 → 字符串），保持确定性。
 */
export function messagePreimage({ version, sender, target, payload, nonce, timestamp }) {
  const payloadBytes = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return [
    String(version),
    String(sender),
    String(target),
    String(payloadBytes),
    String(nonce),
    String(timestamp),
  ].join('\n');
}

/**
 * 创建签名消息信封。
 * @param {object} params
 * @param {string} params.sender 发送方服务身份（如 agentId / service-did）
 * @param {string} params.target 接收方服务身份
 * @param {object|string} params.payload 消息体（对象将 JSON 序列化）
 * @param {(preimageBytes: Uint8Array) => string} params.signer 注入式签名器，
 *        接收 preimage 的 UTF-8 字节，返回 hex 签名
 * @param {string} [params.nonce] 消息唯一标识（默认自增计数）
 * @param {number} [params.timestamp] 发送方时钟（默认 Date.now()）
 * @param {number} [params.version=1] 信封版本
 * @returns {object} 信封 { version, sender, target, payload, nonce, timestamp, signature }
 */
export function createMessageEnvelope({ sender, target, payload, signer, nonce, timestamp = Date.now(), version = ENVELOPE_VERSION }) {
  if (!sender || !target || payload === undefined || typeof signer !== 'function') {
    throw new Error('createMessageEnvelope: sender, target, payload, and signer are required');
  }
  const n = nonce || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  const envelope = { version, sender, target, payload, nonce: n, timestamp };
  const preimage = messagePreimage(envelope);
  envelope.signature = signer(new TextEncoder().encode(preimage));
  return envelope;
}

/**
 * 防重放守卫：LRU 窗口，记录已见 (sender, nonce)。
 * 容量超限时淘汰最旧条目（仅用于演示/开发；生产建议用集中式状态）。
 */
export function createReplayGuard({ maxEntries = 1000 } = {}) {
  const seen = new Map(); // key -> timestamp
  return {
    /**
     * 标记 key 已见。若此前已见 → 返回 false（重放），否则记录并返回 true。
     * @param {string} key 通常为 `${sender}:${nonce}`
     */
    record(key) {
      if (seen.has(key)) return false;
      seen.set(key, Date.now());
      if (seen.size > maxEntries) {
        const oldest = seen.keys().next().value;
        seen.delete(oldest);
      }
      return true;
    },
    get size() {
      return seen.size;
    },
  };
}

/**
 * 校验签名消息信封。
 * @param {object} params
 * @param {object} params.envelope 信封（createMessageEnvelope 输出）
 * @param {(preimageBytes: Uint8Array, signature: string) => boolean} params.verifier
 *        注入式验签器：对 preimage 字节与 hex 签名返回是否通过
 * @param {object} [params.replayGuard] 防重放守卫（createReplayGuard 输出）；
 *        提供时启用 anti-replay
 * @param {number} [params.maxAgeMs=300000] 时间新鲜度窗口
 * @param {number} [params.now=Date.now()] 校验方时钟（测试可注入）
 * @returns {{ ok: true }} 或 {{ ok: false, error: string }}
 */
export function verifyMessageEnvelope({ envelope, verifier, replayGuard = null, maxAgeMs = DEFAULT_MAX_AGE_MS, now = Date.now() }) {
  if (!envelope || typeof envelope !== 'object') return { ok: false, error: 'malformed_envelope' };
  const { version, sender, target, payload, nonce, timestamp, signature } = envelope;

  if (Number(version) !== ENVELOPE_VERSION) return { ok: false, error: 'unsupported_version' };
  if (!sender || !target || payload === undefined) return { ok: false, error: 'missing_field' };
  if (typeof nonce !== 'string' || nonce === '') return { ok: false, error: 'missing_nonce' };
  if (typeof timestamp !== 'number' || Number.isNaN(timestamp)) return { ok: false, error: 'missing_timestamp' };

  // 时间新鲜度：防重放 + 防过期消息。
  const age = Math.abs(now - timestamp);
  if (age > maxAgeMs) return { ok: false, error: 'timestamp_expired' };

  if (typeof verifier !== 'function') return { ok: false, error: 'no_verifier' };
  const preimage = messagePreimage(envelope);
  const valid = verifier(new TextEncoder().encode(preimage), signature);
  if (!valid) return { ok: false, error: 'invalid_signature' };

  // anti-replay：同一 (sender, nonce) 只能接受一次。仅在验签通过后记录 —
  // 无效签名的消息不烧 nonce，否则攻击者可抢先投递篡改副本毒化 nonce，
  // 使随后到达的合法原件被误判为重放（拒绝服务）。
  if (replayGuard && !replayGuard.record(`${sender}:${nonce}`)) {
    return { ok: false, error: 'replay_detected' };
  }

  return { ok: true };
}

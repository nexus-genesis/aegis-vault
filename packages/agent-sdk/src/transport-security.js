/**
 * transport-security.js — 运行时传输安全中间层 (Sprint 4 T1.3/T1.4 + Sprint 6 T2)
 *
 * 把 Sprint 3 T3 的「可测参考实现」升级为服务级运行时能力：
 *   - createReplayStore：anti-replay 状态，基于 T1 store 抽象（Sprint 6 T2）：
 *       · 默认 local 后端（进程内 + 本地 JSON 持久化 + 上限淘汰）——单实例语义，
 *         与 Sprint 4/5 基线行为一致；
 *       · 注入 store（如 createSqliteStore）→ 共享模式：claim 恰好一次是
 *         **全实例族**语义（sqlite INSERT OR IGNORE 原子登记），同一 (sender,nonce)
 *         整个服务族只放行一次；跨实例可见、重启不丢。
 *   - createInboundVerifier：inbound 验签中间层，供 Agent↔Agent / Agent↔服务
 *     的服务端入口使用。未签名 / 身份未知 / 验签失败 / 重放 / 过期一律 fail-closed。
 *
 * 与 message-security.js 的分工：
 *   - message-security.js：纯信封 + 签名/验签/防重放原子能力（零依赖、可测）。
 *   - transport-security.js：运行时接线（身份解析 + 持久化/共享防重放 + inbound 中间层）。
 */
import { unlinkSync } from 'node:fs';
import { verifyMessageEnvelope, DEFAULT_MAX_AGE_MS } from './message-security.js';
import { createLocalStore } from './store-interface.js';

const REPLAY_PREFIX = 'replay:';

/**
 * anti-replay 状态（接口与 createReplayGuard 兼容：record/has/size/clear，
 * 可直接作为 verifyMessageEnvelope 的 replayGuard 传入）。
 *
 * 语义（INV-009 不变量，两种后端一致）：
 *   - record(key) === true ⇔ 本次调用是**全族首个**登记者（恰好一次）；
 *     false ⇔ 已被登记（本实例或族内其他实例）→ 判定重放。
 *   - record 仅在验签通过后被调用（verifyMessageEnvelope 保证）——无效签名不烧 nonce。
 *
 * @param {object} [opts]
 * @param {string|null} [opts.file] local 模式持久化 JSON 路径（共享模式忽略）。
 * @param {number} [opts.maxEntries] 容量硬上限：超过 → 先按 retentionMs 清过期（绝对
 *        时间窗口），仍超 → FIFO 淘汰最旧（与单机基线上限淘汰语义一致）。
 * @param {object} [opts.store] 注入 T1 store（createSqliteStore 输出）→ 共享模式。
 *        共享模式 fail-closed：后端构造/操作错误直接传播——绝不静默退化为
 *        「各自独立窗口」放低多实例安全（Sprint 6 规划约束 #1）。
 * @param {number} [opts.retentionMs] 时间窗口保留期（默认 2×信封新鲜度窗口 10min）。
 *        保留期 ≥ 新鲜度窗口即可保证安全：过旧重放即使被淘汰也会被 timestamp_expired 拒。
 * @returns {{ record(key:string)=>boolean, has(key:string)=>boolean, size:number,
 *            clear():void, backendType:string, degraded:boolean, instanceFamilyId():string }}
 */
export function createReplayStore({ file = null, maxEntries = 10000, store = null, retentionMs = 2 * DEFAULT_MAX_AGE_MS } = {}) {
  let backend = store || null;
  let degraded = false;

  if (!backend) {
    try {
      backend = createLocalStore({ file });
    } catch (err) {
      // 单机 legacy 容忍（INV-009 已文档化）：replay 文件损坏仅降级「重放检测粒度」，
      // 验签/身份安全不受影响（各自独立 fail-closed）。显式告警 + 自愈重建；
      // 自愈失败（如目录只读）→ 本会话纯内存窗口。共享模式不走此路径——
      // 注入 store 的构造错误由调用方 fail-closed 处理，不在此吞掉。
      process.stderr.write(`[replay-store] WARNING: replay state file corrupted — replay-detection granularity degraded (signature/identity unaffected): ${err.message}\n`);
      degraded = true;
      if (file) {
        try {
          unlinkSync(file); // 自愈：移除损坏文件，下次落盘重建（与旧实现"首条记录覆写"等价）
          backend = createLocalStore({ file });
        } catch {
          backend = createLocalStore(); // 纯内存（本会话不持久化）
        }
      } else {
        backend = createLocalStore();
      }
    }
  }

  const keyOf = (k) => REPLAY_PREFIX + k;

  function enforceCapacity() {
    if (backend.keys(REPLAY_PREFIX).length <= maxEntries) return;
    backend.purgeExpired(Date.now() - retentionMs); // 先清过期（绝对时间，重启不丢语义）
    if (backend.keys(REPLAY_PREFIX).length > maxEntries) {
      backend.evictOldest(REPLAY_PREFIX, maxEntries); // 仍超 → 硬上限 FIFO（基线语义）
    }
  }

  return {
    backendType: backend.type,
    degraded,
    instanceFamilyId: backend.instanceFamilyId, // 审计对账：哪些实例共享同一重放窗口
    record(key) {
      const { claimed } = backend.claim(keyOf(key), { ts: Date.now() });
      if (claimed) enforceCapacity();
      return claimed;
    },
    has(key) {
      return backend.has(keyOf(key));
    },
    get size() {
      return backend.keys(REPLAY_PREFIX).length;
    },
    clear() {
      for (const k of backend.keys(REPLAY_PREFIX)) backend.delete(k);
    },
  };
}

/**
 * inbound 验签中间层。
 * @param {object} params
 * @param {object} params.directory service identity 目录（createIdentityDirectory 输出）
 * @param {string} params.self 本服务的身份（envelope.target 必须等于它，防跨服务重放）
 * @param {object} [params.replayStore] createReplayStore 输出（缺省则不做重放检测）
 * @param {number} [params.maxAgeMs] 时间新鲜度窗口（默认 5 分钟）
 * @returns {(body: any) => { ok: boolean, error?: string, reason?: string, identity?: string, payload?: any }}
 */
export function createInboundVerifier({ directory, self, replayStore = null, maxAgeMs = DEFAULT_MAX_AGE_MS }) {
  if (!directory || typeof directory.resolve !== 'function') {
    throw new Error('createInboundVerifier: directory with resolve() is required');
  }
  if (!self || typeof self !== 'string') {
    throw new Error('createInboundVerifier: self (this service identity) is required — target check prevents cross-service replay (RFC §2)');
  }

  return function verifyRequest(body) {
    // 发送侧（createHttpTransport + messageSecurity）统一包装为 { envelope }。
    if (!body || typeof body !== 'object' || !body.envelope) {
      return { ok: false, error: 'missing_envelope', reason: 'message security enabled: unsigned request rejected (fail-closed)' };
    }
    const envelope = body.envelope;
    // 跨服务重放防护（RFC §2 目标错误投递）：target 入签名只防篡改，不防
    // 「合法签名的消息被原样转发给另一个服务」。接收方必须校验 target === self，
    // 否则发给 service-b 的信封可在 service-c 的 replay store（未见过该 nonce）重放。
    if (envelope.target !== self) {
      return { ok: false, error: 'wrong_target', reason: `envelope targets '${envelope.target}', not this service '${self}' (cross-service replay rejected)` };
    }
    const identity = directory.resolve(envelope.sender);
    if (!identity) {
      return { ok: false, error: 'unknown_identity', reason: `sender '${envelope.sender}' is not a registered service identity` };
    }
    if (typeof identity.verifier !== 'function') {
      return { ok: false, error: 'no_verifier_for_identity', reason: `identity '${envelope.sender}' has no verifier configured` };
    }
    const res = verifyMessageEnvelope({ envelope, verifier: identity.verifier, replayGuard: replayStore, maxAgeMs, now: Date.now() });
    if (!res.ok) return { ok: false, error: res.error, reason: res.error };
    return { ok: true, identity: envelope.sender, payload: envelope.payload };
  };
}

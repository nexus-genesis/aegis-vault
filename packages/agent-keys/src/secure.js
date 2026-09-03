/**
 * Aegis Vault - Memory Hygiene Utilities
 * 内存卫生工具：secureZero + ShardedSecret
 *
 * ═══════════════════════════════════════════════════════════════════════
 *  SECURITY BOUNDARY DECLARATION — 物理攻击防御边界（请勿删改）
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  ┌────────────────────────────────────────────────────────────────┐
 *  │  本软件层（agent-keys Package）能力边界                         │
 *  ├────────────────────────────────────────────────────────────────┤
 *  │                                                                │
 *  │  W2-2: 物理攻击防御边界                                        │
 *  │  ──────────────────────────                                    │
 *  │  本包不防御以下物理攻击向量（属于 TEE 域）：                    │
 *  │                                                                │
 *  │  1. DMA 攻击（PCIe/Thunderbolt 直接内存访问）                  │
 *  │     → 缓解：IOMMU + VT-d + 物理端口禁用                       │
 *  │     → TEE 方案：Nitro Enclaves / SEV-SNP 的内存隔离            │
 *  │                                                                │
 *  │  2. 冷启动攻击（RAM 残留数据恢复）                              │
 *  │     → 缓解：全盘加密 + 快速关机（<5min 窗口）                 │
 *  │     → TEE 方案：SEV-SNP 内存加密（on-die AES）                 │
 *  │                                                                │
 *  │  3. 硬件探针（JTAG/SWD 调试接口读内存）                        │
 *  │     → 缓解：eFuse 熔断调试接口 + 安全启动链                   │
 *  │                                                                │
 *  │  4. 物理芯片剥离（直接读 DRAM 颗粒）                            │
 *  │     → 无缓解（此级攻击者已超出软件防御范围）                   │
 *  │     → 终极方案：HSM / 硬件钱包冷存储                          │
 *  │                                                                │
 *  │  本软件层实际覆盖的威胁象限：                                    │
 *  │  ┌──────────────┬──────────────────┬──────────────────┐       │
 *  │  │              │ 软件攻击         │ 物理攻击         │       │
 *  │  ├──────────────┼──────────────────┼──────────────────┤       │
 *  │  │ 运行时内存   │ ShardedSecret    │ ❌ 需 TEE        │       │
 *  │  │              │ + secureZero     │                  │       │
 *  │  ├──────────────┼──────────────────┼──────────────────┤       │
 *  │  │ 持久化存储   │ 加密信封(AES)    │ ❌ 需 HSM        │       │
 *  │  │              │ + PBKDF2         │                  │       │
 *  │  ├──────────────┼──────────────────┼──────────────────┤       │
 *  │  │ 进程间       │ Signer 子进程    │ ❌ 需 TEE        │       │
 *  │  │              │ + IPC 隔离       │                  │       │
 *  │  └──────────────┴──────────────────┴──────────────────┘       │
 *  │                                                                │
 *  │  结论：本模块的目标是「缩小暴露窗口 + 提高攻击成本」，          │
 *  │        不是「绝对消除内存残留」。绝对承诺属于 TEE 的定义域。    │
 *  ═══════════════════════════════════════════════════════════════════
 */

import crypto from 'crypto';

/**
 * Deterministically overwrite the contents of one or more buffers.
 * 确定性覆写 Buffer 内容（不依赖 GC，立即生效）。
 *
 * Accepts Buffer / Uint8Array. Fills the underlying ArrayBuffer region
 * owned by each view. Silently skips null/undefined entries so callers
 * can pass optional values without branching.
 *
 * @param {...(Buffer|Uint8Array|null|undefined)} bufs
 * @returns {void}
 */
export function secureZero(...bufs) {
  for (const buf of bufs) {
    if (buf == null) continue;
    if (Buffer.isBuffer(buf) || buf instanceof Uint8Array) {
      try {
        buf.fill(0);
      } catch {
        // Read-only or detached views — nothing we can overwrite.
        // 非常规状态（detached ArrayBuffer），静默跳过。
      }
    }
  }
}

/** Validate a candidate shard/secret buffer is a non-empty byte buffer. */
function assertBytes(value, name) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Buffer or Uint8Array`);
  }
  if (value.length === 0) {
    throw new RangeError(`${name} must not be empty`);
  }
}

/**
 * ShardedSecret — in-memory secret splitting (XOR 2-of-2).
 * 内存分片存储：明文密钥不以连续形态驻留内存。
 *
 * Design:
 *   shardA = random(len(secret))
 *   shardB = secret XOR shardA
 *   → 两个分片独立存放（不连续内存区域）
 *   → 任一分片单独不泄露任何信息（信息论安全的一次一密结构）
 *   → reassemble = shardA XOR shardB（仅在签名瞬间执行，用完立即清零）
 *
 * Threat model addressed:
 *   内存 dump / core dump 攻击者必须先定位两个不连续分片并正确
 *   组合，才能还原密钥。相比单一连续 Buffer，提取难度显著提高。
 *
 * NOT addressed (see boundary statement at top of file):
 *   物理内存读取、库内部副本、swap/core 落盘。
 */
export class ShardedSecret {
  /**
   * Shard a secret immediately. The input buffer is zeroed after sharding
   * so the caller's copy does not linger.
   * @param {Buffer|Uint8Array} secret
   */
  constructor(secret) {
    assertBytes(secret, 'secret');
    const len = secret.length;
    const shardA = crypto.randomBytes(len);
    const shardB = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      shardB[i] = secret[i] ^ shardA[i];
    }
    // Immediately destroy the caller's plaintext copy.
    secureZero(secret);
    this._shardA = shardA;
    this._shardB = shardB;
    this._length = len;
  }

  /** Rebuild shards from persisted/serialized parts (e.g. encrypted envelope). */
  static fromShards(shardA, shardB) {
    assertBytes(shardA, 'shardA');
    assertBytes(shardB, 'shardB');
    if (shardA.length !== shardB.length) {
      throw new RangeError('Shard length mismatch');
    }
    const instance = Object.create(ShardedSecret.prototype);
    instance._shardA = Buffer.from(shardA);
    instance._shardB = Buffer.from(shardB);
    instance._length = shardA.length;
    return instance;
  }

  /** Byte length of the encapsulated secret. */
  get length() {
    return this._length;
  }

  /**
   * Transient-use pattern — the recommended way to consume the secret.
   * 瞬时使用模式（推荐）：明文仅在回调执行期间存在。
   *
   * The secret is reassembled, handed to `fn`, then deterministically
   * zeroed in a finally block — even if `fn` throws. The assembled
   * plaintext NEVER outlives the callback invocation.
   *
   * CONTRACT: `fn` must not retain or leak the buffer it receives
   * (no storing in closures, no async escapes beyond the call).
   *
   * @template T
   * @param {(secret: Buffer) => T} fn
   * @returns {T}
   */
  use(fn) {
    if (typeof fn !== 'function') {
      throw new TypeError('use() requires a callback function');
    }
    if (this.isDestroyed) {
      throw new Error('ShardedSecret destroyed — key material no longer available');
    }
    const secret = this._reassemble();
    try {
      return fn(secret);
    } finally {
      secureZero(secret);
    }
  }

  /**
   * Reassemble the plaintext secret. CALLER MUST call secureZero() on the
   * result when done — prefer use() which handles this automatically.
   * @returns {Buffer} plaintext secret (caller-managed lifetime)
   */
  _reassemble() {
    const out = Buffer.alloc(this._length);
    for (let i = 0; i < this._length; i++) {
      out[i] = this._shardA[i] ^ this._shardB[i];
    }
    return out;
  }

  /**
   * Export shards for persistence (e.g. feed each shard into a separate
   * encryption envelope). Exported copies are fresh buffers; the in-memory
   * shards are untouched.
   * @returns {{ shardA: Buffer, shardB: Buffer }}
   */
  exportShards() {
    return {
      shardA: Buffer.from(this._shardA),
      shardB: Buffer.from(this._shardB)
    };
  }

  /**
   * Destroy all shard material. Idempotent; the instance is unusable after.
   * 销毁全部分片（幂等，调用后实例不可再用）。
   */
  destroy() {
    secureZero(this._shardA, this._shardB);
    this._shardA = null;
    this._shardB = null;
    this._length = -1;
  }

  /** Whether this instance still holds usable shards. */
  get isDestroyed() {
    return this._shardA === null;
  }
}

/**
 * Disable core dumps for the current process (best effort).
 * Best effort: on platforms where setrlimit is unavailable this is a no-op.
 * @returns {boolean} true if applied
 */
export function disableCoreDumps() {
  try {
    if (typeof process.setrlimit === 'function') {
      process.setrlimit('core', { soft: 0, hard: 0 });
      return true;
    }
  } catch {
    // Windows / restricted environments — no-op.
  }
  return false;
}

export default {
  secureZero,
  ShardedSecret,
  disableCoreDumps
};

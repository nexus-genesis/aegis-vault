/**
 * service-identity.js — Service Identity 目录 (Sprint 4 T1.5)
 *
 * did / agentId → { publicKey, algorithm, verifier } 的权威解析源。
 * 供 createInboundVerifier 解析 sender 身份；resolve 失败 → unknown_identity（fail-closed）。
 *
 * 设计：
 *   - 身份在进程启动时注入登记（operator 配置）；verifier 为注入式，不绑定算法，
 *     生产可接 Dilithium2 / Ed25519 / EVM（与 message-security.js 同一可插拔原则）。
 *   - 内存目录（P1 范围）；未来可后接链上 PQC 身份注册表（RFC P2 路线）。
 *   - list() 只暴露公钥元数据，绝不暴露 verifier 实现细节。
 */
export function createIdentityDirectory() {
  const registry = new Map(); // id -> { id, publicKey, algorithm, verifier, registeredAt }

  return {
    /**
     * 登记一个服务身份。
     * @param {object} params
     * @param {string} params.id 服务身份（agentId / did）
     * @param {string} params.publicKey 公钥（hex / base64，校验用）
     * @param {string} [params.algorithm='ed25519'] 签名算法标识
     * @param {(bytes: Uint8Array, signature: string) => boolean} params.verifier 注入式验签函数
     */
    register({ id, publicKey, algorithm = 'ed25519', verifier }) {
      if (!id || typeof id !== 'string') throw new Error('registerIdentity: id is required');
      if (!publicKey || typeof publicKey !== 'string') throw new Error('registerIdentity: publicKey is required');
      if (typeof verifier !== 'function') throw new Error('registerIdentity: verifier (injectable signature check) is required');
      registry.set(id, { id, publicKey, algorithm, verifier, registeredAt: Date.now() });
      return { ok: true, id };
    },

    /**
     * 解析身份。未登记 → null（上层据此 fail-closed 拒绝）。
     * @param {string} id
     * @returns {object|null} { id, publicKey, algorithm, verifier, registeredAt }
     */
    resolve(id) {
      return registry.get(id) ?? null;
    },

    /** 公开身份清单（不含 verifier 实现）。 */
    list() {
      return [...registry.values()].map(({ id, publicKey, algorithm, registeredAt }) => ({ id, publicKey, algorithm, registeredAt }));
    },

    get size() {
      return registry.size;
    },
  };
}

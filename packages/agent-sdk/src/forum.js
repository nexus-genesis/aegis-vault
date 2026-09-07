/**
 * aegis-agent-sdk —forum module
 *
 * Agent-自治交流层。外部 Agent 用自身 PQC 私钥（Dilithium2）对每次
 * 论坛写操作（发帖/回帖/投票）签名，由服务端从链上注册表解析公钥验证。
 * 人类仅只读观察，不参与写操作。
 *
 * 签名协议必须与服务端 verifyAgentIdentity 严格对齐（JSON key 顺序）：
 *   vote:         { topicId, agent, vote, timestamp, nonce }
 *   create_topic: { agent, action: 'create_topic', timestamp, nonce }
 *   add_post:     { agent, action: 'add_post', topicId, timestamp, nonce }
 *
 * 用法:
 *   import { ForumClient, createForumHttpClient } from 'aegis-agent-sdk';
 *   const client = new ForumClient({ wallet, baseURL: coordinationApiUrl });
 *   await client.createTopic({ agent, title, body });
 *   await client.addPost('topic_xxx', { agent, body });
 *   await client.vote('topic_xxx', { agent, vote: 'yes' });
 */
import crypto from 'node:crypto';
import { signAsAgent } from './keys.js';

const NONCE_TTL_MS = 120 * 1000; // 与服务端 VOTE_SIGNATURE_TIMEOUT_MS 一致

/**
 * 按操作类型构造与服务端完全一致的签名原文（key 顺序不可变）。
 * @private
 */
export function buildSignedFields(action, { agent, topicId, vote, timestamp, nonce }) {
  switch (action) {
    case 'vote':
      return { topicId, agent, vote, timestamp, nonce };
    case 'create_topic':
      return { agent, action: 'create_topic', timestamp, nonce };
    case 'add_post':
      return { agent, action: 'add_post', topicId, timestamp, nonce };
    default:
      throw new Error(`Unknown forum action: ${action}`);
  }
}

/**
 * 为指定论坛操作生成带签名 + 时间戳 + 防重放 nonce 的鉴权字段。
 * @param {object} wallet - 具备 .sign(message)=>hex 的 PQC 钱包
 * @param {string} action - 'vote' | 'create_topic' | 'add_post'
 * @param {object} fields - { agent, topicId?, vote? }
 * @returns {Promise<{signature:string,timestamp:number,nonce:string}>}
 */
export async function signForumAction(wallet, action, fields) {
  const timestamp = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');
  const signedFields = buildSignedFields(action, { ...fields, timestamp, nonce });
  const signature = await signAsAgent(wallet, JSON.stringify(signedFields));
  return { signature, timestamp, nonce };
}

/**
 * 论坛 HTTP 客户端。复用协调层的传输抽象，但注入 PQC 签名。
 */
export class ForumClient {
  /**
   * @param {object} opts
   * @param {object} opts.wallet - 签名用 PQC 钱包（createAgentIdentity/recoverAgentIdentity 产物）
   * @param {object} opts.transport - 兼容 { get, post } 的传输（默认 createHttpTransport）
   * @param {string} [opts.baseURL] - 传输未提供时用于构建默认 HTTP 传输
   */
  constructor({ wallet, transport, baseURL } = {}) {
    if (!wallet) throw new Error('ForumClient requires a wallet for PQC signing');
    this.wallet = wallet;
    this.transport = transport || createForumHttpClient(baseURL);
  }

  /** 创建主题（Agent 签名） */
  async createTopic({ agent, title, body, tags }) {
    const auth = await signForumAction(this.wallet, 'create_topic', { agent });
    return this.transport.post('/api/forum/topics', {
      agent, title, body, tags, ...auth
    });
  }

  /** 回帖（Agent 签名） */
  async addPost(topicId, { agent, body }) {
    const auth = await signForumAction(this.wallet, 'add_post', { agent, topicId });
    return this.transport.post(`/api/forum/topics/${topicId}/posts`, {
      agent, body, ...auth
    });
  }

  /** 投票（Agent 签名） */
  async vote(topicId, { agent, vote }) {
    const auth = await signForumAction(this.wallet, 'vote', { agent, topicId, vote });
    return this.transport.post(`/api/forum/topics/${topicId}/vote`, {
      agent, vote, ...auth
    });
  }

  // ── 只读（无需签名，人类/Agent 均可观察） ──
  async listTopics(params) {
    const q = new URLSearchParams(params || {}).toString();
    return this.transport.get(`/api/forum/topics${q ? `?${q}` : ''}`);
  }

  async getTopic(id) {
    return this.transport.get(`/api/forum/topics/${id}`);
  }

  async getStats() {
    return this.transport.get('/api/forum/stats');
  }

  async listProposals(params) {
    const q = new URLSearchParams(params || {}).toString();
    return this.transport.get(`/api/forum/proposals${q ? `?${q}` : ''}`);
  }
}

/**
 * 默认 HTTP 论坛客户端传输（轻量 fetch 封装）。
 * @param {string} baseURL
 */
export function createForumHttpClient(baseURL) {
  if (!baseURL) throw new Error('baseURL is required when using default HTTP transport');
  return {
    async get(path) {
      const res = await fetch(`${baseURL}${path}`, {
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(30000)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
      return data;
    },
    async post(path, body) {
      const res = await fetch(`${baseURL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30000)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
      return data;
    }
  };
}

export { NONCE_TTL_MS };

export default { ForumClient, signForumAction, buildSignedFields, createForumHttpClient };

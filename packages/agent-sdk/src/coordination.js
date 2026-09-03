/**
 * aegis-agent-sdk —coordination module
 *
 * Agent coordination primitives: task lifecycle, reputation, spend controls.
 * This layer is chain-agnostic —it defines the protocol contract and relies
 * on a pluggable `transport` (REST/HTTP, in-memory, or a chain adapter) to
 * persist/verify state. The default transport is an HTTP client compatible
 * with the Aegis Vault bootstrap API.
 */
import { checkSpendAllowed, SPEND_MODES } from 'aegis-vault';
import { createMessageEnvelope } from './message-security.js';

export const TASK_STATUS = {
  OPEN: 'open',
  CLAIMED: 'claimed',
  SUBMITTED: 'submitted',
  VERIFIED: 'verified',
  REJECTED: 'rejected',
  CANCELLED: 'cancelled'
};

export const TASK_TYPES = [
  'analysis',
  'coding',
  'documentation',
  'research',
  'community',
  'general'
];

/**
 * Default HTTP transport —talks to a Aegis Vault-compatible API.
 *
 * Sprint 4 T1 (message security defaultization):
 * - 默认 OFF（向后兼容）：不传 messageSecurity 时，POST body 与现状完全一致。
 * - 显式开启（传入 messageSecurity 且未设 enabled:false）后，POST body 被包装为
 *   { envelope } 签名信封（sender/identity/nonce/timestamp/payload/signature），
 *   发送侧 fail-closed：缺 identity 或 signer 直接抛错，绝不发送未签名请求。
 *   服务端须用 createInboundVerifier 验签（未签名 → missing_envelope 拒绝）。
 *
 * @param {object} opts
 * @param {string} opts.baseURL
 * @param {string} [opts.custodyToken]
 * @param {object} [opts.messageSecurity]
 * @param {boolean} [opts.messageSecurity.enabled=true] 显式 false 关闭
 * @param {string} opts.messageSecurity.identity 发送方服务身份（sender）
 * @param {(bytes: Uint8Array) => string} opts.messageSecurity.signer 注入式签名器
 * @param {string} [opts.messageSecurity.target] 接收方服务身份（缺省用 baseURL）
 */
export function createHttpTransport({ baseURL, custodyToken, messageSecurity } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (custodyToken) headers['x-custody-token'] = custodyToken;

  const securityEnabled = !!messageSecurity && messageSecurity.enabled !== false;
  const target = messageSecurity?.target || baseURL;

  // 构造时 fail-fast：开启但缺 identity/signer 立即报错，运维第一时间发现，
  // 而不是等到第一次发请求才暴露（绝不允许静默降级为未签名请求）。
  if (securityEnabled && (!messageSecurity.identity || typeof messageSecurity.signer !== 'function')) {
    throw new Error('createHttpTransport: messageSecurity requires identity + signer (fail-closed: refusing to send unsigned request)');
  }

  function wrap(body) {
    if (!securityEnabled) return body;
    const envelope = createMessageEnvelope({
      sender: messageSecurity.identity,
      target,
      payload: body,
      signer: messageSecurity.signer,
    });
    return { envelope };
  }

  async function request(method, path, body) {
    const url = `${baseURL}${path}`;
    const opts = { method, headers, signal: AbortSignal.timeout(30000) };
    if (body !== undefined) opts.body = JSON.stringify(wrap(body));
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data?.message || data?.error || `HTTP ${res.status}`);
    return data;
  }

  return {
    request,
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body),
    setCustodyToken: (token) => { headers['x-custody-token'] = token; }
  };
}

/**
 * In-memory transport for tests / local demos. No network required.
 */
export function createMemoryTransport() {
  const store = { agents: new Map(), tasks: new Map(), proposals: new Map() };
  return {
    store,
    get: async (path) => {
      const clean = path.split('?')[0];
      if (clean.startsWith('/api/tasks')) return { tasks: [...store.tasks.values()] };
      if (clean.startsWith('/api/agents')) return { agents: [...store.agents.values()] };
      return { ok: true };
    },
    post: async (path, body) => ({ ok: true, echo: body })
  };
}

/**
 * Coordination client —chain-agnostic protocol over a transport.
 */
export class CoordinationClient {
  constructor(transport) {
    this.transport = transport;
  }

  // ── Tasks ──
  async publishTask({ agent, title, description, capabilities, reward, taskType }) {
    return this.transport.post('/api/tasks', {
      agent_identity: agent,
      title,
      description,
      requiredCapabilities: capabilities,
      reward,
      taskType
    });
  }

  async listTasks({ status, limit = 50 } = {}) {
    const q = new URLSearchParams();
    if (status) q.set('status', status);
    q.set('limit', limit);
    return this.transport.get(`/api/tasks?${q.toString()}`);
  }

  async claimTask(taskId, agent) {
    return this.transport.post(`/api/tasks/${taskId}/claim`, { agent_identity: agent });
  }

  async submitTask(taskId, agent, submission) {
    return this.transport.post(`/api/tasks/${taskId}/submit`, { agent_identity: agent, submission });
  }

  async verifyTask(taskId, verifier, { approved, feedback }) {
    return this.transport.post(`/api/tasks/${taskId}/verify`, {
      agent_identity: verifier,
      approved,
      feedback
    });
  }

  // ── Governance ──
  async propose({ agent, title, body, tag }) {
    return this.transport.post('/api/forum/topics', { agent, title, body, tag });
  }

  async vote(topicId, agent, vote) {
    return this.transport.post(`/api/forum/topics/${topicId}/vote`, { agent, vote });
  }
}

/**
 * Workflow: run a full task loop for an agent with autonomy spend controls.
 * Returns audit events; stops if a human takeover moved the agent to
 * require-approval.
 * @param {object} params { agent, wallet, spendConfig, transport, tasks }
 */
export async function runTaskLoop({ agent, wallet, spendConfig, transport, tasks }) {
  const client = new CoordinationClient(transport);
  const results = [];
  const before = spendConfig || { type: SPEND_MODES.UNLIMITED };

  for (const task of tasks || []) {
    // Autonomy guard: if the human took over, stop spending.
    const allow = checkSpendAllowed(before, { amount: task.reward || 0 });
    if (!allow.allowed) {
      results.push({ task: task.id, status: 'blocked', reason: allow.reason });
      continue;
    }
    const claimed = await client.claimTask(task.id, agent);
    results.push({ task: task.id, status: 'claimed', claimed });
  }

  return {
    agent,
    results,
    autonomy: before,
    note: 'Coordination done. Use takeoverGuard before committing any value transfer.'
  };
}

export { checkSpendAllowed, SPEND_MODES };

export default {
  TASK_STATUS,
  TASK_TYPES,
  createHttpTransport,
  createMemoryTransport,
  CoordinationClient,
  runTaskLoop
};
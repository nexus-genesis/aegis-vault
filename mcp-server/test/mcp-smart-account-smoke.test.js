/**
 * T4 — Testnet 冒烟 (Sprint 2.6 T4)
 *
 * 目标：不止 LocalChain（进程内临时链），而是验证链上路径跑在一条「独立链进程」上。
 * 环境无 anvil/ganache（见 packages/chain-eth/test/helpers/local-chain.mjs 注释），
 * 因此把 LocalChain 作为独立 OS 子进程（独立 HTTP JSON-RPC，真实 wire 协议）拉起，
 * MCP server 通过 CHAIN_RPC_URL 走 testnet 配置面连接 —— 与接真实测试网是同一代码路径：
 *   createChainProvider(CHAIN_RPC_URL) → deploy/registerSession/executeFromAgent over the wire。
 *
 * 覆盖 Sprint 2.6 生产化收口的 5 点：
 *   T1 部署配置标准化  → testnet 配置面 fail-closed 校验（缺 RPC / 缺 relayer key /
 *                        anvil 公钥拒绝 / owner=relayer 冲突 / production 缺 artifact）
 *   T2 链上状态持久化  → SMART_ACCOUNT_STATE_FILE 落盘：accountId→contractAddress、
 *                        sessionId、最近广播 txHash、当前链环境（chainUrl/profile）；
 *                        重启后 restore 到同一外部链（不重新部署）
 *   T2 Relayer/Owner 分层 → execute 只走 relayer（relayer nonce 增、owner nonce 不动）
 *   T3 错误归一化      → AmountExceedsPerTx / InvalidSignature / BadNonce 固定语义
 *   T4 独立进程冒烟    → 独立子进程 pid ≠ 本进程；setup 返回 chainUrl = 外部 RPC
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, __resetSmartAccountForTest } from '../src/server.js';
import { loadChainState } from '../src/chain-state-store.js';
import { buildChainEnvConfig } from '../src/chain-config.js';

// Sprint 5 T4: the SMART_ACCOUNT_SIMULATION_GATE=0 opt-out was removed —
// preview-first is the only path. Executes arm the gate via signed previews;
// over-ceiling intents surface as typed reverts at preview + fail-closed
// SimulationRequired at execute.

// ─── Testnet-profile fixtures (non-anvil, non-well-known operation keys) ──
// 这些是「仿真 testnet 运维私钥」：非 KNOWN_ANVIL_KEYS，owner ≠ relayer ≠ emergency。
const OWNER_PK = '0x' + 'a1'.repeat(32);
const EMERGENCY_PK = '0x' + 'a2'.repeat(32);
const RELAYER_PK = '0x' + 'a3'.repeat(32);

const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 'smoke-agent';
const AGENT_PK = '0x' + '11'.repeat(32);
const ISSUED_AT = Date.now() - 1000;
const EXPIRES_AT = Date.now() + 3600_000;

const WHITELIST = {
  allowedChains: ['ethereum'],
  allowedAssets: ['USDC'],
  allowedContracts: ['0xToken'],
  allowedMethods: ['transfer'],
  allowedRecipients: ['0xRecipient'],
};

const INTENT = {
  action: 'transfer',
  chain: 'ethereum',
  asset: 'USDC',
  amount: '25',
  recipient: '0xRecipient',
  contract: '0xToken',
  method: 'transfer',
  nonce: '1',
};

const SESSION_BINDING = { agentId: AGENT_ID, sessionId: SESSION_ID, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT };

const STATE_FILE = join(tmpdir(), `smoke-chain-state-${process.pid}-${Date.now()}.json`);

let server;
let client;
let clientTransport;
let serverTransport;
let chainChild = null;
let externalUrl = null;

/** 临时覆盖一组 env（undefined → 删除），结束后恢复。 */
function withEnv(patch, fn) {
  const saved = new Map();
  for (const k of Object.keys(patch)) saved.set(k, process.env[k]);
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined || v === null) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/**
 * 拉起一条独立链进程（独立 OS 进程 + 独立 HTTP JSON-RPC），预充值三个操作地址。
 * 进程就绪后在 stdout 打印 __SMOKE_CHAIN_URL__=<url>，随后常驻。
 */
function spawnSmokeChain() {
  const helperUrl = new URL('../../packages/chain-eth/test/helpers/local-chain.mjs', import.meta.url).href;
  const cwd = fileURLToPath(new URL('..', import.meta.url)); // mcp-server → 解析 ethers
  const code = `
import { createLocalChain } from ${JSON.stringify(helperUrl)};
import { ethers } from 'ethers';
const mk = (n) => process.env['SMOKE_KEY_' + n].toLowerCase();
const owner = new ethers.Wallet(mk('OWNER'));
const emergency = new ethers.Wallet(mk('EMERGENCY'));
const relayer = new ethers.Wallet(mk('RELAYER'));
const chain = await createLocalChain({ funded: [
  { address: owner.address, balance: 10n ** 18n },
  { address: emergency.address, balance: 10n ** 18n },
  { address: relayer.address, balance: 10n ** 18n },
]});
console.log('__SMOKE_CHAIN_URL__=' + chain.url);
const keep = setInterval(() => {}, 1 << 30);
process.on('SIGTERM', async () => { clearInterval(keep); await chain.stop(); process.exit(0); });
`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], {
    cwd,
    env: { ...process.env, SMOKE_KEY_OWNER: OWNER_PK, SMOKE_KEY_EMERGENCY: EMERGENCY_PK, SMOKE_KEY_RELAYER: RELAYER_PK },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('smoke chain spawn timeout (15s)'));
    }, 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/__SMOKE_CHAIN_URL__=(.+?)\r?\n/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, url: m[1].trim() });
      }
    });
    child.stderr.on('data', (d) => process.stderr.write(`[smoke-chain] ${d}`));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (!buf.includes('__SMOKE_CHAIN_URL__=')) reject(new Error(`smoke chain exited early code=${code}`));
    });
  });
}

async function callTool(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(res.content[0].text);
}

before(async () => {
  const { child, url } = await spawnSmokeChain();
  chainChild = child;
  externalUrl = url;

  // testnet 配置面 + 外部 RPC + 显式非 anvil 运维私钥 + 持久层启用。
  process.env.CHAIN_PROFILE = 'testnet';
  process.env.CHAIN_RPC_URL = externalUrl;
  process.env.CHAIN_OWNER_PK = OWNER_PK;
  process.env.CHAIN_EMERGENCY_PK = EMERGENCY_PK;
  process.env.CHAIN_RELAYER_PK = RELAYER_PK;
  process.env.SMART_ACCOUNT_STATE_FILE = STATE_FILE;

  __resetSmartAccountForTest();
  server = createServer();
  [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-smoke', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

after(async () => {
  await client?.close();
  await server?.close();
  __resetSmartAccountForTest();
  if (chainChild) chainChild.kill();
  if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE);
});

// ─────────────────────────────────────────────────────────────────────────
// T1 配置面 fail-closed（纯单元，不触发 server boot）
// ─────────────────────────────────────────────────────────────────────────
test('T4.1 testnet/production config fail-closed (unit)', () => {
  // 非 local 必须显式外部 RPC。
  withEnv({ CHAIN_RPC_URL: undefined }, () => {
    assert.throws(() => buildChainEnvConfig({ profile: 'testnet' }), (e) => e.code === 'CHAIN_RPC_URL_REQUIRED');
  });

  // 显式外部 RPC 必须显式提供 relayer 广播私钥（缺省回退 anvil 公钥 → 拒绝）。
  withEnv({ CHAIN_RPC_URL: 'http://127.0.0.1:9999', CHAIN_RELAYER_PK: undefined }, () => {
    assert.throws(() => buildChainEnvConfig({ profile: 'testnet' }), (e) => e.code === 'CHAIN_RELAYER_KEY_REQUIRED');
  });

  // 非 local 禁止众所周知 anvil 私钥。
  withEnv({
    CHAIN_RPC_URL: 'http://127.0.0.1:9999',
    CHAIN_RELAYER_PK: RELAYER_PK,
    CHAIN_OWNER_PK: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // anvil #0
  }, () => {
    assert.throws(() => buildChainEnvConfig({ profile: 'testnet' }), (e) => e.code === 'CHAIN_ANVIL_KEY_REJECTED');
  });

  // owner 与 relayer 必须严格分离（Sprint 2.6 T2 角色分层）。
  withEnv({ CHAIN_RPC_URL: 'http://127.0.0.1:9999', CHAIN_RELAYER_PK: OWNER_PK, CHAIN_OWNER_PK: OWNER_PK }, () => {
    assert.throws(() => buildChainEnvConfig({ profile: 'testnet' }), (e) => e.code === 'CHAIN_OWNER_RELAYER_COLLISION');
  });

  // production 必须显式 artifact 路径。
  withEnv({ CHAIN_RPC_URL: 'http://127.0.0.1:9999', CHAIN_RELAYER_PK: RELAYER_PK, CHAIN_OWNER_PK: OWNER_PK, SMART_ACCOUNT_ARTIFACT: undefined }, () => {
    assert.throws(() => buildChainEnvConfig({ profile: 'production' }), (e) => e.code === 'SMART_ACCOUNT_ARTIFACT_REQUIRED');
  });

  // 合法 testnet 配置通过。
  const ok = buildChainEnvConfig({ profile: 'testnet' });
  assert.equal(ok.profile, 'testnet');
  assert.equal(ok.useLocalChain, false);
  assert.equal(ok.rpcUrl, externalUrl);
});

// ─────────────────────────────────────────────────────────────────────────
// T4 独立进程冒烟：完整生命周期 + 分层 + 持久化 + 错误归一化
// ─────────────────────────────────────────────────────────────────────────
test('T4.2 external chain smoke: lifecycle + relayer/owner separation + persistence', async () => {
  const { addressForPrivateKey, signSmartAccountIntent } = await import('aegis-chain-eth');

  // ── 独立进程证明 ────────────────────────────────────────────────────────
  assert.ok(chainChild, 'independent chain process must be running');
  assert.notEqual(chainChild.pid, process.pid, 'chain must be a separate OS process');

  // ── setup（testnet 配置面 / 外部 RPC）───────────────────────────────────
  // T3.3 key isolation: testnet 配置面禁止经工具参数直传 owner/emergency 私钥 —
  // 由 CHAIN_OWNER_PK / CHAIN_EMERGENCY_PK env 注入（见 before()），不传参数。
  const setup = await callTool('smart_account_setup', {
    sessionId: SESSION_ID,
    agentId: AGENT_ID,
    agentEvmAddress: addressForPrivateKey(AGENT_PK),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    maxPerTx: '100',
    maxDaily: '500',
    ...WHITELIST,
  });
  assert.equal(setup.success, true, JSON.stringify(setup));
  assert.equal(setup.onChain, true);
  assert.equal(setup.chainUrl, externalUrl, 'setup must run against the external chain, not an in-process LocalChain');
  assert.match(setup.accountId, /^0x[0-9a-f]{40}$/);
  assert.equal(setup.contractAddress, setup.accountId);

  // ── estimate_loss before ────────────────────────────────────────────────
  const beforeLoss = await callTool('smart_account_estimate_loss', {});
  assert.equal(beforeLoss.success, true);
  assert.equal(beforeLoss.accountRemaining, '1000000');
  assert.equal(beforeLoss.sessionMaxLoss, '500');

  // ── preview（无签名 → 无伪裁决）─────────────────────────────────────────
  const preview = await callTool('smart_account_preview', { ...INTENT, nonce: 1 });
  assert.equal(preview.success, true, JSON.stringify(preview));
  assert.equal(preview.wouldExecute, null);
  assert.match(preview.digest, /^0x[0-9a-f]{64}$/);

  // ── execute（signed，经外部链广播）──────────────────────────────────────
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the exact digest with a signed preview.
  const armed = await callTool('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true, JSON.stringify(exec));
  assert.equal(exec.amount, '25');
  assert.match(exec.txHash, /^0x[0-9a-f]{64}$/);

  const afterLoss = await callTool('smart_account_estimate_loss', {});
  assert.equal(afterLoss.success, true);
  assert.equal(afterLoss.accountRemaining, '999975'); // 1M - 25
  assert.equal(afterLoss.sessionMaxLoss, '475'); // 500 - 25

  // ── T3 错误归一化：固定语义 error code over the wire ────────────────────
  // T4 迁移：超限在 preview 端出 typed revert（同一链上 hard-policy 路径）；
  // execute 端该 digest 无法 arm → 门禁层 SimulationRequired（不触碰 relayer）。
  const big = { ...INTENT, amount: '250', nonce: '2' };
  const signedBig = signSmartAccountIntent({ session: SESSION_BINDING, intent: big, privateKeyHex: AGENT_PK });
  const bigPrev = await callTool('smart_account_preview', { ...big, nonce: 2, signature: signedBig.signature });
  assert.equal(bigPrev.wouldExecute, false);
  assert.equal(bigPrev.reason, 'AmountExceedsPerTx');
  const bigExec = await callTool('smart_account_execute', { payload: signedBig.payload, signature: signedBig.signature });
  assert.equal(bigExec.success, false);
  assert.equal(bigExec.error, 'SimulationRequired');

  // 伪造签名：payload digest 与 armed 匹配 → 过门禁，链上验签 InvalidSignature。
  const forged = await callTool('smart_account_execute', {
    payload: signed.payload,
    signature: '0x' + '00'.repeat(65),
  });
  assert.equal(forged.success, false);
  assert.equal(forged.error, 'InvalidSignature');

  // 重放：armed digest 仍匹配 → 链上 BadNonce。
  const replay = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(replay.success, false);
  assert.equal(replay.error, 'BadNonce');

  // ── T2 Relayer/Owner 分层：execute 只走 relayer，owner 不兼任广播者 ──────
  const { JsonRpcProvider, Wallet } = await import('ethers');
  const prov = new JsonRpcProvider(externalUrl);
  const ownerAddr = new Wallet(OWNER_PK).address;
  const relayerAddr = new Wallet(RELAYER_PK).address;
  const ownerNonce = await prov.getTransactionCount(ownerAddr);
  const relayerNonce = await prov.getTransactionCount(relayerAddr);
  assert.ok(ownerNonce >= 2, `owner deployed + registered (nonce=${ownerNonce})`);
  assert.equal(relayerNonce, 1, `relayer broadcast exactly once (nonce=${relayerNonce})`);

  // ── T2 链上状态持久化：落盘 accountId→contractAddress / sessionId / txHash / 环境 ──
  // Sprint 6 T3：落盘为行级 store 格式——断言走语义层 loadChainState()（格式无关）。
  assert.ok(existsSync(STATE_FILE), 'state file must be written');
  const raw = loadChainState();
  assert.equal(raw.profile, 'testnet');
  assert.equal(raw.chainUrl, externalUrl);
  assert.ok(Array.isArray(raw.accounts) && raw.accounts.length === 1);
  const acc = raw.accounts[0];
  assert.equal(acc.accountId, setup.accountId);
  assert.equal(acc.contractAddress, setup.contractAddress);
  assert.equal(acc.currentSessionId, SESSION_ID);
  assert.ok(Array.isArray(acc.txHashes) && acc.txHashes.length >= 1, 'recent broadcast txHash must be persisted');
  assert.equal(acc.sessions[0].sessionId, SESSION_ID);
  assert.equal(acc.sessions[0].maxPerTx, '100');
  assert.equal(acc.sessions[0].maxDaily, '500');
});

// ─────────────────────────────────────────────────────────────────────────
// T2 重启恢复：持久化账户在外部链上恢复，不重新部署
// ─────────────────────────────────────────────────────────────────────────
test('T4.3 restart recovery: persisted account restored on the same external chain', async () => {
  const prev = loadChainState();
  assert.ok(prev.accounts.length >= 1, 'lifecycle test must have persisted an account first');
  const persistedAccountId = prev.accounts[0].accountId;

  // 模拟重启：清空内存 smartAccounts + 链环境，下一次调用重新 boot + restore。
  __resetSmartAccountForTest();

  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.success, true, JSON.stringify(est));
  // 恢复的是同一合约地址（不重新部署）。
  assert.equal(est.accountId, persistedAccountId, 'must reuse the persisted contract, not redeploy');
  // 链上已消费状态也在：说明恢复的 conn 真连到了外部链上同一个合约。
  assert.equal(est.accountRemaining, '999975');
  assert.equal(est.sessionMaxLoss, '475');

  // 恢复的账户仍可继续执行（非只读）：同一 nonce 1 已消费，换 nonce 3 通过预览语义。
  const { signSmartAccountIntent } = await import('aegis-chain-eth');
  const next = { ...INTENT, nonce: '3' };
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: next, privateKeyHex: AGENT_PK });

  // T4 preview-first: arm the restored account's gate for the new digest.
  const armed = await callTool('smart_account_preview', { ...next, nonce: 3, signature: signed.signature });
  assert.equal(armed.wouldExecute, true, JSON.stringify(armed));

  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true, JSON.stringify(exec));
  assert.equal(exec.amount, '25');
});

// ─────────────────────────────────────────────────────────────────────────
// Sprint 4 T2.1：重启恢复模拟窗口（simulationLog 持久化的端到端回归）
// T4 之后 gate 恒开（无 opt-out），此用例验证 T2.1 的核心承诺：
// arming 落盘 → 重启 → 窗口恢复（不丢、不重置、不过度放行）。
// ─────────────────────────────────────────────────────────────────────────
test('T2.1 restart keeps the armed simulation window (persisted + restored)', async () => {
  const { signSmartAccountIntent } = await import('aegis-chain-eth');

  // 重启 #1：从状态文件恢复账户（T4.3 已执行 nonce 3，这里用 nonce 4）。
  __resetSmartAccountForTest();
  const est = await callTool('smart_account_estimate_loss', {});
  assert.equal(est.success, true, JSON.stringify(est));

  // 签名 preview（arm）→ arming 随状态文件落盘。
  const intent = { ...INTENT, nonce: '4' };
  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent, privateKeyHex: AGENT_PK });
  const prev = await callTool('smart_account_preview', { ...intent, nonce: 4, signature: signed.signature });
  assert.equal(prev.wouldExecute, true, JSON.stringify(prev));

  // 重启 #2：内存 simulationLog 清空，只能靠状态文件恢复。
  __resetSmartAccountForTest();
  const est2 = await callTool('smart_account_estimate_loss', {});
  assert.equal(est2.success, true, JSON.stringify(est2));

  // 同一 digest：恢复的窗口放行（重启不丢 arming）。
  const exec = await callTool('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  assert.equal(exec.success, true, JSON.stringify(exec));

  // 反向验证：恢复的窗口只覆盖已模拟的 digest——不同 digest 仍 fail-closed。
  const other = { ...INTENT, nonce: '5' };
  const signedOther = signSmartAccountIntent({ session: SESSION_BINDING, intent: other, privateKeyHex: AGENT_PK });
  const blocked = await callTool('smart_account_execute', { payload: signedOther.payload, signature: signedOther.signature });
  assert.equal(blocked.success, false);
  assert.equal(blocked.error, 'SimulationRequired');
});

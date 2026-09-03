#!/usr/bin/env node
/**
 * Sprint 2.7 运营闭环演示 — 完整 execute 流程 + 日志/指标核验
 *
 * 拓扑（与生产部署一致）：
 *   [demo 客户端] --stdio MCP--> [独立 MCP server 进程] --JSON-RPC over HTTP--> [独立链进程]
 *
 *   1. 链：独立 OS 子进程跑 LocalChain（真实 wire JSON-RPC）。本机无 anvil/无测试网资金，
 *      这与接真实 testnet RPC 是同一代码路径（CHAIN_RPC_URL 外部模式）。
 *      → 若有真实测试网与已注资密钥，可直接：
 *        DEMO_CHAIN_RPC_URL=https://sepolia... DEMO_OWNER_PK=.. DEMO_EMERGENCY_PK=..
 *        DEMO_RELAYER_PK=.. node scripts/ops-smoke-demo.mjs
 *   2. MCP server：`node src/index.js` 作为独立 stdio 子进程拉起（生产入口），
 *      配置面 CHAIN_PROFILE=testnet；其 stderr（审计行 + 结构化日志）实时流入本终端。
 *   3. 流程：setup → preview → execute(成功) → estimate_loss → tx_status →
 *      execute 超限/重放/伪造签名（三类失败）→ audit → metrics。
 *   4. 核验：指标计数、审计字段、AUDIT_LOG_FILE 落盘、relayer/owner nonce 分层。
 */
import { spawn } from 'node:child_process';
import { readFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { addressForPrivateKey, signSmartAccountIntent } from 'aegis-chain-eth';
import { Wallet, JsonRpcProvider } from 'ethers';

const MCP_ROOT = fileURLToPath(new URL('..', import.meta.url)); // mcp-server/

// ─── 密钥面：默认为「仿真 testnet 运维密钥」（非 anvil 公钥，三角色分离）───
const OWNER_PK = process.env.DEMO_OWNER_PK || '0x' + 'a1'.repeat(32);
const EMERGENCY_PK = process.env.DEMO_EMERGENCY_PK || '0x' + 'a2'.repeat(32);
const RELAYER_PK = process.env.DEMO_RELAYER_PK || '0x' + 'a3'.repeat(32);
const EXTERNAL_RPC = process.env.DEMO_CHAIN_RPC_URL || null; // 真实测试网直连入口

const SESSION_ID = '0x' + 'ab'.repeat(32);
const AGENT_ID = 'ops-demo-agent';
const AGENT_PK = '0x' + '11'.repeat(32);
const ISSUED_AT = Date.now() - 1000;
const EXPIRES_AT = Date.now() + 3600_000;
const SESSION_BINDING = { agentId: AGENT_ID, sessionId: SESSION_ID, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT };
const INTENT = {
  action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
  recipient: '0xRecipient', contract: '0xToken', method: 'transfer', nonce: '1',
};

const STATE_FILE = join(tmpdir(), `ops-demo-state-${process.pid}-${Date.now()}.json`);
const AUDIT_FILE = join(tmpdir(), `ops-demo-audit-${process.pid}-${Date.now()}.jsonl`);

const checks = [];
let chainChild = null;
let client = null;
let rpcUrl = EXTERNAL_RPC;

function check(name, expected, actual) {
  const pass = JSON.stringify(expected) === JSON.stringify(actual);
  checks.push({ name, expected, actual, pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `  (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`}`);
  return pass;
}

function section(title) {
  console.log(`\n──── ${title} ${'─'.repeat(Math.max(2, 66 - title.length))}`);
}

/** 拉起独立链进程（真实 wire JSON-RPC；预充值三角色）。 */
function spawnSimulatedChain() {
  const helperUrl = new URL('../../packages/chain-eth/test/helpers/local-chain.mjs', import.meta.url).href;
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
    cwd: MCP_ROOT,
    env: { ...process.env, SMOKE_KEY_OWNER: OWNER_PK, SMOKE_KEY_EMERGENCY: EMERGENCY_PK, SMOKE_KEY_RELAYER: RELAYER_PK },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('chain spawn timeout')); }, 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/__SMOKE_CHAIN_URL__=(.+?)\r?\n/);
      if (m) { clearTimeout(timer); resolve({ child, url: m[1].trim() }); }
    });
    child.stderr.on('data', (d) => process.stderr.write(`[chain] ${d}`));
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

async function call(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(res.content[0].text);
}

async function main() {
  console.log('╔════════════════════════════════════════════════════════════════════╗');
  console.log('║  Sprint 2.7 运营闭环演示 — 独立链进程 + stdio MCP server + execute  ║');
  console.log('╚════════════════════════════════════════════════════════════════════╝');

  // ── 1. 链环境 ─────────────────────────────────────────────────────────
  if (!EXTERNAL_RPC) {
    console.log('\n[1/4] 拉起独立链进程（真实 HTTP JSON-RPC wire）…');
    const { child, url } = await spawnSimulatedChain();
    chainChild = child;
    rpcUrl = url;
  } else {
    console.log('\n[1/4] 使用外部 RPC（DEMO_CHAIN_RPC_URL）…');
  }
  console.log(`  chain rpc      : ${rpcUrl}`);
  console.log(`  chain pid      : ${chainChild ? chainChild.pid : 'external'}  (demo pid ${process.pid})`);
  console.log(`  owner / emergency / relayer : ${new Wallet(OWNER_PK).address.slice(0, 10)}… / ${new Wallet(EMERGENCY_PK).address.slice(0, 10)}… / ${new Wallet(RELAYER_PK).address.slice(0, 10)}…`);

  // ── 2. MCP server（生产 stdio 入口，独立进程）─────────────────────────
  console.log('\n[2/4] 启动 MCP server 子进程（node src/index.js，CHAIN_PROFILE=testnet）…');
  console.log('      其 stderr（[audit] 审计行 + 结构化日志）将实时输出在本终端 ↓');
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['src/index.js'],
    cwd: MCP_ROOT,
    env: {
      ...process.env,
      CHAIN_PROFILE: 'testnet',
      CHAIN_RPC_URL: rpcUrl,
      CHAIN_OWNER_PK: OWNER_PK,
      CHAIN_EMERGENCY_PK: EMERGENCY_PK,
      CHAIN_RELAYER_PK: RELAYER_PK,
      SMART_ACCOUNT_STATE_FILE: STATE_FILE,
      AUDIT_LOG_FILE: AUDIT_FILE,
    },
    stderr: 'inherit',
  });
  client = new Client({ name: 'ops-smoke-demo', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);
  console.log('  MCP server 就绪（stdio 握手完成）');

  // ── 3. 完整 execute 流程 ──────────────────────────────────────────────
  console.log('\n[3/4] 完整 execute 流程：');
  // T3.3 密钥隔离：owner/emergency 私钥经 CHAIN_OWNER_PK / CHAIN_EMERGENCY_PK env
  // 注入（见上方 StdioClientTransport env），绝不经工具参数传输。
  const setup = await call('smart_account_setup', {
    sessionId: SESSION_ID, agentId: AGENT_ID,
    agentEvmAddress: addressForPrivateKey(AGENT_PK),
    issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT,
    maxPerTx: '100', maxDaily: '500',
    allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xToken'],
    allowedMethods: ['transfer'], allowedRecipients: ['0xRecipient'],
  });
  console.log(`  setup        : success=${setup.success} onChain=${setup.onChain} account=${setup.accountId?.slice(0, 12)}…`);

  const preview = await call('smart_account_preview', { ...INTENT, nonce: 1 });
  console.log(`  preview      : wouldExecute=${preview.wouldExecute} digest=${preview.digest?.slice(0, 18)}…`);

  const signed = signSmartAccountIntent({ session: SESSION_BINDING, intent: INTENT, privateKeyHex: AGENT_PK });

  // Sprint 3 T1: transfer 为 required action，execute 前必须先经带签名成功 preview
  //（fail-closed 门禁）。先演示未 preview 直接被拦，再走正路。
  const gateBlocked = await call('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  console.log(`  execute(未模拟) : error=${gateBlocked.error}  ← simulation gate fail-closed`);

  const prevSigned = await call('smart_account_preview', { ...INTENT, nonce: 1, signature: signed.signature });
  console.log(`  preview(签名) : wouldExecute=${prevSigned.wouldExecute} sim=${prevSigned.simulation?.level}`);

  const exec = await call('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  console.log(`  execute      : success=${exec.success} status=${exec.status} txHash=${exec.txHash?.slice(0, 18)}…`);

  const est = await call('smart_account_estimate_loss', {});
  console.log(`  estimate_loss: accountRemaining=${est.accountRemaining} sessionMaxLoss=${est.sessionMaxLoss}`);

  const st = await call('smart_account_tx_status', { txHash: exec.txHash });
  console.log(`  tx_status    : onChain=${st.onChain.status} block=${st.onChain.blockNumber} gasUsed=${st.onChain.gasUsed}`);

  const big = signSmartAccountIntent({ session: SESSION_BINDING, intent: { ...INTENT, amount: '250', nonce: '2' }, privateKeyHex: AGENT_PK });
  // 超限在模拟阶段即被链上拒绝（wouldExecute=false → 该 digest 未成功模拟）。
  const prevBig = await call('smart_account_preview', { ...INTENT, amount: '250', nonce: 2, signature: big.signature });
  console.log(`  preview(超限) : wouldExecute=${prevBig.wouldExecute} reason=${prevBig.reason}`);
  // 未成功模拟的 digest 无法通过 gate → 链下拦截，不会浪费一笔注定失败的广播。
  const overLimit = await call('smart_account_execute', { payload: big.payload, signature: big.signature });
  console.log(`  execute(超限) : error=${overLimit.error}  ← 未成功模拟被 gate 拦（省 gas）`);

  const replay = await call('smart_account_execute', { payload: signed.payload, signature: signed.signature });
  console.log(`  execute(重放) : error=${replay.error}`);

  const forged = await call('smart_account_execute', { payload: signed.payload, signature: '0x' + '00'.repeat(65) });
  console.log(`  execute(伪造) : error=${forged.error}`);

  const audit = await call('smart_account_audit', { limit: 50 });
  const metrics = (await call('smart_account_metrics', {})).metrics;

  // ── 4. 核验 ───────────────────────────────────────────────────────────
  section('4/4 核验 — execute 流程结果');
  check('setup success/onChain', true, setup.success === true && setup.onChain === true);
  check('setup 走外部 RPC', rpcUrl, setup.chainUrl);
  check('preview 未签名 → wouldExecute=null', null, preview.wouldExecute);
  check('未模拟 execute → SimulationRequired (gate fail-closed)', 'SimulationRequired', gateBlocked.error);
  check('带签名 preview → wouldExecute=true (arms gate)', true, prevSigned.wouldExecute === true && prevSigned.simulation?.level === 'required');
  check('execute 成功 + status=confirmed', 'confirmed', exec.status);
  check('txHash 格式', true, /^0x[0-9a-f]{64}$/.test(exec.txHash || ''));
  check('accountRemaining = 1,000,000 - 25', '999975', est.accountRemaining);
  check('sessionMaxLoss = 500 - 25', '475', est.sessionMaxLoss);
  check('tx_status 链上重查 confirmed', 'confirmed', st.onChain.status);
  check('tx_status 带 blockNumber/gasUsed', true, /^\d+$/.test(String(st.onChain.blockNumber)) && /^\d+$/.test(String(st.onChain.gasUsed)));
  check('超限 preview → wouldExecute=false (AmountExceedsPerTx)', 'AmountExceedsPerTx', prevBig.reason);
  check('超限 execute → gate 拦截（未成功模拟，省 gas）', 'SimulationRequired', overLimit.error);
  check('重放 → BadNonce', 'BadNonce', replay.error);
  check('伪造签名 → InvalidSignature', 'InvalidSignature', forged.error);

  section('核验 — 审计日志（smart_account_audit + AUDIT_LOG_FILE）');
  const byTool = {};
  for (const e of audit.entries) byTool[e.tool] = (byTool[e.tool] || 0) + 1;
  check('setup 留痕 ×1', 1, byTool.smart_account_setup ?? 0);
  check('preview 留痕 ×3（无签名 + 成功 + 超限拒绝）', 3, byTool.smart_account_preview ?? 0);
  check('execute 留痕 ×5（gate 拦 2 + 成功 1 + 重放 1 + 伪造 1）', 5, byTool.smart_account_execute ?? 0);
  check('estimate_loss 留痕 ×1', 1, byTool.smart_account_estimate_loss ?? 0);
  const gatedAudit = audit.entries.find((e) => e.gate === 'simulation');
  check('gate 拦审记含 errorName=SimulationRequired', 'SimulationRequired', gatedAudit?.errorName);
  const okExec = audit.entries.find((e) => e.tool === 'smart_account_execute' && e.ok === true);
  check('成功 execute 审计含 txHash', true, !!okExec?.txHash);
  check('成功 execute 审计含 payloadDigest', true, /^0x[0-9a-f]{64}$/.test(okExec?.payloadDigest || ''));
  check('broadcaster = relayer（非 owner）', new Wallet(RELAYER_PK).address, okExec?.broadcaster);
  check('审计条目均含 ISO timestamp', true, audit.entries.every((e) => /^\d{4}-\d{2}-\d{2}T/.test(e.timestamp || '')));
  // Sprint 4 T2.2：execute 门禁首次策略评估记录 policy_change（无策略文件 →
  // previousFingerprint=null 初始事件），审计行数 10 → 11。
  const policyChange = audit.entries.find((e) => e.tool === 'policy_change');
  check('policy_change 初始事件（T2.2）previousFingerprint=null', true, !!policyChange && (policyChange.previousFingerprint === null || policyChange.previousFingerprint === undefined));
  check('AUDIT_LOG_FILE 落盘 11 条 JSON lines', 11, existsSync(AUDIT_FILE) ? readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).length : 0);

  section('核验 — 指标（smart_account_metrics）');
  const expect = {
    smart_account_setup_count: 1,
    smart_account_preview_count: 3,
    smart_account_execute_total: 3,
    smart_account_execute_success: 1,
    smart_account_execute_failed: 2,
    smart_account_simulation_blocked: 2,
    smart_account_revert_AmountExceedsPerTx: 1,
    smart_account_revert_BadNonce: 1,
    smart_account_revert_InvalidSignature: 1,
    smart_account_nonce_conflict: 1,
    smart_account_limit_rejected: 1,
  };
  for (const [k, v] of Object.entries(expect)) check(k, v, metrics[k] ?? 0);

  if (!EXTERNAL_RPC) {
    section('核验 — Relayer/Owner 分层（链上 nonce 实证）');
    const prov = new JsonRpcProvider(rpcUrl);
    const ownerNonce = await prov.getTransactionCount(new Wallet(OWNER_PK).address);
    const relayerNonce = await prov.getTransactionCount(new Wallet(RELAYER_PK).address);
    check('owner nonce = 2（仅部署+注册，未广播）', 2, ownerNonce);
    check('relayer nonce = 1（唯一广播者）', 1, relayerNonce);
  }

  section('审计文件样例（AUDIT_LOG_FILE 末 3 行）');
  const lines = readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
  for (const l of lines.slice(-3)) console.log(`  ${l}`);

  // ── 结果 ──────────────────────────────────────────────────────────────
  const failed = checks.filter((c) => !c.pass).length;
  console.log(`\n${'═'.repeat(72)}`);
  console.log(`  演示结果：${checks.length - failed}/${checks.length} 项核验通过${failed ? `，${failed} 项失败` : ''}`);
  console.log(`  状态文件 : ${STATE_FILE}（已清理）`);
  console.log(`  审计文件 : ${AUDIT_FILE}（已清理，内容见上方样例）`);
  console.log(`${'═'.repeat(72)}`);
  process.exitCode = failed ? 1 : 0;
}

// 总看门狗：任何挂起都不允许遗留子进程。
const watchdog = setTimeout(() => {
  console.error('\n[watchdog] 90s 超时，强制退出');
  try { chainChild?.kill(); } catch { /* noop */ }
  process.exit(1);
}, 90000);
watchdog.unref?.();

main()
  .catch((err) => {
    console.error('\n[demo] 失败：', err?.stack || err);
    process.exitCode = 1;
  })
  .finally(async () => {
    try { await client?.close(); } catch { /* noop */ }
    try { chainChild?.kill(); } catch { /* noop */ }
    for (const f of [STATE_FILE, AUDIT_FILE]) {
      try { if (existsSync(f)) unlinkSync(f); } catch { /* noop */ }
    }
    clearTimeout(watchdog);
  });

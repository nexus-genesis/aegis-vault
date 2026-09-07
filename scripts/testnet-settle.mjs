/**
 * testnet-settle.mjs — Stage 1「真实结算 execute」：公共测试网端到端结算
 *
 * 与 examples/smart-account-e2e.mjs 的区别：
 *   - 拒绝 LocalChain / anvil 默认私钥（真金白银的测试网 ETH，必须显式提供钥匙）
 *   - 先跑预检（RPC 连通 / chainId / 三个角色余额 / 合约 artifact），缺一项
 *     直接给出可操作的失败原因，而不是跑到一半断网
 *   - 全流程：deploy → registerSession → agent 离线出签 → 链上 digest 交叉
 *     校验 → relayer 广播 executeFromAgent → 链上状态断言 → INV-005/007
 *     防御性拒绝路径（simulate，无副作用）
 *
 * 运行（完整步骤见 docs/runbook/TESTNET-SETTLEMENT.md）：
 *   CHAIN_RPC_URL=https://sepolia.infura.io/v3/<key> \
 *   OWNER_PK=0x… EMERGENCY_PK=0x… RELAYER_PK=0x… AGENT_PK=0x… \
 *   node scripts/testnet-settle.mjs
 *
 * 私钥仅存在于进程内，永不落盘、永不打印。
 */
import crypto from 'node:crypto';
import { ethers } from 'ethers';
import {
  deploySmartAccount,
  createChainProvider,
  signSmartAccountIntent,
  verifySmartAccountIntent,
  addressForPrivateKey,
} from 'aegis-chain-eth';
import { loadSmartAccountArtifact } from 'aegis-chain-eth/test-helpers/load-artifact';

const RPC_URL = process.env.CHAIN_RPC_URL || null;
const OWNER_PK = process.env.OWNER_PK || null;
const EMERGENCY_PK = process.env.EMERGENCY_PK || null;
const RELAYER_PK = process.env.RELAYER_PK || null;
const AGENT_PK = process.env.AGENT_PK || '0x' + '11'.repeat(32);

const MAX_PER_TX = 100n; // 演示额：intent 用 25（合法）与 101（超限拒绝）
const MAX_DAILY = 500n;
const ACCOUNT_MAX_DAILY = 1_000_000n;
const MIN_BALANCE_ETH = 0.005;

const ANVIL_DEFAULT_PKS = new Set([
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
]);

function ok(msg) { console.log(`  [OK] ${msg}`); }
function fail(msg, hint) {
  console.error(`  [FAIL] ${msg}`);
  if (hint) console.error(`         ↳ ${hint}`);
  process.exit(1);
}

function makeIntent(nonce, amount = '25', action = 'transfer', method = 'transfer') {
  return {
    action,
    chain: 'ethereum',
    asset: 'USDC',
    amount,
    recipient: '0xRecipient',
    contract: '0xToken',
    method,
    nonce: String(nonce), // INV-007 防重放：签名原像的一部分
  };
}

async function preflight() {
  console.log('── Preflight ──────────────────────────────────');
  if (!RPC_URL) fail('CHAIN_RPC_URL is required', '公共测试网结算拒绝进程内 LocalChain——用 Sepolia/Base Sepolia 等 RPC 端点');
  if (!OWNER_PK || !EMERGENCY_PK || !RELAYER_PK) {
    fail('OWNER_PK / EMERGENCY_PK / RELAYER_PK are required', '测试网需要真实资金账户；anvil 默认私钥被显式拒绝');
  }
  for (const [name, pk] of [['OWNER_PK', OWNER_PK], ['EMERGENCY_PK', EMERGENCY_PK], ['RELAYER_PK', RELAYER_PK]]) {
    if (ANVIL_DEFAULT_PKS.has(pk.toLowerCase())) {
      fail(`${name} 是 anvil 默认私钥`, '测试网结算必须使用你自己的 funded 账户（先过水龙头）');
    }
  }

  const artifact = loadSmartAccountArtifact();
  if (!artifact) {
    fail('SmartAccount artifact 未找到', '先在 contracts/solidity 执行 `forge build --use 0.8.24`，或设置 SMART_ACCOUNT_ARTIFACT');
  }
  ok(`artifact: ${artifact.contractName ?? 'SmartAccount'}`);

  let provider;
  try {
    provider = createChainProvider(RPC_URL);
    const net = await provider.getNetwork();
    ok(`RPC 连通: chainId=${net.chainId} (${net.name ?? 'unknown'})`);
    if (Number(net.chainId) === 31337) {
      fail('目标是公共测试网，chainId 31337 (anvil/local) 不被接受');
    }
  } catch (err) {
    fail(`RPC 不可达: ${RPC_URL}`, err.message);
  }

  for (const [role, pk] of Object.entries({ owner: OWNER_PK, emergency: EMERGENCY_PK, relayer: RELAYER_PK })) {
    const addr = new ethers.Wallet(pk).address;
    const bal = await provider.getBalance(addr);
    const eth = Number(ethers.formatEther(bal));
    // owner pays deployment, relayer pays execution — both need real gas.
    // emergency is only a constructor argument (never signs/sends), so a
    // funded-balance requirement there is meaningless; just report it.
    if (role !== 'emergency' && eth < MIN_BALANCE_ETH) {
      fail(`${role} (${addr}) 余额 ${eth} ETH 不足 ${MIN_BALANCE_ETH}`, '先过测试网水龙头（Sepolia: google/alchemy/pow 水龙头均可）');
    }
    ok(`${role}: ${addr} → ${eth.toFixed(4)} ETH`);
  }
  return { provider, artifact };
}

async function main() {
  console.log('═══════════════════════════════════════════════');
  console.log('  aegis-vault — 测试网真实结算 E2E');
  console.log('═══════════════════════════════════════════════\n');

  const { provider, artifact } = await preflight();

  const owner = new ethers.Wallet(OWNER_PK);
  const emergency = new ethers.Wallet(EMERGENCY_PK);
  const relayer = new ethers.Wallet(RELAYER_PK);
  const agentAddr = addressForPrivateKey(AGENT_PK);
  console.log(`\n  agent EVM address: ${agentAddr}`);

  // ── deploy ────────────────────────────────────────────────────────────
  console.log('\n── 1. deploy SmartAccount ─────────────────────');
  const dep = await deploySmartAccount({
    provider,
    signer: owner.connect(provider),
    abi: artifact.abi,
    bytecode: artifact.bytecode.object,
    owner: owner.address,
    emergencyKey: emergency.address,
    accountMaxDaily: ACCOUNT_MAX_DAILY,
  });
  if (!dep.ok) fail(`deploySmartAccount: ${dep.reason}`, '常见原因：gas 不足 / RPC 限速 / artifact 与链不匹配');
  ok(`deployed at ${dep.address}`);
  console.log(`        ↳ 区块浏览器核对: owner=${owner.address} emergency=${emergency.address}`);
  const conn = dep.connection;

  // ── register session ──────────────────────────────────────────────────
  console.log('\n── 2. registerSession（owner，链上限额）───────');
  const latest = await provider.getBlock('latest');
  const nowMs = latest.timestamp * 1000; // 用链上时钟，避免时钟漂移触发 INV-003
  const sessionId = '0x' + crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
  const session = {
    agentId: `testnet-settle-${latest.number}`,
    sessionId,
    issuedAt: nowMs,
    expiresAt: nowMs + 60 * 60 * 1000,
  };
  const reg = await conn.registerSession({
    sessionId,
    agentId: session.agentId,
    agentEvmAddress: agentAddr,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    maxPerTx: MAX_PER_TX,
    maxDaily: MAX_DAILY,
    whitelist: {
      allowedChains: ['ethereum'],
      allowedAssets: ['USDC'],
      allowedContracts: ['0xToken'],
      allowedMethods: ['transfer'],
      allowedRecipients: ['0xRecipient'],
    },
  });
  if (!reg.ok) fail(`registerSession: ${reg.reason}`);
  ok(`session registered, maxPerTx=${MAX_PER_TX} maxDaily=${MAX_DAILY}`);

  // ── agent 离线出签 + 链上 digest 交叉校验 ─────────────────────────────
  console.log('\n── 3. agent 离线出签 → 链上 digest 交叉校验 ───');
  const signed = signSmartAccountIntent({
    session,
    intent: makeIntent(1, '25'),
    privateKeyHex: AGENT_PK,
  });
  if (!/^0x[0-9a-f]{64}$/.test(signed.digest)) fail('digest 格式异常');
  const verified = verifySmartAccountIntent({ address: agentAddr, signature: signed.signature, payload: signed.payload });
  if (!verified.valid) fail('离线签名验证失败', 'agent 地址与签名不一致');
  ok('intent signed & locally verified (amount=25 ≤ maxPerTx)');

  const onChainDigest = await conn.hashIntent(signed.payload);
  if (onChainDigest !== signed.digest) {
    fail('链上 hashIntent ≠ JS hashIntentDigest', 'JS ↔ Solidity canonical payload 漂移——立即停止，先修一致性');
  }
  ok('JS ↔ Solidity digest 交叉校验一致');

  // ── relayer 广播 ──────────────────────────────────────────────────────
  console.log('\n── 4. relayer 广播 executeFromAgent ───────────');
  const res = await conn.executeFromAgent({
    payload: signed.payload,
    signature: signed.signature,
    signer: relayer.connect(provider), // relayer 只需 gas，无 agent 私钥
  });
  if (!res.ok) fail(`executeFromAgent: ${res.reason}`, '检查 INV-005/006/007 类型化 revert 与 session 白名单');
  ok(`Executed amount=${res.amount} txId=${res.txId?.slice(0, 18)}…`);
  if (res.txHash) ok(`txHash: ${res.txHash}${res.blockNumber ? ` (block ${res.blockNumber})` : ''}`);

  // ── 防御性拒绝路径（simulate = eth_call，无副作用、无 gas）────────────
  console.log('\n── 5. 链上防御性拒绝路径（INV-005/007）────────');
  const evil = signSmartAccountIntent({ session, intent: makeIntent(2, '1', 'increaseLimit', 'increaseLimit'), privateKeyHex: AGENT_PK });
  const denied = await conn.simulateExecuteFromAgent({ payload: evil.payload, signature: evil.signature });
  if (denied.ok || denied.errorName !== 'SelfEscalationRejected') {
    fail(`INV-005 自升级未被链上拒绝 (errorName=${denied.errorName})`);
  }
  ok('INV-005: agent 自升级限额 → SelfEscalationRejected');

  const over = signSmartAccountIntent({ session, intent: makeIntent(3, String(MAX_PER_TX + 1n)), privateKeyHex: AGENT_PK });
  const overRes = await conn.simulateExecuteFromAgent({ payload: over.payload, signature: over.signature });
  if (overRes.ok) fail('INV-007 超限交易未被拒绝');
  ok(`INV-007: 单笔超 maxPerTx(${MAX_PER_TX}) → 链上拒绝 (${overRes.errorName ?? 'revert'})`);

  console.log('\n═══════════════════════════════════════════════');
  console.log('  RESULT: 真实测试网结算链路全部通过');
  console.log(`  SmartAccount: ${dep.address}`);
  if (res.txHash) console.log(`  settle tx:    ${res.txHash}`);
  console.log('═══════════════════════════════════════════════');
}

main().catch((err) => {
  console.error('\n[E2E FAILED]', process.env.SETTLE_DEBUG ? err.stack : err.message);
  process.exit(1);
});

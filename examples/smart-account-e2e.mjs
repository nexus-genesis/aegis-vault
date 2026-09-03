/**
 * Aegis Vault — Smart Account 官方 EVM 路径 E2E（本地链 / anvil 双模式）
 *
 * 一条"照着就能跑"的最小链路，把 Sprint 2.3 的链上广播能力串起来：
 *   1. 启动链后端：默认进程内 LocalChain（@ethereumjs/vm，真实 EVM，零外部依赖）；
 *      设置 CHAIN_RPC_URL 则连接外部 anvil / 测试网节点
 *   2. 部署 SmartAccount（owner + emergency key + 账户级限额）
 *   3. owner 注册 agent session（绑定 agentEvmAddress）
 *   4. agent 离线出签（signSmartAccountIntent → raw digest + secp256k1）
 *   5. 任意 EOA（relayer）广播 executeFromAgent → 链上状态断言
 *   6. 防御性拒绝路径：自升级 / 超限在链上以类型化 revert 拒绝（INV-005/007）
 *
 * 运行：
 *   node examples/smart-account-e2e.mjs
 *     # → 进程内 LocalChain（自动启动/停止，零外部依赖）
 *   CHAIN_RPC_URL=http://127.0.0.1:8545 node examples/smart-account-e2e.mjs
 *     # → anvil（或任意 JSON-RPC 节点）。默认用 anvil 前三个账户私钥，
 *     #   可用 OWNER_PK / EMERGENCY_PK / RELAYER_PK 覆盖
 *   SMART_ACCOUNT_ARTIFACT=/path/to/SmartAccount.json node examples/smart-account-e2e.mjs
 *     # → 覆盖合约 artifact（默认 <repo>/contracts/solidity/out/...，需先
 *     #   forge build --use 0.8.24）
 *
 * 私钥仅存在于进程内，永不落盘。
 */
import { ethers } from 'ethers';
import {
  deploySmartAccount,
  createChainProvider,
  signSmartAccountIntent,
  verifySmartAccountIntent,
  addressForPrivateKey,
} from 'aegis-chain-eth';

// LocalChain / artifact loader 通过 chain-eth 的 `./test-helpers` 子路径导出，
// 不依赖仓库相对路径，examples 可独立分发运行。
import { createLocalChain } from 'aegis-chain-eth/test-helpers/local-chain';
import { loadSmartAccountArtifact } from 'aegis-chain-eth/test-helpers/load-artifact';

const RPC_URL = process.env.CHAIN_RPC_URL || null;

// anvil 默认前三个账户（owner / emergency / relayer）。本地链模式会为这些
// 派生地址预充值；外部链模式需确保它们有余额。
const OWNER_PK = process.env.OWNER_PK ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const EMERGENCY_PK = process.env.EMERGENCY_PK ?? '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const RELAYER_PK = process.env.RELAYER_PK ?? '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';
const AGENT_PK = process.env.AGENT_PK ?? '0x' + '11'.repeat(32);

const MAX_PER_TX = 100n;
const MAX_DAILY = 500n;
const ACCOUNT_MAX_DAILY = 1_000_000n;

function assert(cond, msg) {
  if (!cond) throw new Error(`E2E FAILED: ${msg}`);
  console.log(`  [OK] ${msg}`);
}

async function main() {
  console.log('═══════════════════════════════════════════════');
  console.log('  Smart Account — 官方 EVM 路径 E2E（链上广播）');
  console.log('═══════════════════════════════════════════════\n');

  // ── 0. 合约 artifact（部署必需）──────────────────────────────────────
  const artifact = loadSmartAccountArtifact();
  if (!artifact) {
    throw new Error(
      'SmartAccount artifact not found. Run `forge build --use 0.8.24` in ' +
      'contracts/solidity, or set SMART_ACCOUNT_ARTIFACT to the built JSON.',
    );
  }

  // ── 1. 链后端：LocalChain（默认）或外部 RPC（CHAIN_RPC_URL）──────────
  const owner = new ethers.Wallet(OWNER_PK);
  const emergency = new ethers.Wallet(EMERGENCY_PK);
  const relayer = new ethers.Wallet(RELAYER_PK);
  const agentAddr = addressForPrivateKey(AGENT_PK);

  let chain = null;
  let provider;
  if (RPC_URL) {
    provider = createChainProvider(RPC_URL);
    console.log(`  [chain] external RPC   ${RPC_URL}`);
    console.log(`          owner=${owner.address}  emergency=${emergency.address}  relayer=${relayer.address}`);
  } else {
    chain = await createLocalChain({
      funded: [
        { address: owner.address, balance: 10n ** 18n },
        { address: emergency.address, balance: 10n ** 18n },
        { address: relayer.address, balance: 10n ** 18n },
      ],
    });
    provider = createChainProvider(chain.url);
    console.log(`  [chain] LocalChain     ${chain.url} (in-process EVM, zero external deps)`);
  }

  try {
    // ── 2. 部署 SmartAccount ─────────────────────────────────────────────
    const dep = await deploySmartAccount({
      provider,
      signer: owner.connect(provider),
      abi: artifact.abi,
      bytecode: artifact.bytecode.object,
      owner: owner.address,
      emergencyKey: emergency.address,
      accountMaxDaily: ACCOUNT_MAX_DAILY,
    });
    assert(dep.ok, `deploySmartAccount → ${dep.address}${dep.reason ? ` (${dep.reason})` : ''}`);
    const conn = dep.connection;

    assert((await conn.owner()) === owner.address, `on-chain owner() === ${owner.address}`);
    assert((await conn.emergencyKey()) === emergency.address, `on-chain emergencyKey() === ${emergency.address}`);
    assert((await conn.accountMaxDaily()) === ACCOUNT_MAX_DAILY, `on-chain accountMaxDaily() === ${ACCOUNT_MAX_DAILY}`);
    assert((await conn.paused()) === false, 'on-chain paused() === false');
    assert((await conn.frozen()) === false, 'on-chain frozen() === false');

    // ── 3. 注册 session（owner）─────────────────────────────────────────
    const sessionId = '0x' + 'ab'.repeat(32);
    // 用链上最新块时间戳（秒）作为 session 时间基准，而非本地 Date.now()——
    // 外部 anvil/节点时钟与本地可能有偏差，若 issuedAt 落在链上"未来"会触发
    // registerSession 的过期校验异常（INV-003）。
    const latest = await provider.getBlock('latest');
    const nowMs = latest.timestamp * 1000;
    const session = {
      agentId: 'agent-e2e-demo',
      sessionId,
      issuedAt: nowMs,
      expiresAt: nowMs + 60 * 60 * 1000, // 1h
    };

    const reg = await conn.registerSession({
      sessionId,
      agentId: session.agentId,
      agentEvmAddress: agentAddr, // EVM path：绑定 secp256k1 地址而非 PQC 公钥
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
    assert(reg.ok, `registerSession(${sessionId.slice(0, 10)}…)${reg.reason ? ` → ${reg.reason}` : ''}`);

    // ── 4 + 5. canonical payload + agent 离线出签 ───────────────────────
    const signed = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer',
        chain: 'ethereum',
        asset: 'USDC',
        amount: '25',
        recipient: '0xRecipient',
        contract: '0xToken',
        method: 'transfer',
        nonce: '1', // 签名原像的一部分（INV-007 防重放）
      },
      privateKeyHex: AGENT_PK,
    });
    assert(!!signed.payload, 'canonicalizeAssetIntent → 12 字段 canonical payload');
    assert(/^0x[0-9a-f]{64}$/.test(signed.digest), 'hashIntentDigest → 32 字节 digest');
    assert(/^0x[0-9a-f]{130}$/.test(signed.signature), 'signIntentDigest → 65 字节 (r||s||v) 签名');

    // 离线自校验
    const v = verifySmartAccountIntent({ address: agentAddr, signature: signed.signature, payload: signed.payload });
    assert(v.valid, 'verifySmartAccountIntent 离线自校验通过');

    // 链上 hashIntent 交叉校验（JS ↔ Solidity 一致性）
    const onChainDigest = await conn.hashIntent(signed.payload);
    assert(onChainDigest === signed.digest, `链上 hashIntent === JS hashIntentDigest（${signed.digest.slice(0, 16)}…）`);

    // ── 6. 广播执行（任意 EOA 可中继，合约校验签名）────────────────────
    const res = await conn.executeFromAgent({
      payload: signed.payload,
      signature: signed.signature,
      signer: relayer.connect(provider), // relayer 只需有 gas，不需 agent 私钥
    });
    assert(res.ok, `executeFromAgent（relayer 广播）${res.reason ? ` → ${res.reason}` : ''}`);
    assert(res.amount === 25n, `Executed 事件 amount=${res.amount}`);
    assert(res.txId?.length === 66, 'Executed 事件 txId 为 bytes32');

    // 链上状态断言
    assert((await conn.sessionLastNonce(sessionId)) === 1n, '链上 sessionLastNonce === 1');
    assert((await conn.sessionSpentThisWindow(sessionId)) === 25n, '链上 sessionSpentThisWindow === 25');

    // ── 7. 防御性拒绝路径（simulate = eth_call，无副作用）────────────────
    // INV-005：自升级即使签名合法也会被拒
    const evil = signSmartAccountIntent({
      session,
      intent: {
        action: 'increaseLimit',
        chain: 'ethereum',
        asset: 'USDC',
        amount: '1',
        recipient: '0xRecipient',
        contract: '0xToken',
        method: 'increaseLimit',
        nonce: '2',
      },
      privateKeyHex: AGENT_PK,
    });
    const denied = await conn.simulateExecuteFromAgent({ payload: evil.payload, signature: evil.signature });
    assert(!denied.ok && denied.errorName === 'SelfEscalationRejected',
      `INV-005 自升级链上拒绝（errorName=${denied.errorName}）`);

    // INV-007：单笔超 maxPerTx（100）被拒
    const over = signSmartAccountIntent({
      session,
      intent: {
        action: 'transfer',
        chain: 'ethereum',
        asset: 'USDC',
        amount: '101',
        recipient: '0xRecipient',
        contract: '0xToken',
        method: 'transfer',
        nonce: '3',
      },
      privateKeyHex: AGENT_PK,
    });
    const exceeded = await conn.simulateExecuteFromAgent({ payload: over.payload, signature: over.signature });
    assert(!exceeded.ok && exceeded.errorName === 'AmountExceedsPerTx',
      `INV-007 超 maxPerTx 链上拒绝（errorName=${exceeded.errorName}）`);

    console.log('\n═══════════════════════════════════════════════');
    console.log('  E2E 全部通过 ✔（真实链上广播）');
    console.log('═══════════════════════════════════════════════');
  } finally {
    // 清理失败不应掩盖主流程的错误——仅告警。
    if (chain) {
      try {
        await chain.stop();
      } catch (err) {
        console.warn(`[chain] LocalChain stop failed: ${err.message}`);
      }
    }
  }
}

main().catch((err) => {
  console.error('\n❌', err.message);
  process.exit(1);
});

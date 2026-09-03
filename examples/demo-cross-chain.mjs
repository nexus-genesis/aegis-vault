/**
 * Aegis Vault 标杆 demo — 跨链 Agent 密钥管理与协调
 * 最小可复现案例：一个外部 Agent 用 aegis-chain-adapters 框架
 *   1. 生成 PQC 根身份（Dilithium2，抗量子）
 *   2. 从同一根身份派生出 nexus / ethereum / solana 三链地址
 *   3. 用 PQC 根密钥签名协调任务（claim）
 *   4. 用已派生的 ETH 密钥签名消息（EIP-191）
 *   5. 人类接管：spend 模式从 self-sovereign 切到 require-approval
 *
 * 运行：node examples/demo-cross-chain.mjs
 * 私钥永不离开本进程。
 */
import { generateKeyPair, sign, takeoverGuard, SPEND_MODES } from 'aegis-vault';
import { deriveChainAddresses, deriveAgentFingerprint } from 'aegis-chain-adapters';
import { deriveEthWalletFromPQC, signMessage as signEth, verifyMessage as verifyEth } from 'aegis-chain-eth';
import { deriveSolWalletFromPQC } from 'aegis-chain-sol';

const line = '='.repeat(60);

async function main() {
  console.log(line);
  console.log('Aegis Vault — 跨链 Agent 密钥管理 + 协调 demo');
  console.log(line);

  // 1. PQC 根身份
  const { publicKey, privateKey } = await generateKeyPair();
  const fingerprint = deriveAgentFingerprint(publicKey);
  console.log('\n[1] PQC 根身份 (Dilithium2 / FIPS 204)');
  console.log(`    fingerprint  : ${fingerprint}`);

  // 2. 三链地址派生（同一根身份）
  const addrs = deriveChainAddresses(publicKey, privateKey);
  const eth = deriveEthWalletFromPQC(privateKey);
  const sol = deriveSolWalletFromPQC(privateKey);
  console.log('\n[2] 一个根身份 → 三链地址');
  console.log(`    nexus (ng1)  : ${addrs.nexus}`);
  console.log(`    ethereum     : ${addrs.eth}`);
  console.log(`    solana       : ${addrs.sol}`);

  // 3. 用 PQC 根密钥签名协调事件（离线可验证）
  const task = { id: 'task-42', action: 'claim', agent: fingerprint };
  const sig = (await sign('nexus-claim', privateKey)).toString('hex');
  console.log('\n[3] PQC 签名协调任务 (claim task-42)');
  console.log(`    signature    : ${sig.slice(0, 40)}... (${sig.length} chars)`);

  // 4. ETH 派生密钥签名（EIP-191）
  const ethMsg = 'agent confirms research task';
  const ethSig = signEth(ethMsg, eth.privateKeyHex);
  const validEth = verifyEth(eth.address, ethMsg, ethSig);
  console.log('\n[4] ETH 派生密钥签名 (EIP-191)');
  console.log(`    address      : ${eth.address}`);
  console.log(`    verify       : ${validEth}`);

  // 5. 人类接管：spend 额度控制
  const before = { type: SPEND_MODES.UNLIMITED };
  const after = { type: SPEND_MODES.REQUIRE_APPROVAL };
  const safe = takeoverGuard(before, after);
  console.log('\n[5] 人类接管 guard');
  console.log(`    接管方向     : unlimited → require-approval`);
  console.log(`    takeoverGuard: ${safe ? 'safe (通过)' : 'BLOCK value transfer'}`);

  console.log('\n' + line);
  console.log('结论：外部 Agent 可用同一把 PQC 根密钥在 nexus/eth/sol 多链上');
  console.log('管理账户 + 协调任务，且人类随时可接管。私钥全程不出本进程。');
  console.log(line);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
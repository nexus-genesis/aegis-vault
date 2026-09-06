/**
 * Aegis Vault — Guardrail E2E（design partner 演示 · 纯离线，零外部依赖）
 *
 * Stage 2 集成面串成一条链路，1 天 pilot 的"照着就能跑"起点：
 *   1. x402 护栏：小额自动放行 / 中额时限锁（HOLD）/ 超限拒绝
 *   2. 放行决策 → 签名授权快照（审计与纠纷证据的原子单元）
 *   3. 快照 → AP2 Payment Mandate 联签 + 三方吻合校验（含篡改检测）
 *   4. KYA 承诺 → ERC-8004 注册文件绑定（链上写入见 runbook）
 *
 * 运行：
 *   npm run e2e:guardrail --workspace aegis-examples
 *
 * 签名者用 HMAC 占位，演示的是"签名者无关"接口——生产里换成
 * session key / PQC op key / remote signer，代码零改动。
 */
import crypto from 'node:crypto';
import { createX402Guardrail, DECISIONS } from 'aegis-guardrail-x402';
import { createAp2MandateBuilder, snapshotHash } from 'aegis-guardrail-ap2';
import {
  buildAgentRegistration, kyaCommitment, verifyBinding,
  agentRegistryString, toDataUri
} from 'aegis-registry-8004';

const SECRET = Buffer.alloc(32, 0xa9);
const sign = async (preimage) => crypto.createHmac('sha256', SECRET).update(preimage).digest('hex');
const verify = async (preimage, sig) =>
  crypto.createHmac('sha256', SECRET).update(preimage).digest('hex') === sig;

function assert(cond, msg) {
  if (!cond) throw new Error(`E2E FAILED: ${msg}`);
  console.log(`  [OK] ${msg}`);
}

const POLICY = {
  type: 'limit',
  maxPerTx: 100_000_000n,
  maxDaily: 500_000_000n,
  tierThresholds: { smallThreshold: '3000000', largeThreshold: '10000000' }
};

async function main() {
  console.log('═══════════════════════════════════════════════');
  console.log('  Aegis Guardrail E2E — x402 → AP2 → ERC-8004');
  console.log('═══════════════════════════════════════════════\n');

  // ── 1. x402 护栏 ────────────────────────────────────────────────
  console.log('── 1. x402 护栏决策（四级梯度） ──────────────────');
  const guardrail = createX402Guardrail({
    agentId: 'agent-007',
    policy: POLICY,
    spentToday: async () => '4000000',
    sign
  });

  const small = await guardrail.evaluatePayment({
    amount: 2_500_000n, asset: 'USDC', payTo: '0xabc0000000000000000000000000000000000000',
    chain: 'base-sepolia', requestId: 'req-small', purpose: 'printer paper'
  });
  assert(small.decision === DECISIONS.ALLOW, '小额支付 → 自动放行 + 签名快照');

  const medium = await guardrail.evaluatePayment({
    amount: 8_000_000n, asset: 'USDC', payTo: '0xabc0000000000000000000000000000000000000',
    chain: 'base-sepolia', requestId: 'req-medium', purpose: 'annual software license'
  });
  assert(medium.decision === DECISIONS.HOLD, '中额支付 → HOLD（时限锁窗口内可撤销）');

  const approval = await guardrail.evaluatePayment({
    amount: 60_000_000n, asset: 'USDC', payTo: '0xabc0000000000000000000000000000000000000',
    chain: 'base-sepolia', requestId: 'req-large'
  });
  assert(approval.decision === DECISIONS.APPROVAL_REQUIRED, '大额支付 → 需人工审批');

  const denied = await guardrail.evaluatePayment({
    amount: 120_000_000n, asset: 'USDC', payTo: '0xabc0000000000000000000000000000000000000',
    chain: 'base-sepolia', requestId: 'req-over'
  });
  assert(denied.decision === DECISIONS.DENY, '超 maxPerTx 限额 → 直接拒绝');

  // ── 2. 快照 → AP2 Payment Mandate 联签 ──────────────────────────
  console.log('\n── 2. AP2 Mandate 联签 ───────────────────────────');
  const builder = createAp2MandateBuilder({ sign, verify });
  const mandate = await builder.toPaymentMandate(small.snapshot, {
    paymentMandateId: 'pm-42',
    merchantOrigin: 'https://merchant.example',
    paymentMethod: 'credential-token-demo'
  });
  assert(mandate.aegis.snapshot_hash === snapshotHash(small.snapshot),
    'mandate 绑定了快照完整性哈希');
  assert(mandate.aegis.cosignature.signature?.length > 0, '护栏联签已附加');

  const verdict = await builder.verifyCosignature(mandate, { snapshot: small.snapshot });
  assert(verdict.ok, `三方吻合校验通过（payload + snapshot + cosignature）`);

  const tampered = structuredClone(mandate);
  tampered.payment_mandate.payment_details.total = '999999999';
  const badVerdict = await builder.verifyCosignature(tampered, { snapshot: small.snapshot });
  assert(badVerdict.ok === false, '篡改金额 → 校验拒绝（fail-closed）');

  // ── 3. KYA 承诺 → ERC-8004 绑定 ─────────────────────────────────
  console.log('\n── 3. ERC-8004 身份锚定 ──────────────────────────');
  const registry = agentRegistryString(11155111, '0xf66e7CBdAE1Cb710fee7732E4e1f173624e137A7');
  const kyaUri = 'https://kya.example/agent-007';
  const commitment = kyaCommitment({
    agentRegistry: registry,
    agentId: 22,
    kyaUri,
    ownerFingerprint: '0x' + crypto.createHash('sha256').update('pqc-root-pubkey-demo').digest('hex'),
    sessionPolicyHash: '0x' + crypto.createHash('sha256')
      .update(JSON.stringify(POLICY, (k, v) => (typeof v === 'bigint' ? v.toString() : v)))
      .digest('hex'),
    auditChainHead: '0x' + '77'.repeat(32)
  });
  assert(/^0x[0-9a-f]{64}$/.test(commitment), 'KYA 承诺 = keccak(bundle)，任何字段变更即失效');

  const file = buildAgentRegistration({
    name: 'agent-007',
    description: 'Procurement agent under aegis tiered spend guardrails',
    services: [{ name: 'web', endpoint: 'https://agent.example/' }],
    registrations: [{ agentId: 22, agentRegistry: registry }],
    x402Support: true,
    kyaUri,
    kyaCommitment: commitment
  });
  const bound = verifyBinding(file, { agentRegistry: registry, agentId: 22, kyaUri, kyaCommitment: commitment });
  assert(bound.ok, 'ERC-8004 注册文件携带可校验的 aegis 绑定');

  console.log('\n  agentURI（全链上形态）:');
  console.log(`  ${toDataUri(file).slice(0, 96)}…`);
  console.log('\n  链上写入步骤 → docs/runbook/ERC8004-ANCHORING.md');
  console.log('\n═══════════════ E2E PASS ═════════════');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

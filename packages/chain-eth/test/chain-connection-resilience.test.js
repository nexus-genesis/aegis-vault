/**
 * Sprint 4 T3 复核补充 — ChainConnection.executeFromAgent 广播后韧性路径
 *
 * 这三条路径在 T3 实现中引入但此前零覆盖（mcp-server 集成测试的失败都发生在
 * estimateGas 阶段，从未挖出过 status-0 的交易）：
 *   1. mined-but-reverted（status 0）→ ok:false（修复了旧的 ok:true 矛盾语义）
 *   2. wait() 抖动但对账轮询拿到 receipt → ok:true 复用已落账结果
 *   3. wait() 抖动且对账拿不到 → ok:false + waitFailed:true + txHash 保留
 *
 * 用 stub contract 直测（构造器只取 {contract, address}，无需真实链）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChainConnection } from '../src/chain-connection.js';

const PAYLOAD = {
  sessionId: '0x' + 'ab'.repeat(32),
  agentId: 'test-agent',
  action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
  recipient: '0xR', contract: '0xToken', method: 'transfer', nonce: '1',
  sessionIssuedAt: String(Date.now() - 1000),
  sessionExpiresAt: String(Date.now() + 3600_000),
};

function stubConn(txStub, providerStub) {
  const conn = new ChainConnection({ contract: null, address: '0xSA' });
  conn.contract = {
    interface: { parseLog: () => null },
    connect: () => ({ executeFromAgent: async () => txStub }),
    runner: providerStub ?? null,
  };
  return conn;
}

test('T3 status-0 (mined but reverted) is a FAILURE, not success', async () => {
  const tx = { hash: '0xrev', wait: async () => ({ status: 0, logs: [] }) };
  const conn = stubConn(tx);
  const res = await conn.executeFromAgent({ payload: PAYLOAD, signature: '0x' + '00'.repeat(65) });
  assert.equal(res.ok, false, 'reverted-on-chain tx must NOT report ok:true');
  assert.equal(res.txHash, '0xrev');
  assert.match(res.reason, /reverted on-chain/);
  assert.equal(res.waitFailed, undefined, 'this is a definitive on-chain fact, not a wait flake');
});

test('T3 wait() flake reconciled via receipt poll → ok:true with the landed txHash', async () => {
  const receipt = { status: 1, logs: [], blockNumber: 7, gasUsed: 21000n };
  const provider = { getTransactionReceipt: async () => receipt };
  const tx = {
    hash: '0xland',
    wait: async () => { throw new Error('request timeout after broadcast'); },
  };
  const conn = stubConn(tx, provider);
  const res = await conn.executeFromAgent({ payload: PAYLOAD, signature: '0x' + '00'.repeat(65) });
  assert.equal(res.ok, true, 'tx landed on-chain despite the wait() flake');
  assert.equal(res.txHash, '0xland');
  assert.equal(res.receipt, receipt);
});

test('T3 wait() flake with no receipt anywhere → ok:false, waitFailed, txHash kept for the caller', async () => {
  process.env.RELAYER_RECONCILE_ATTEMPTS = '0'; // 单次探测即可，不拖慢测试
  try {
    const provider = { getTransactionReceipt: async () => null };
    const tx = {
      hash: '0xpending',
      wait: async () => { throw new Error('request timeout after broadcast'); },
    };
    const conn = stubConn(tx, provider);
    const res = await conn.executeFromAgent({ payload: PAYLOAD, signature: '0x' + '00'.repeat(65) });
    assert.equal(res.ok, false);
    assert.equal(res.waitFailed, true);
    assert.equal(res.txHash, '0xpending', 'caller needs the hash to reconcile later');
    assert.match(res.reason, /timeout/);
  } finally {
    delete process.env.RELAYER_RECONCILE_ATTEMPTS;
  }
});

test('T3 wait() flake with NO provider on the runner → still fails soft (waitFailed), never throws', async () => {
  process.env.RELAYER_RECONCILE_ATTEMPTS = '2';
  try {
    const tx = {
      hash: '0xnoprov',
      wait: async () => { throw new Error('socket hang up'); },
    };
    const conn = stubConn(tx, null); // runner === null → providerFor → null
    const res = await conn.executeFromAgent({ payload: PAYLOAD, signature: '0x' + '00'.repeat(65) });
    assert.equal(res.ok, false);
    assert.equal(res.waitFailed, true);
    assert.equal(res.txHash, '0xnoprov');
  } finally {
    delete process.env.RELAYER_RECONCILE_ATTEMPTS;
  }
});

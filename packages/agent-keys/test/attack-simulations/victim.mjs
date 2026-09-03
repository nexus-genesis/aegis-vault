#!/usr/bin/env node
/**
 * Attack-simulation victim process（攻击模拟目标进程）
 *
 * 用法:
 *   node victim.mjs              # 修复后模式（ShardedSecret 分片持有）
 *   node victim.mjs --legacy     # 修复前模式（连续明文 Buffer 持有，对照组）
 *
 * 行为:
 *   1. 生成 Dilithium2 密钥对
 *   2. 按模式持有私钥（分片 / 连续明文）
 *   3. 每 2 秒签名一次（保持密钥被使用的活性）
 *   4. 将"完整明文 hex"写入 marker.fullkey.txt（仅供扫描器对照，
 *      模拟攻击者通过其他渠道拿到一份明文副本用于内存比对）
 *   5. 持续运行，等待外部扫描器（dump-core.sh / read-proc-mem.sh /
 *      gcore / env-leak.sh / swap-scan.sh）
 *
 * 退出: SIGTERM / SIGINT
 */
import { writeFileSync } from 'node:fs';
import { generateKeyPair, signSync, PQCWallet, ShardedSecret } from '../src/index.js';

const LEGACY = process.argv.includes('--legacy');
const pid = process.pid;

console.log(`[victim] mode=${LEGACY ? 'LEGACY(修复前对照)' : 'SHARDED(修复后)'}`);
console.log(`[victim] pid=${pid}`);

const { publicKey, privateKey } = await generateKeyPair();

// marker: 完整明文（攻击者对照样本）
writeFileSync('marker.fullkey.txt', privateKey.toString('hex'));
console.log(`[victim] marker written: marker.fullkey.txt (${privateKey.length} bytes)`);

let sharded = null;
let legacyKey = null;
if (LEGACY) {
  legacyKey = Buffer.from(privateKey); // 连续明文驻留 —— 旧行为
} else {
  sharded = new ShardedSecret(privateKey); // 分片，构造时清零明文入参
}
secureZeroSource(privateKey);

function secureZeroSource(buf) {
  if (buf && buf.fill) { try { buf.fill(0); } catch {} }
}

// 长期持有并周期性使用密钥 —— 模拟 7×24 Agent
let round = 0;
const timer = setInterval(() => {
  round++;
  try {
    if (LEGACY) {
      const sig = signSync(`heartbeat-${round}`, legacyKey);
      if (sig.length === 0) throw new Error('empty sig');
    } else {
      sharded.use(pk => signSync(`heartbeat-${round}`, pk));
    }
    console.log(`[victim] round=${round} signed ok, rss=${(process.memoryUsage().rss / 1024 / 1024).toFixed(1)}MB`);
  } catch (e) {
    console.error(`[victim] sign failed: ${e.message}`);
  }
}, 2000);

// 保持进程存活，密钥持续驻留内存
process.on('SIGTERM', () => { clearInterval(timer); process.exit(0); });
process.on('SIGINT', () => { clearInterval(timer); process.exit(0); });
console.log('[victim] running — start your scanners now');

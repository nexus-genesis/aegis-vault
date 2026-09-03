#!/usr/bin/env node
/**
 * Dump scanner（转储扫描器）— 在 core dump / gcore 镜像 / 原始内存段中
 * 搜索完整明文私钥与分片。
 *
 * 用法:
 *   node scan-dump.mjs <dump-file> [marker-fullkey.txt]
 *
 * 输出:
 *   FULL-KEY-FOUND   : 找到连续完整明文（修复前预期 / 修复后不应出现）
 *   FULL-KEY-ABSENT  : 未找到连续完整明文（修复后的目标结果）
 *   并附带分片命中统计（信息性）
 */
import { readFileSync } from 'node:fs';

const dumpFile = process.argv[2];
const markerFile = process.argv[3] || 'marker.fullkey.txt';

if (!dumpFile) {
  console.error('Usage: node scan-dump.mjs <dump-file> [marker-fullkey.txt]');
  process.exit(2);
}

const fullKeyHex = readFileSync(markerFile, 'utf8').trim();
const fullKey = Buffer.from(fullKeyHex, 'hex');

console.log(`[scan] dump=${dumpFile} keyLen=${fullKey.length}`);
const dump = readFileSync(dumpFile);
console.log(`[scan] dumpSize=${dump.length} bytes`);

const idx = dump.indexOf(fullKey);
if (idx !== -1) {
  console.log(`RESULT: FULL-KEY-FOUND at offset ${idx} (0x${idx.toString(16)})`);
  process.exit(1); // 修复后模式出现此结果 = 内存卫生失效
}

console.log('RESULT: FULL-KEY-ABSENT — contiguous plaintext key not present in dump');

// 信息性：尝试定位分片（无法从 dump 直接重构分片对，仅统计熵特征不可行；
// 完整性由 ShardedSecret 的 XOR 结构保证：无连续明文即无完整密钥）。
console.log('[scan] sharded halves are indistinguishable from random bytes —');
console.log('[scan] reconstructing the key requires locating BOTH non-contiguous shards');
process.exit(0);

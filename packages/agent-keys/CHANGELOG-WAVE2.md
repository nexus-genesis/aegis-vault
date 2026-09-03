# Wave 2 变更说明 — 开发团队必读

> 版本: 2.0.0  
> 复核日期: 2026-08-15  
> 复核范围: agent-keys 包 (packages/agent-keys)

---

## 目录

1. [API 不兼容变更](#1-api-不兼容变更)
2. [已知架构限制](#2-已知架构限制)
3. [安全修复清单](#3-安全修复清单)
4. [新增文件清单](#4-新增文件清单)
5. [迁移指南](#5-迁移指南)

---

## 1. API 不兼容变更

### 1.1 `signer.sign()` 第二参数签名变更 (Breaking)

**旧签名 (Wave 1):**
```js
signer.sign(hash: string, timeoutMs?: number): Promise<string>
```

**新签名 (Wave 2):**
```js
signer.sign(hash: string, opts?: { amount?: string, timeoutMs?: number }): Promise<string | TimelockInfo>
```

**影响范围:**
- `signer.sign(hash)` — 无变化，兼容
- `signer.sign(hash, 5000)` — **破坏性变更**，原裸数字 timeout 参数不再支持
- `signer.sign(hash, { amount: '50' })` — 新用法，推荐

**迁移方式:**
```js
// 旧代码 (Wave 1)
const sig = await signer.sign('0x...', 30000);

// 新代码 (Wave 2)
const sig = await signer.sign('0x...', { timeoutMs: 30000 });
// 或带金额 (policy-aware 场景):
const sig = await signer.sign('0x...', { amount: '50', timeoutMs: 30000 });
```

**返回类型变更:**
- 普通签名返回 `string` (0x-prefixed hex) — 不变
- 中额时间锁 (medium-tier) 返回 `{ timelocked: true, timelockMs: number, scheduledAt: number }`
- 调用方需检查返回值类型: `typeof result === 'string'` 或 `result.timelocked`

### 1.2 `spawnSigner` 新增参数

**新增可选字段:**
```js
const signer = await spawnSigner({
  envelope,    // 必需
  password,    // 必需
  policy,      // 可选 — 支出策略配置
  idleTimeoutMs // 可选 — 空闲超时(ms)，默认 5 分钟
});
```

### 1.3 新增导出符号

`index.js` 新增以下导出，无需额外安装:

```js
import {
  // Wave 2 新增
  spawnSigner,           // Signer 子进程启动
  SignerHandle,          // Signer IPC 句柄
  createSessionKey,      // 创建会话密钥
  checkSessionAccess,    // 会话密钥权限检查
  verifySessionSignature, // 会话密钥签名验证
  getSessionTTL,         // 获取会话密钥剩余 TTL
  isSessionExpired,      // 检查会话密钥是否过期
  // takeover.js 新增
  checkSpendAllowedTiered, // 三级梯度授权检查
  resolveTier,           // 金额层级解析
  PolicyTimelock,        // 策略时间锁类
  TIER_MODES,            // 授权层级常量
  DEFAULT_TIER_THRESHOLDS, // 默认阈值
  MEDIUM_TIER_TIMELOCK_MS, // 中额时间锁 ms
  POLICY_TIMELOCK_MS,    // 策略变更时间锁 ms
} from 'aegis-vault';
```

---

## 2. 已知架构限制

### 2.1 [严重] amount-hash 不可链接性

**问题描述:**
Signer 子进程对收到的 `amount` 字段进行策略检查，但**无法验证**该 `amount` 是否与待签名的 `hash` 一致。一个被攻陷的父进程可以发送 `amount: "1"` 同时请求签署一笔百万代币转账的 hash——worker 会批准签名，因为策略检查使用虚假的金额。

**根因:**
这是进程隔离架构的固有缺陷。worker 无法解析链上状态来验证 hash 对应的交易金额。

**缓解措施:**
1. **Session Key 层验证** — 合约或链上验证器在接收签名前**必须**独立验证交易金额不超过 session key 的 `maxPerTx`/`maxDaily`
2. **大额人工审查** — 大额时间锁层 (large-require-approval) 下，人类应直接在区块浏览器上审查原始交易 hash，不依赖 agent 报告的金额
3. **未来方案** — 零知识证明 (ZK proof) 证明 hash 编码的交易金额 ≤ 声明金额，可完全消除此差距。当前版本未实现

**相关文档位置:**
- [signer.js 源码注释](packages/agent-keys/src/signer.js#L41-L60)
- [signer-worker.js 源码注释](packages/agent-keys/src/signer-worker.js#L25-L28)

### 2.2 [中] PolicyTimelock 进程内调度器

`PolicyTimelock` 的 `getEffectiveChanges()` 为进程内调度器，进程重启后所有挂起的策略变更将丢失。生产部署需接持久化层（如 Redis 或链上状态）。

### 2.3 [中] Session Key 无撤销机制

Session Key 缺少 jti (JWT ID) 和吊销列表，只能通过 TTL 过期失效。TTL 最长 365 天（`MAX_TTL_MS` 常量）。建议在 Wave 3 增加撤销机制。

### 2.4 [低] 中额时间锁无自动续签队列

中额时间锁 (medium-timelock) 当前只返回锁定信息，无到期自动续签队列。调用方需自行处理 `sign_timelock` 响应并在到期后重新发起请求。

---

## 3. 安全修复清单

### Wave 2 首次复核修复 (P0-P2)

| 严重度 | 文件 | 问题 | 修复 |
|--------|------|------|------|
| **P0** | signer-worker.js | 策略检查用 `policy.maxPerTx` 冒充金额，真实交易金额从未被校验 | IPC 协议扩展 `amount` 字段，worker 用真实金额检查 |
| **P0** | takeover.js | `checkSpendAllowedTiered` 无 amount 时 fail-open 放行 | 无 amount 一律返回 requiresApproval |
| **P1** | signer.test.js | 测试用无效 mode `'limited'`，断言靠 fail-closed 兜底 | 改为 require-approval 正向用例，新增 3 个测试 |
| **P1** | session.js, takeover.js | 非法金额字符串崩溃调用方；`BigInt('') === 0n` 空串溜过限额 | try-catch + 空串显式拒绝 |
| **P2** | signer-worker.js | stdin 无长度上限，可 OOM | 1 MiB 消息上限 |
| **P2** | session.js | 4 个死导入 | 清理 |
| **P2** | session.js | JSDoc 示例用 `SessionKey.create` 命名空间 | 改为独立函数名 |
| **P2** | signer.js | `sign()` 返回类型二义性无文档 | 已文档化 |
| **P2** | pqc-benchmark.js | 尺寸对比口径不一致 (DER vs raw) | 加脚注说明 |

### Wave 2 二次复核修复

| 文件 | 修复内容 |
|------|---------|
| signer.js | 补全 `sign_timelock` 响应类型到 IPC 协议文档 |
| signer.js | 追加 `BREAKING CHANGE` 说明 |
| signer.js, signer-worker.js | 文档化 amount-hash 不可链接性 (KNOWN LIMITATION) |
| signer.test.js | 修正注释误导；新增 `options.amount` 正则测试 |

---

## 4. 新增文件清单

| 文件 | 说明 |
|------|------|
| `src/signer.js` | Signer 子进程 IPC 封装 (父进程端) |
| `src/signer-worker.js` | Signer 子进程入口 (子进程端) |
| `src/session.js` | Session Key 五维权限系统 |
| `test/signer.test.js` | Signer E2E 测试 (11 tests) |
| `test/session.test.js` | Session Key 测试 (17 tests) |
| `test/takeover-tiered.test.js` | 三级授权 + 时间锁测试 (30 tests) |
| `bench/pqc-benchmark.js` | PQC 基准对比脚本 |

**修改文件:**
| 文件 | 变更 |
|------|------|
| `src/index.js` | 新增导出符号 |
| `src/takeover.js` | 新增 `checkSpendAllowedTiered`, `PolicyTimelock`, `resolveTier` 等 |

---

## 5. 迁移指南

### 5.1 无需修改的调用方

- `signer.sign(hash)` — 无变化
- 纯消息签名 (无 policy 配置) — 无变化
- 通过 `PQCWallet` 接口调用 — 无变化

### 5.2 需要修改的调用方

- 使用 `signer.sign(hash, timeoutMs)` 裸数字超时参数 → 改为 `signer.sign(hash, { timeoutMs })`
- 使用 `signer.sign()` 且配置了 spend policy → 必须传入 `{ amount: '...' }`，否则 worker fail-closed 拒签

### 5.3 建议的调用模式

```js
// 消息签名 (无金额, 无 policy)
const sig = await signer.sign('0x' + messageHash);

// 交易签名 (有 policy)
const result = await signer.sign('0x' + txHash, { amount: txAmount });
if (typeof result === 'string') {
  // 签名成功: 将 result 提交到链上
} else if (result.timelocked) {
  // 中额时间锁: 等待 scheduledAt 后重新请求
  console.log(`Timelocked until ${new Date(result.scheduledAt).toISOString()}`);
  scheduleRetry(result.scheduledAt);
} else {
  // 不应到达此处
}
```
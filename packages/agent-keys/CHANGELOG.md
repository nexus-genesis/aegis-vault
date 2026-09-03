# Changelog — aegis-vault

## 0.3.1 (2026-08-15)

**主题：五大技术障碍闭环 + 专家复核二轮强化**

本版本是安全整改阶段的收官版本。针对深度分析报告提出的五大技术障碍，全部形成"机制 + 测试 + 边界声明"三位一体闭环，并吸收外部专家复核意见完成第二轮强化（E1-E5）。

### 五大技术障碍闭环成果

| # | 障碍 | 闭环机制 | 测试 |
|---|------|---------|------|
| 1 | **内存安全** | `secureZero` 确定性清零 + `ShardedSecret` XOR 2-of-2 分片存储（签名时临时拼接、用后即焚）+ `PQCWallet.destroy()` 生命周期销毁 + `disableCoreDumps()` 落盘防护；V8 边界主动声明（栈拷贝/JIT 中间数据无法覆盖） | 16 项 + **E1 堆快照实证**：GC 后全堆 dump 扫描无连续明文（二进制与 hex 双形态） |
| 2 | **进程隔离** | Signer 子进程：stdio JSON-line IPC（只传 hash 与签名，永传密钥）、1MiB 消息上限、空闲超时自动销毁、密码不落 env/cmdline、全链路 fail-closed；物理攻击（DMA/冷启动/JTAG/芯片剥离）威胁象限划界 | 11 项 E2E（真实子进程）+ **E2 最小权限**：`NGX_SIGNER_DOWNGRADE=1` 自动降级 nobody，降级失败拒绝启动；配套 seccomp 白名单 profile（`deploy/seccomp/signer-seccomp.json`） |
| 3 | **权限粒度** | Session Key 五维权限：合约白名单 + 方法白名单 + 链限定 + 单笔上限 + 日累计，短 TTL，发行方签名防篡改，非法输入 fail-closed | 17 项 + **E3 权限只降不升**：`narrowSession()` 刚性单调收窄——白名单子集校验、显式空/`'0'` 视为放开并拒绝、限额只降、过期钳制到父会话；省略维度=继承父作用域；10 项新增测试 |
| 4 | **策略僵化** | 三级梯度授权（小额自动 / 中额 24h 时间锁可撤销 / 大额强制人工）+ `PolicyTimelock` 48h 策略变更延迟 + 阈值可配置 + 全链路 fail-closed | 30 项 + **E4 告警闭环**：`addNotifier()` 与 `POLICY_WEBHOOK_URL` 环境变量，scheduled/revoked/effective/cleared 四类事件，webhook 5s 超时 fire-and-forget，notifier 异常不阻断执行路径——形成"检测-延迟-处置"完整闭环；6 项新增测试 |
| 5 | **后量子密码** | Dilithium2（NIST FIPS 204）基准对比表（vs ECDSA P-256 / Ed25519，含量化结论与 DER 封装口径脚注）+ KEY_MODELS 三档信任假设决策树 + 多实例 HA 方案 + **E5 审计边界声明**：@noble 原语已独立审计 vs Aegis Vault 组合层未审计，附防"蹭审计"正确引用措辞 | 基准测试 + 全套件 |

### 新增 API

```js
import {
  narrowSession,        // E3: 会话权限单调收窄（只降不升）
  PolicyTimelock,       // E4: 现已支持 addNotifier() + webhook 告警
} from 'aegis-vault';
```

- `narrowSession(parentSession, narrower, issuerKey)` — 派生会话在全部五个维度上只能收窄。省略维度继承父作用域；显式空数组 / `'0'`（无限制）在受限父会话下属于提权，直接抛错；过期时间钳制在父会话到期之内。
- `new PolicyTimelock(delayMs, { webhookUrl })` — webhookUrl 缺省回退 `POLICY_WEBHOOK_URL` 环境变量。

### 部署强化

- Signer 子进程最小权限：POSIX 环境以 root 启动且 `NGX_SIGNER_DOWNGRADE=1` 时自动 `setgid/setuid('nobody')`，失败即退出（fail-closed）
- 参考级 seccomp 白名单：`deploy/seccomp/signer-seccomp.json`（`defaultAction: SCMP_ACT_ERRNO`），配合 Docker `--security-opt seccomp=...` 收窄 syscall 面（上线前请在目标 Linux 环境实测）

### 质量记录

- 单元测试 **121/121 通过**（0.3.0 为 105 项）
- 下游 CLI E2E 14 项、MCP 冒烟 12 项全绿
- 累计四轮交叉复核：发现并修复 28 项缺陷（5 P0 / 6 P1 / 17 P2）+ 二轮强化 5 项
- 完整整改报告：`docs/FIVE_BARRIERS_ENHANCEMENT.md`（主仓库）

### 兼容性

- 对 0.3.0 **无新增破坏性变更**
- 从 0.2.x 升级注意（0.3.0 已引入，此处重申）：`signer.sign(hash, options)` 第二参数由裸 `timeoutMs` 数字改为 `{ amount, timeoutMs }` 对象——详见 `CHANGELOG-WAVE2.md`

### 已知限制（主动声明）

- amount-hash 不可链接性：IPC 协议无法验证 amount 与被签 hash 一致，依赖 session key 层校验，详见 `src/signer.js` KNOWN LIMITATION
- `PolicyTimelock` 为进程内调度器，重启即失忆，生产化需接持久层
- Session key 尚无撤销列表（jti/revocation list），TTL 为当前唯一失效手段
- 中额时间锁到期后需调用方自行重试，暂无自动续签队列

# Attack Simulation Suite（攻击模拟套件）

对 Aegis Vault agent-keys 内存卫生机制（`secureZero` / `ShardedSecret`）的**可复现攻击验证**。在 Linux 部署环境运行，产出"修复前 / 修复后"对照数据。

## 四个标准场景

| # | 场景 | 脚本 | 模拟的攻击 | 修复后预期 |
|---|------|------|-----------|-----------|
| 1 | core dump 提取 | `dump-core.sh` | 进程崩溃 → core 文件落盘 → 攻击者搜索明文私钥 | `FULL-KEY-ABSENT` |
| 2 | 跨进程内存读取 | `read-proc-mem.sh` | root/ptrace 读取 `/proc/<pid>/mem` | `FULL-KEY-ABSENT` |
| 2b | gcore 内存镜像 | `gcore-scan.sh` | gdb gcore 导出完整内存（无需崩溃） | `FULL-KEY-ABSENT` |
| 3 | 环境泄露 | `env-leak.sh` | env / argv / 日志中搜索明文 | `ENV-LEAK-ABSENT` |
| 4 | swap 泄露 | `swap-scan.sh` | 扫描 swap 分区 | `SWAP-LEAK-ABSENT` |

## 使用方法

```bash
cd packages/agent-keys/test/attack-simulations

# 终端 1：启动目标进程（修复后模式 = 默认）
ulimit -c unlimited
node victim.mjs &
VICTIM_PID=$!

# 终端 2：运行攻击场景
sudo ./read-proc-mem.sh $VICTIM_PID    # 场景 2
sudo ./gcore-scan.sh $VICTIM_PID       # 场景 2b
./env-leak.sh $VICTIM_PID              # 场景 3
sudo ./swap-scan.sh                    # 场景 4
./dump-core.sh $VICTIM_PID             # 场景 1（进程将被终止）

# 对照组：修复前模式（连续明文持有，预期 FULL-KEY-FOUND）
node victim.mjs --legacy &
sudo ./gcore-scan.sh <new-pid>
```

## 修复前后对照记录

> 在目标部署环境实测后填写，作为对外披露的实测证据。

| 场景 | 修复前（--legacy） | 修复后（默认） | 部署环境 |
|------|------------------|--------------|---------|
| 1 core dump | FULL-KEY-FOUND | FULL-KEY-ABSENT | _待测：Ubuntu 22.04 / Node 20_ |
| 2 /proc/mem | FULL-KEY-FOUND | FULL-KEY-ABSENT | _待测_ |
| 2b gcore | FULL-KEY-FOUND | FULL-KEY-ABSENT | _待测_ |
| 3 env/argv/log | ABSENT（设计上不经过） | ABSENT | _待测_ |
| 4 swap | 取决于内核换页 | ABSENT（建议加密 swap） | _待测_ |

## 诚实边界（与 src/secure.js 头部声明一致）

本套件验证的是：**完整连续明文私钥不驻留可扫描内存**。它不（也不能）验证：

1. V8 栈上临时拷贝 / JIT 中间数据（毫秒窗口内存在，无法从 dump 稳定复现）
2. `@noble/post-quantum` 库内部副本（库的内存卫生责任，待独立审计）
3. DMA / 冷启动等物理内存读取（TEE 领域，见部署加固清单）
4. 签名瞬间的毫秒级窗口命中（理论可达，攻击成本极高）

绝对承诺属于 TEE 的定义域；本套件证明的是**暴露窗口压缩 + 攻击成本提升**。

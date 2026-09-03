#!/usr/bin/env bash
# 场景 2b：gcore 完整内存镜像
# 用 gdb 的 gcore 生成运行中进程的完整核心转储（无需崩溃）
#
# 前置: gdb 已安装；root 或 ptrace 权限
# 用法: sudo ./gcore-scan.sh <pid>
set -euo pipefail
PID="${1:?usage: sudo gcore-scan.sh <pid>}"
OUT="gcore.${PID}.bin"

command -v gdb >/dev/null || { echo "[gcore-scan] gdb not installed" >&2; exit 3; }

echo "[gcore-scan] generating core image of PID $PID..."
gcore -o "$OUT" "$PID" >/dev/null
# gcore 输出文件名为 <prefix>.<pid>
[ -f "$OUT" ] || OUT="${OUT}.${PID}"

echo "[gcore-scan] core saved: $OUT ($(stat -c%s "$OUT") bytes)"
node scan-dump.mjs "$OUT" marker.fullkey.txt

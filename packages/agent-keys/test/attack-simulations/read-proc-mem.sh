#!/usr/bin/env bash
# 场景 2：跨进程内存读取（/proc/<pid>/mem）
# 模拟攻击者用 root/ptrace 权限直接读取运行中进程内存
#
# 前置: root 或 ptrace 权限（kernel.yama.ptrace_scope 允许）
# 用法: sudo ./read-proc-mem.sh <pid>
set -euo pipefail
PID="${1:?usage: sudo read-proc-mem.sh <pid>}"
OUT="procmem.${PID}.bin"

echo "[read-proc-mem] dumping readable regions of PID $PID..."
: > "$OUT"
# 遍历可读的私有内存段（跳过共享库/映射文件），逐段读出
for range in $(awk '/^[0-9a-f]-[0-9a-f] r..p/ {print $1}' "/proc/$PID/maps" 2>/dev/null); do
  start="${range%%-*}"; end="${range##*-}"
  start=$((16#$start)); end=$((16#$end))
  size=$((end - start))
  # 跳过超大段（>512MB，防止误读保留区）
  [ "$size" -gt 536870912 ] && continue
  dd if="/proc/$PID/mem" of="seg.tmp" bs=4096 skip=$((start / 4096)) \
     count=$(((size + 4095) / 4096)) status=none 2>/dev/null || continue
  cat "seg.tmp" >> "$OUT"
done
rm -f "seg.tmp"

echo "[read-proc-mem] dumped $(stat -c%s "$OUT") bytes → $OUT"
node scan-dump.mjs "$OUT" marker.fullkey.txt

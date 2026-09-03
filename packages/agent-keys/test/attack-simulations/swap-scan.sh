#!/usr/bin/env bash
# 场景 4：swap 分区泄露
# 验证运行过程中私钥未进入 swap（需 root；建议生产配置加密 swap）
#
# 前置: root；系统存在活跃 swap
# 用法: sudo ./swap-scan.sh
set -euo pipefail
FULLKEY=$(cat marker.fullkey.txt)
FOUND=0

command -v swapon >/dev/null || { echo "[swap-scan] swapon not available"; exit 3; }

mapfile -t SWAPS < <(swapon --show=NAME --noheadings 2>/dev/null || true)
[ "${#SWAPS[@]}" -gt 0 ] || { echo "[swap-scan] no active swap — result trivially clean"; exit 0; }

for dev in "${SWAPS[@]}"; do
  echo "[swap-scan] scanning $dev (this may take a while) ..."
  # 逐块读取 swap 设备并在原始流中搜索明文（跳过前 4KB swap 头）
  if dd if="$dev" bs=1M skip=1 status=none 2>/dev/null | grep -aq "$FULLKEY"; then
    echo "RESULT: SWAP-LEAK-FOUND on $dev"
    FOUND=1
  else
    echo "  clean on $dev"
  fi
done

[ "$FOUND" -eq 0 ] && echo "RESULT: SWAP-LEAK-ABSENT"
exit $FOUND

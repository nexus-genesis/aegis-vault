#!/usr/bin/env bash
# 场景 3：环境变量 / 命令行 / 日志泄露
# 验证私钥从不进入 env、argv、stdout/stderr
#
# 用法: ./env-leak.sh <pid> [log-dir]
set -euo pipefail
PID="${1:?usage: env-leak.sh <pid> [log-dir]}"
LOGDIR="${2:-.}"
FULLKEY=$(cat marker.fullkey.txt)
FAIL=0

echo "[env-leak] checking /proc/$PID/environ ..."
if tr '\0' '\n' < "/proc/$PID/environ" 2>/dev/null | grep -qi "$FULLKEY"; then
  echo "RESULT: ENV-LEAK-FOUND"; FAIL=1
else
  echo "  clean — full key not in environment"
fi

echo "[env-leak] checking /proc/$PID/cmdline ..."
if tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null | grep -qi "$FULLKEY"; then
  echo "RESULT: ARGV-LEAK-FOUND"; FAIL=1
else
  echo "  clean — full key not in command line"
fi

echo "[env-leak] scanning logs in $LOGDIR ..."
if compgen -G "$LOGDIR/*.log" >/dev/null; then
  if grep -qil "$FULLKEY" "$LOGDIR"/*.log 2>/dev/null; then
    echo "RESULT: LOG-LEAK-FOUND"; FAIL=1
  else
    echo "  clean — full key not in logs"
  fi
else
  echo "  no .log files to scan"
fi

[ "$FAIL" -eq 0 ] && echo "RESULT: ENV-LEAK-ABSENT (all channels clean)"
exit $FAIL

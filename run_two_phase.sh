#!/usr/bin/env bash
# 两阶段 libFuzzer 批量(自动:Phase1 跑完 → 自动接 Phase2):
#   Phase1  全量 × 短预算(先收好撞的、建 corpus)
#   Phase2  只对 Phase1 没出 PoC 的,续跑长预算(复用 Phase1 的 corpus 累积)
#
# 用法: ./run_two_phase.sh [OUT_DIR] [P1_SECS] [P2_SECS] [JOBS] [LANGS] [LIMIT]
#   LANGS 空=全部三种语言; 或 c_cpp / python / go / "c_cpp,python"
#   LIMIT 0=全部;>0 只取前 N 个(小样本验证用)
set -Eeuo pipefail
cd "$(dirname "$0")"

OUT="${1:-./out_$(date +%m%d_%H%M)}"
P1="${2:-300}"      # 第一阶段每个 target 秒数
P2="${3:-1800}"     # 第二阶段每个 target 秒数
JOBS="${4:-4}"
LANGS="${5:-}"
LIMIT="${6:-0}"

OUT="$(mkdir -p "$OUT" && cd "$OUT" && pwd)"   # 转绝对路径
LIM_ARG=(); [ "$LIMIT" -gt 0 ] && LIM_ARG=(--limit "$LIMIT")
# 用 fix.diff 定向(字典+focus,纯脚本无 agent)。设 USE_DIFF=0 可关。
DIFF_ARG=(--use-diff); [ "${USE_DIFF:-1}" = "0" ] && DIFF_ARG=()
# fork 模式子进程数(每个 task 内)。设 FORK=0 关闭。默认 2。
FORK_ARG=(); [ "${FORK:-2}" -gt 0 ] && FORK_ARG=(--fork "${FORK:-2}")
# 续跑:RESUME=1 时 Phase1 跳过已完成的 task(error 的重跑),结果追加不覆盖。
RESUME_ARG=(); [ "${RESUME:-0}" = "1" ] && RESUME_ARG=(--resume)
# agent 脚手架:AGENT=1 开启(读 description+diff 产种子/字典喂 fuzz)。需 OPENAI_BASE_URL+key。
AGENT_ARG=(); [ "${AGENT:-0}" = "1" ] && AGENT_ARG=(--agent-assist)

echo "================================================================"
echo "OUT=$OUT  P1=${P1}s  P2=${P2}s  JOBS=$JOBS  LANGS=${LANGS:-all}  LIMIT=$LIMIT  USE_DIFF=${USE_DIFF:-1}  FORK=${FORK:-2}"
echo "start: $(date '+%F %T')"
echo "================================================================"

echo; echo "########## PHASE 1 (全量 ${P1}s) ##########"
python3 fuzz_batch.py --out "$OUT" --phase p1 --secs "$P1" \
        --jobs "$JOBS" --langs "$LANGS" "${LIM_ARG[@]}" "${DIFF_ARG[@]}" "${FORK_ARG[@]}" "${RESUME_ARG[@]}" "${AGENT_ARG[@]}" --write-back

echo; echo "########## PHASE 2 (仅失败项续跑 ${P2}s) ##########"
python3 fuzz_batch.py --out "$OUT" --phase p2 --secs "$P2" \
        --jobs "$JOBS" --langs "$LANGS" "${LIM_ARG[@]}" "${DIFF_ARG[@]}" "${FORK_ARG[@]}" "${AGENT_ARG[@]}" --write-back --skip-succeeded

echo; echo "########## 全部完成 · 汇总 ##########"
echo "end: $(date '+%F %T')"
python3 fuzz_batch.py --out "$OUT" --status
echo
echo "累计成功 PoC 数: $(wc -l < "$OUT/success_ledger.txt" 2>/dev/null || echo 0)"
echo "成功清单:  $OUT/success_ledger.txt"
echo "逐条明细:  $OUT/results_p1.jsonl  $OUT/results_p2.jsonl"
echo "实时流水:  $OUT/run.log"

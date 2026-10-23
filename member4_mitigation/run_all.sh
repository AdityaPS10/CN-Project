#!/bin/bash
# Member 4 - runs the full experiment matrix, then builds the comparison.
#
#   bash member4_mitigation/run_all.sh            # 1 repeat  (30 runs, ~50 min)
#   REPEATS=3 bash member4_mitigation/run_all.sh  # 3 repeats (90 runs, ~2.5 h)
#   CONFIGS="entropy:on" bash member4_mitigation/run_all.sh   # only some configurations
#
# Matrix: 6 traffic configurations (normal, flash_crowd, naive_ddos,
# adaptive_ddos subtle/moderate/aggressive) x
#   - combined detector + mitigation ON   (proposed system)
#   - combined detector + mitigation OFF  (no-mitigation baseline)
#   - threshold-only    + mitigation ON   (detector baseline)
#   - cusum-only        + mitigation ON   (detector baseline)
#   - entropy-only      + mitigation ON   (detector baseline)
# A failed run is reported and the matrix continues.
set -u
cd "$(dirname "$0")/.." || exit 1
REPEATS=${REPEATS:-1}
sudo -v || exit 1                      # ask for the password once, up front

TRAFFIC=("normal" "flash_crowd" "naive_ddos" "adaptive_ddos subtle"
         "adaptive_ddos moderate" "adaptive_ddos aggressive")
# CONFIGS env: space-separated detector:mitigation pairs, e.g. "combined:on entropy:on"
if [ -n "${CONFIGS:-}" ]; then
  read -r -a _cfg <<<"$CONFIGS"; CONFIGS=(); for c in "${_cfg[@]}"; do CONFIGS+=("${c/:/ }"); done
else
  CONFIGS=("combined on" "combined off" "threshold on" "cusum on" "entropy on")
fi
failed=()

for r in $(seq 1 "$REPEATS"); do
  for t in "${TRAFFIC[@]}"; do
    read -r scen level <<<"$t"
    for c in "${CONFIGS[@]}"; do
      read -r det mit <<<"$c"
      args=(--scenario "$scen" --detector "$det" --mitigation "$mit" --tag "r$r")
      [ -n "${level:-}" ] && args+=(--level "$level")
      echo; echo "######## repeat $r: ${args[*]}"
      sudo -v
      if ! sudo python3 member4_mitigation/run_experiment.py "${args[@]}"; then
        failed+=("${args[*]}")
        sudo mn -c >/dev/null 2>&1
      fi
    done
    level=""
  done
done

python3 -m member4_mitigation.compare
python3 -m member4_mitigation.offline_detection > /dev/null && echo "written: member4_mitigation/results/offline_detection.md"
if [ ${#failed[@]} -gt 0 ]; then
  echo; echo "FAILED RUNS (${#failed[@]}):"; printf '  %s\n' "${failed[@]}"; exit 1
fi
echo; echo "All runs finished."

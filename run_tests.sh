#!/bin/bash
# Runs every automated check that needs NO root, for all four members.
#
#   bash run_tests.sh
#
# Testbed checks that need root (Mininet/OVS) are separate:
#   bash member4_mitigation/verify_testbed.sh
#   sudo python3 member4_mitigation/run_experiment.py --scenario naive_ddos
set -u
cd "$(dirname "$0")" || exit 1
VENV_PY=${VENV_PY:-$HOME/ryu-venv/bin/python}
pass=0; fail=0; results=()

check() {          # check "<name>" <command...>
  local name=$1; shift
  echo; echo "=== $name"; echo "\$ $*"
  if "$@"; then results+=("PASS  $name"); pass=$((pass+1))
  else results+=("FAIL  $name"); fail=$((fail+1)); fi
}

check "M1 log validator on recorded logs" \
  python3 trafficgen/validate_log.py sdn-ddos-monitoring/validation/normal/h2.csv \
  sdn-ddos-monitoring/validation/flash_crowd/h2.csv sdn-ddos-monitoring/validation/naive_ddos/h2.csv \
  sdn-ddos-monitoring/validation/adaptive_ddos/h2.csv
# Syntax check without writing bytecode (generators run as root in Mininet, so a
# __pycache__ there may be root-owned and not writable by you).
check "M1 scripts compile" python3 -c "import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]; print('syntax OK:', len(sys.argv) - 1, 'files')" \
  trafficgen/common.py trafficgen/normal_traffic.py \
  trafficgen/flash_crowd_traffic.py trafficgen/naive_ddos_traffic.py trafficgen/adaptive_ddos_traffic.py \
  trafficgen/server.py trafficgen/validate_log.py topo/basic_topo.py topo/test_pingall.py
check "M2 unit tests" bash -c "cd sdn-ddos-monitoring && python3 -m unittest discover -s tests"
check "M2 feature CSV format" bash -c "cd sdn-ddos-monitoring && python3 tests/check_csv_format.py"
check "M2 features vs M1 ground truth (naive)" bash -c "cd sdn-ddos-monitoring && python3 tests/compare_ground_truth.py naive_ddos"
check "M3 unit tests" bash -c "cd detection && python3 -m unittest discover -s tests"
check "M3 evaluation reproduces README" bash -c "cd detection && python3 evaluate.py > /dev/null"
check "M4 unit/API/integration tests (system python)" python3 -m unittest discover -s member4_mitigation/tests -t .
if [ -x "$VENV_PY" ]; then
  check "M4 OpenFlow message serialization (os-ken)" "$VENV_PY" -m unittest member4_mitigation.tests.test_flow_rules_osken
  check "Controller apps import under os-ken" env PYTHONPATH=.:sdn-ddos-monitoring "$VENV_PY" -c \
    "import controller.simple_switch_13, monitor, member4_mitigation.mitigation_app; print('imports OK')"
else
  results+=("SKIP  os-ken checks ($VENV_PY not found)")
fi
find . -name __pycache__ -not -path './.git/*' -prune -exec rm -rf {} + 2>/dev/null

echo; echo "=========== SUMMARY"; printf '%s\n' "${results[@]}"
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]

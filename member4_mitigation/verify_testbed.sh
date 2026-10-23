#!/bin/bash
# Member 4 - testbed smoke test: controller + Member 1's pingall check.
#
#   bash member4_mitigation/verify_testbed.sh
#
# 1. checks OVS supports OpenFlow 1.3 meters on a throw-away bridge;
# 2. starts the controller (Member 1 switch + Member 2 monitor + Member 4 app)
#    as YOU, in the background, logging to member4_mitigation/logs/verify_controller.log;
# 3. runs topo/test_pingall.py (Member 1's non-interactive connectivity test);
# 4. stops the controller and cleans up Mininet.
# Exit code 0 only if every step passed.
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
VENV_PY=${VENV_PY:-$HOME/ryu-venv/bin/python}
LOG=member4_mitigation/logs/verify_controller.log
mkdir -p member4_mitigation/logs
fail=0

if ss -ltn | grep -q ':6653 '; then
  echo "FAIL: port 6653 already in use - stop the other controller first (ss -ltnp | grep 6653)"; exit 1
fi
sudo -v || exit 1

echo "== 1. OpenFlow 1.3 meter support (throw-away bridge m4verify)"
sudo ovs-vsctl --may-exist add-br m4verify -- set bridge m4verify protocols=OpenFlow13
feat=$(sudo ovs-ofctl -O OpenFlow13 meter-features m4verify)
sudo ovs-ofctl -O OpenFlow13 add-meter m4verify meter=1,pktps,band=type=drop,rate=10
meters=$(sudo ovs-ofctl -O OpenFlow13 dump-meters m4verify)
sudo ovs-vsctl del-br m4verify
echo "$feat" | grep -E "max_meter|band_types"
if echo "$meters" | grep -q "meter=1 pktps" && echo "$feat" | grep -q "band_types: drop"; then
  echo "PASS: meters supported"
else
  echo "FAIL: meters not supported"; fail=1
fi

echo "== 2. controller (switch + monitor + mitigation app)"
PYTHONPATH=$ROOT:$ROOT/sdn-ddos-monitoring M4_RUN_DIR=$ROOT/member4_mitigation/logs/verify \
  "$VENV_PY" tools/osken_run.py controller.simple_switch_13 monitor member4_mitigation.mitigation_app \
  > "$LOG" 2>&1 &
CTL=$!
for _ in $(seq 1 50); do ss -ltn | grep -q ':6653 ' && break; sleep 0.2; done
if ss -ltn | grep -q ':6653 '; then echo "PASS: controller listening on 6653 (pid $CTL)"
else echo "FAIL: controller did not start, see $LOG"; kill $CTL 2>/dev/null; exit 1; fi

echo "== 3. Mininet pingall (topo/test_pingall.py)"
if sudo python3 topo/test_pingall.py 2>&1 | tee member4_mitigation/logs/verify_pingall.log | grep -E "drop percentage|PASS|FAIL"; then :; fi
grep -q "^PASS" member4_mitigation/logs/verify_pingall.log || fail=1
grep -q "switch connected" "$LOG" && echo "PASS: Member 4 app saw the switch connect" || { echo "FAIL: app did not see the switch"; fail=1; }

echo "== 4. cleanup"
# os-ken often ignores the first Ctrl+C (thread join), so wait up to 5 s, then force.
kill -INT $CTL 2>/dev/null
for _ in $(seq 1 10); do kill -0 $CTL 2>/dev/null || break; sleep 0.5; done
kill -9 $CTL 2>/dev/null; wait $CTL 2>/dev/null
echo "controller stopped"
sudo mn -c >/dev/null 2>&1
rm -f sdn-ddos-monitoring/data/features.csv sdn-ddos-monitoring/data/features_2*.csv
[ $fail -eq 0 ] && echo "ALL TESTBED CHECKS PASSED" || echo "SOME TESTBED CHECKS FAILED"
exit $fail

#!/bin/bash
# Usage: bash tests/check_scenario.sh flash_crowd
cd ~/member2_monitoring || exit 1
cp data/features.csv data/features_$1.csv
python3 ~/member1_traffic/trafficgen/validate_log.py validation/$1/*.csv
python3 tests/compare_ground_truth.py $1

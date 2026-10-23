#!/bin/bash
# Usage: bash tests/check_scenario.sh flash_crowd
cd "$(dirname "$0")/.." || exit 1
cp data/features.csv data/features_$1.csv
python3 ../trafficgen/validate_log.py validation/$1/*.csv
python3 tests/compare_ground_truth.py $1

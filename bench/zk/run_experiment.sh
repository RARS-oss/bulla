#!/usr/bin/env bash
# Zero-knowledge risk-limit proof (real Bulletproofs). An autonomous trading agent proves its order
# is within a committed risk cap WITHOUT revealing the order size or the strategy; a broker verifies.
# Complements the sandbox: the receipt proves the code ran sealed; this proves the order is bounded,
# privately.
#
# Run in Linux/WSL2:  bash bench/zk/run_experiment.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"
out="$(cargo run -q -p bulla-zk --example risk_proof 2>&1)"
echo "$out"
echo
echo "$out" | grep -q "within risk cap = true"        && echo "[assert] in-cap order verifies (value stays hidden)" || { echo "FAIL: in-cap"; exit 1; }
echo "$out" | grep -q "over-cap order verifies = false" && echo "[assert] over-cap order is rejected"                || { echo "FAIL: over-cap"; exit 1; }
echo "$out" | grep -q "tampered proof verifies = false" && echo "[assert] tampered proof is rejected"                || { echo "FAIL: tamper"; exit 1; }

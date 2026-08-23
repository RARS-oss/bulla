#!/usr/bin/env bash
# Decisive demo (metric-gaming vector): a flaky test run many times. bulla chains every attempt into
# a tamper-evident ledger, so the honest pass rate is on the record and a lucky run can't be reported
# as pass@1 by quietly dropping the failures — deleting an attempt breaks the chain.
#
# Run in Linux/WSL2:  bash bench/flaky/run_experiment.sh  [path-to-bulla-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$(command -v bulla || echo "$HOME/.cache/bulla-target/debug/bulla")}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }

W="$(mktemp -d)"; cp "$HERE/flaky_test.py" "$W/"
LDIR="$(mktemp -d)"; L="$LDIR/ledger.jsonl"   # ledger lives OUTSIDE the cell-writable work dir
trap 'rm -rf "$W" "$LDIR"' EXIT

N=7
echo "Running the same flaky test $N times under bulla (shared ledger)…"
for i in $(seq 1 "$N"); do
  "$BIN" run --work "$W" --ledger "$L" --out "$W/.bulla/receipt.json" -- python3 flaky_test.py >/dev/null 2>&1
done

echo
echo "## bulla log — the honest pass rate, tamper-evident:"
"$BIN" log "$L"

echo
echo "## Cherry-pick attempt: delete one attempt to hide a failure…"
python3 - "$L" "$L.cherry" <<'PY'
import json, sys
lines = [json.loads(x) for x in open(sys.argv[1]) if x.strip()]
drop = len(lines) // 2
kept = [e for i, e in enumerate(lines) if i != drop]
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in kept))
print(f"  dropped attempt #{drop} (of {len(lines)}); presenting {len(kept)} as the record")
PY
echo "## bulla log on the tampered ledger — must be flagged BROKEN:"
"$BIN" log "$L.cherry" || echo "  -> bulla log exited non-zero (chain broken, as it should)"

echo
echo "  The ledger records every attempt and the honest pass rate; dropping any interior attempt"
echo "  breaks the hash chain, so a flaky pass can't be laundered into pass@1. (Truncating the most"
echo "  recent attempts needs an external witness — the future Rekor/transparency-log anchor.)"

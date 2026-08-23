#!/usr/bin/env bash
# Decisive demo (network-retrieval vector): the SAME "retrieval solver" passes under a leaky harness
# and fails under bulla's seal — and each run carries a signed receipt saying which regime produced it.
# A controlled, deterministic reproduction of Cursor's finding (network on -> retrieved "pass").
#
# Run in Linux/WSL2:  bash bench/retrieval/run_experiment.sh  [path-to-bulla-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$(command -v bulla || echo "$HOME/.cache/bulla-target/debug/bulla")}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }
PORT=8791

# 1) Host-side mock "upstream" that serves the correct fix (reachable only via the host net namespace).
UP="$(mktemp -d)"
cat > "$UP/calc_fixed.py" <<'PY'
def add(a, b):
    return a + b
PY
( cd "$UP" && python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
SRV=$!

WL="$(mktemp -d)"; WS="$(mktemp -d)"
trap 'kill "$SRV" 2>/dev/null; rm -rf "$UP" "$WL" "$WS"' EXIT
sleep 0.6

# fresh copy of the buggy task per regime
for d in "$WL" "$WS"; do cp "$HERE"/task/calc.py "$HERE"/task/test_calc.py "$HERE"/task/solver.sh "$d"/; done

line() { printf '%s\n' "------------------------------------------------------------"; }
verdict() { "$BIN" verify "$1" | grep -E "seal held|outcome"; }

echo; line; echo "A) LEAKY harness   (bulla run --allow-net : host network reachable)"; line
"$BIN" run --work "$WL" --allow-net --out "$WL/receipt.json" -- sh solver.sh
echo "   -> verify:"; verdict "$WL/receipt.json" | sed 's/^/     /'

echo; line; echo "B) SEALED cell     (bulla run : network denied by default)"; line
"$BIN" run --work "$WS" --out "$WS/receipt.json" -- sh solver.sh
echo "   -> verify:"; verdict "$WS/receipt.json" | sed 's/^/     /'

# 2) The result table, read straight out of the two signed receipts.
ec() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['body']['outcome']['exit_code'])" "$1"; }
sk() { python3 -c "import json,sys;print('HELD' if json.load(open(sys.argv[1]))['body']['seal_ok'] else 'BROKEN')" "$1"; }
pf() { [ "$1" = "0" ] && echo PASS || echo FAIL; }
echo; line; echo "RESULT (from the signed receipts)"; line
printf "  %-18s test=%-4s  seal=%s\n" "leaky (net on)"  "$(pf "$(ec "$WL/receipt.json")")" "$(sk "$WL/receipt.json")"
printf "  %-18s test=%-4s  seal=%s\n" "sealed (net off)" "$(pf "$(ec "$WS/receipt.json")")" "$(sk "$WS/receipt.json")"
echo
echo "  The leaky PASS is retrieved, not derived — and its receipt says SEAL=BROKEN, so a"
echo "  leaderboard can reject it. Sealing the harness flips it to the honest FAIL. Same solver,"
echo "  same task, same binary; only the seal differs. This is Cursor's 87.1% -> 73.0% in miniature."

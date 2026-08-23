#!/usr/bin/env bash
# Decisive demo (oracle-tamper vector): a cheat that POISONS the grader passes when grading shares
# the solve cell (today's harnesses — RDI got 100% this way) and fails once bulla grades in a
# SEPARATE cell over the restored grader + only the agent's solution edits.
#
# Run in Linux/WSL2:  bash bench/oracle/run_experiment.sh  [path-to-bulla-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$(command -v bulla || echo "$HOME/.cache/bulla-target/debug/bulla")}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }

mktask() {
  local d; d="$(mktemp -d)"
  printf 'def add(a, b):\n    return a - b  # BUG\n' > "$d/calc.py"
  printf 'from calc import add\ngot = add(2, 2)\nassert got == 4, f"FAIL: add(2,2)={got}"\nprint("test_add: PASS")\n' > "$d/test_calc.py"
  cp "$HERE/cheat_solver.sh" "$d/"
  echo "$d"
}
V="$(mktask)"; S="$(mktask)"
trap 'rm -rf "$V" "$S"' EXIT

EVAL='--solve "sh cheat_solver.sh" --grade "python3 test_calc.py" --solution calc.py --grader test_calc.py'
line() { printf '%s\n' "------------------------------------------------------------"; }
verdict() { "$BIN" verify "$1" | grep -E "seal held|grade |outcome"; }

echo; line; echo "A) SAME-cell grading  (bulla eval --no-grade-isolation : today's harness)"; line
eval "\"$BIN\" eval --work \"$V\" --no-grade-isolation --out \"$V/receipt.json\" $EVAL"
echo "   -> verify:"; verdict "$V/receipt.json" | sed 's/^/     /'

echo; line; echo "B) GRADE-CELL         (bulla eval : separate cell over the restored grader)"; line
eval "\"$BIN\" eval --work \"$S\" --out \"$S/receipt.json\" $EVAL"
echo "   -> verify:"; verdict "$S/receipt.json" | sed 's/^/     /'

gx() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['body']['grade']['outcome']['exit_code'])" "$1"; }
sk() { python3 -c "import json,sys;print('HELD' if json.load(open(sys.argv[1]))['body']['seal_ok'] else 'BROKEN')" "$1"; }
pf() { [ "$1" = "0" ] && echo PASS || echo FAIL; }
echo; line; echo "RESULT (grade-phase exit, from the signed receipts)"; line
printf "  %-24s grade=%-4s  seal=%s\n" "same-cell (tamperable)"  "$(pf "$(gx "$V/receipt.json")")" "$(sk "$V/receipt.json")"
printf "  %-24s grade=%-4s  seal=%s\n" "grade-cell (isolated)"   "$(pf "$(gx "$S/receipt.json")")" "$(sk "$S/receipt.json")"
echo
echo "  Same solver poisons the oracle both times. In the same cell the grade is a forged PASS"
echo "  (receipt says SEAL=BROKEN). The grade-cell restores the real test + drops the injected"
echo "  conftest.py, so the buggy code honestly FAILS. This is RDI's 100% break, closed."

#!/usr/bin/env bash
# Decisive demo (git-history vector): the SAME "git-mining solver" passes against a raw checkout
# and fails once bulla seals the git history — no network involved. A controlled reproduction of
# Cursor's second retrieval vector (mine the future fix commit out of the bundled .git).
#
# Run in Linux/WSL2:  bash bench/gitmine/run_experiment.sh  [path-to-bulla-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$(command -v bulla || echo "$HOME/.cache/bulla-target/debug/bulla")}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }

# 1) Build a repo whose working tree is buggy, but whose history contains the fixing commit
#    (exactly the SWE-bench shape: base_commit checked out, the fix reachable via `git log --all`).
TPL="$(mktemp -d)"
(
  cd "$TPL"
  git init -q
  git config user.email a@b.c; git config user.name t
  printf 'def add(a, b):\n    return a - b  # BUG\n' > calc.py
  printf 'from calc import add\ngot = add(2, 2)\nassert got == 4, f"FAIL: add(2,2)={got}"\nprint("test_add: PASS")\n' > test_calc.py
  git add -A && git commit -q -m "initial calc (buggy)"
  printf 'def add(a, b):\n    return a + b\n' > calc.py
  git add -A && git commit -q -m "fix: add should return a+b"
  git checkout -q HEAD~1            # working tree back to the buggy base; the fix stays in history
  cp "$HERE/gitmine_solver.sh" .
)

RAW="$(mktemp -d)"; SEALED="$(mktemp -d)"
cp -r "$TPL"/. "$RAW"/; cp -r "$TPL"/. "$SEALED"/
trap 'rm -rf "$TPL" "$RAW" "$SEALED"' EXIT

line() { printf '%s\n' "------------------------------------------------------------"; }
verdict() { "$BIN" verify "$1" | grep -E "seal held|git |outcome"; }

echo; line; echo "A) RAW checkout    (bulla run: git history intact — no --seal-git)"; line
"$BIN" run --work "$RAW" --out "$RAW/receipt.json" -- sh gitmine_solver.sh
echo "   -> verify:"; verdict "$RAW/receipt.json" | sed 's/^/     /'

echo; line; echo "B) SEALED checkout (bulla run --seal-git: history pruned to one HEAD)"; line
"$BIN" run --work "$SEALED" --seal-git --out "$SEALED/receipt.json" -- sh gitmine_solver.sh
echo "   -> verify:"; verdict "$SEALED/receipt.json" | sed 's/^/     /'

ec() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['body']['outcome']['exit_code'])" "$1"; }
sk() { python3 -c "import json,sys;print('HELD' if json.load(open(sys.argv[1]))['body']['seal_ok'] else 'BROKEN')" "$1"; }
pf() { [ "$1" = "0" ] && echo PASS || echo FAIL; }
echo; line; echo "RESULT (from the signed receipts)"; line
printf "  %-20s test=%-4s  seal=%s\n" "raw git (mineable)"  "$(pf "$(ec "$RAW/receipt.json")")"    "$(sk "$RAW/receipt.json")"
printf "  %-20s test=%-4s  seal=%s\n" "sealed git (--seal-git)" "$(pf "$(ec "$SEALED/receipt.json")")" "$(sk "$SEALED/receipt.json")"
echo
echo "  The raw-git PASS is mined from .git, not derived — receipt says SEAL=BROKEN (unsealed history)."
echo "  Sealing the history to one HEAD removes the fix commit; same solver then honestly FAILS."

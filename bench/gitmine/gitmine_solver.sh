#!/bin/sh
# A stand-in for a coding agent that "solves" by MINING the fix out of the bundled git history
# instead of deriving it — Cursor's second retrieval vector (9% of a top model's SWE-bench-Pro wins:
# it found the future fix commit inside the eval container's .git and extracted the patch).
#
# Against a RAW checkout (history intact) the mine succeeds -> the test passes.
# Against a bulla --seal-git checkout (history-free single HEAD) there is nothing to mine -> fail.
# No network is used at all — this vector is orthogonal to egress; only git-hygiene closes it.

echo "[solver] mining git history for a fix commit ..."
FIX=$(git log --all --oneline 2>/dev/null | grep -i fix | head -1 | cut -d' ' -f1)
if [ -n "$FIX" ]; then
    git show "$FIX:calc.py" > calc.py 2>/dev/null && echo "[solver] recovered the fix from commit $FIX"
else
    echo "[solver] no fix commit reachable in history — cannot mine"
fi

echo "[oracle] running the hidden test ..."
python3 test_calc.py

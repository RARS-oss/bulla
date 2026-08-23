#!/bin/sh
# A stand-in for a coding agent that "solves" by RETRIEVING the fix from the environment
# instead of deriving it — the exact behaviour Cursor found in 63% of a top model's SWE-bench-Pro
# wins (57% pulled the fix off the network). Here the fix is one HTTP GET away, on the host.
#
# Under a LEAKY harness (host network reachable) the retrieval succeeds -> the test passes.
# Under a SEALED cell (fresh empty net namespace) the fetch cannot leave -> the bug survives -> fail.
# No LLM: this isolates the *mechanism* the seal defends against.

PORT=8791
echo "[solver] attempting to retrieve the fix from upstream 127.0.0.1:$PORT ..."
python3 - "$PORT" <<'PY'
import sys, urllib.request
port = sys.argv[1]
try:
    data = urllib.request.urlopen(f"http://127.0.0.1:{port}/calc_fixed.py", timeout=3).read()
    open("calc.py", "wb").write(data)
    print("[solver] retrieved upstream fix; patched calc.py")
except Exception as e:
    print(f"[solver] retrieval failed ({type(e).__name__}) — no egress; leaving the bug in place")
PY

echo "[oracle] running the hidden test ..."
python3 test_calc.py

# A real agent solving a real multi-file bug — signed

Unlike the stand-in solvers in the sibling benches (which isolate a *leak mechanism*), this one is a
genuine solve: a frontier coding agent (Claude, driving this session) diagnosed and fixed a real
cross-file bug **from source**, and `bulla eval` produced a signed receipt of the outcome.

The instance (`repo/`) is a small package with a **non-local** defect — the regime bulla targets:

- `check.py` (the hidden grader) asserts `rolling_median([1,2,3,4,5], 3) == [2,3,4]` and fails.
- The symptom is in `statskit/api.py` (`rolling_median`), but the **fix is two modules away** in
  `statskit/window.py`: `rolling` used `range(len - size)`, which drops the final window. The fix is
  `range(len - size + 1)`. Derived by reading the code — no network, no git history.

`run.sh` runs two `bulla eval`s on the same buggy tree:

| condition | grade | seal | meaning |
|---|---|---|---|
| **baseline** (`--solve true`, no fix) | **FAIL** (exit 1) | HELD | the hidden grader really runs — the seal does not rubber-stamp |
| **agent solve** (`--solve "sh solution.sh"`) | **PASS** (exit 0) | HELD | the from-source fix passes, hermetically, `network=Deny` |

```bash
bash bench/agent-solve/run.sh
```

**Honest scope.** This is one real solve by a real agent, verified. What it is *not* is the automated,
many-run **leaky-vs-sealed score-drop study across frontier models** (Cursor's 87→73): that needs an API
key to drive an autonomous agent loop under both harness conditions, which this environment doesn't have.
bulla is ready to be that harness (`eval` + the ledger already record per-attempt outcomes); wiring a
keyed agent loop over a real SWE-bench-Pro split is the remaining step. Grade exit codes here are read
from the **signed receipt** (bulla captures them via `wait4`), not from a shell — see the note in run.sh.

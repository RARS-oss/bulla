#!/usr/bin/env bash
# Determinism / reproducibility, stated precisely. Run the SAME command over the SAME inputs twice
# (receipts + key written OUTSIDE the work dir, so the hashed work tree is byte-identical). Under the
# hermetic deterministic profile the OUTPUT digests reproduce exactly; the signed body does NOT (it
# carries a wall-clock timestamp), so body_digest differs. That is the honest reproducibility claim.
#
# Run in Linux/WSL2:  bash bench/determinism/run_experiment.sh  [path-to-bulla-binary]
set -u
BIN="${1:-$HOME/.cache/bulla-target/debug/bulla}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }

W="$(mktemp -d)"; OUT="$(mktemp -d)"
printf 'x = 41\nprint(x + 1)\n' > "$W/task.py"
KEY="$OUT/key.seed"
trap 'rm -rf "$W" "$OUT"' EXIT

"$BIN" run --work "$W" --key "$KEY" --out "$OUT/r1.json" --ledger "$OUT/l.jsonl" -- sh -c "python3 task.py" >/dev/null 2>&1
"$BIN" run --work "$W" --key "$KEY" --out "$OUT/r2.json" --ledger "$OUT/l.jsonl" -- sh -c "python3 task.py" >/dev/null 2>&1

python3 - "$OUT/r1.json" "$OUT/r2.json" <<'PY'
import json, sys
r1 = json.load(open(sys.argv[1])); r2 = json.load(open(sys.argv[2]))
a, b = r1["body"], r2["body"]
so = a["outcome"]["stdout_sha256"] == b["outcome"]["stdout_sha256"]
ir = a["inputs"]["root"] == b["inputs"]["root"]
bd = r1["body_digest"] == r2["body_digest"]
print(f"  stdout_sha256 identical : {so}")
print(f"  inputs_root   identical : {ir}")
print(f"  body_digest   identical : {bd}   (expected False — the body carries created_epoch)")
assert so and ir and not bd, "determinism claim violated"
print("\n[assert] the deterministic OUTPUTS reproduce byte-for-byte; the timestamped body does not —")
print("         exactly what the receipt claims. A skeptic re-checks the output hashes, not body_digest.")
PY

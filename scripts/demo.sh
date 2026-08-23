#!/usr/bin/env bash
# bulla Phase-0 demo: seal a real run, prove the receipt attests "network was off",
# show the sealed-vs-open contrast, and show that tampering the receipt is detected.
#
# Run inside Linux/WSL2:  bash scripts/demo.sh  [path-to-bulla-binary]
set -u

BIN="${1:-$(command -v bulla || echo "$HOME/.cache/bulla-target/debug/bulla")}"
if [ ! -x "$BIN" ]; then echo "bulla binary not found: $BIN"; exit 1; fi
echo "== using $BIN =="

DEMO="$(mktemp -d /tmp/bulla-demo.XXXXXX)"
trap 'rm -rf "$DEMO"' EXIT
cat > "$DEMO/task.py" <<'PY'
def add(a, b):
    return a - b          # the bug under test
PY
cat > "$DEMO/probe.sh" <<'SH'
echo "hello from the sealed cell"
python3 - <<'PY'
import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("1.1.1.1", 53)); print("NET_UP: reached 1.1.1.1:53")
except Exception:
    print("NET_DOWN: no egress from the cell")
PY
echo "test_add ... FAILED (add(2,2) == 0, expected 4)"
exit 1   # the task's test fails under an honest run
SH

echo
echo "############################################################"
echo "# 1) SEALED run  (network denied by default)"
echo "############################################################"
"$BIN" run --work "$DEMO" --out "$DEMO/sealed.json" -- sh probe.sh
echo
"$BIN" verify "$DEMO/sealed.json"

echo
echo "############################################################"
echo "# 2) OPEN run  (--allow-net: contrast; seal must NOT hold)"
echo "############################################################"
"$BIN" run --work "$DEMO" --allow-net --out "$DEMO/open.json" -- sh probe.sh
echo
"$BIN" verify "$DEMO/open.json" | sed -n '1,12p'

echo
echo "############################################################"
echo "# 3) TAMPER the sealed receipt  -> verification must FAIL"
echo "############################################################"
python3 - "$DEMO/sealed.json" "$DEMO/tampered.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
# a lab quietly upgrades the failing run (exit 1) to a clean pass (exit 0):
r["body"]["outcome"]["exit_code"] = 0
json.dump(r, open(sys.argv[2], "w"), indent=2)
print("  (forged outcome.exit_code 1 -> 0; body_digest and signature left as-is —")
print("   re-signing is impossible without the private key)")
PY
echo
"$BIN" verify "$DEMO/tampered.json" || echo "  -> bulla verify exited non-zero (as it should)"

echo
echo "############################################################"
echo "# 4) The signed artifact (a 'bulla')"
echo "############################################################"
sed -n '1,60p' "$DEMO/sealed.json"

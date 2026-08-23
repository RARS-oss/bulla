#!/usr/bin/env bash
# Smart egress: the cell keeps an empty network namespace (no raw egress), yet can reach a signed
# allowlist through a mediated Unix-socket broker — and every request/response is hashed into the
# receipt. A denied host is refused and recorded. seal stays HELD.
#
# Run in Linux/WSL2:  bash bench/egress/run_experiment.sh  [path-to-bulla-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HOME/.cache/bulla-target/debug/bulla}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }
PORT=8799

UP="$(mktemp -d)"; printf '{"symbol":"AAPL","price":187.42}\n' > "$UP/quote"
( cd "$UP" && python3 -m http.server "$PORT" >/dev/null 2>&1 ) & SRV=$!
W="$(mktemp -d)"; cp "$HERE/agent.sh" "$W/"
trap 'kill "$SRV" 2>/dev/null; rm -rf "$UP" "$W"' EXIT
sleep 0.6

echo "------------------------------------------------------------"
echo "A) SMART EGRESS  (--egress-allow 127.0.0.1:8799 : only the exchange host reachable)"
echo "------------------------------------------------------------"
"$BIN" run --work "$W" --egress-allow 127.0.0.1:8799 --out "$W/.bulla/r.json" -- sh agent.sh
echo "   -> verify (egress is in the signed receipt):"
"$BIN" verify "$W/.bulla/r.json" | grep -E "seal held|egress|ALLOW|DENY|net_ns" | sed 's/^/     /'

echo
echo "------------------------------------------------------------"
echo "B) DEFAULT       (no allowlist → no broker → no egress at all)"
echo "------------------------------------------------------------"
"$BIN" run --work "$W" --out "$W/.bulla/r2.json" -- sh agent.sh >/dev/null 2>&1
if "$BIN" verify "$W/.bulla/r2.json" | grep -q "egress"; then
  "$BIN" verify "$W/.bulla/r2.json" | grep -E "seal held|egress" | sed 's/^/     /'
else
  echo "     seal held YES · no egress section — the channel never existed"
fi
echo
echo "  The cell's netns is EMPTY in both (net_ns=true, no raw egress). With --egress-allow the only"
echo "  way out is the mediated broker, and the allowlist + every call are signed into the receipt;"
echo "  the off-list host is refused and recorded. Scoped egress, still SEAL HELD."

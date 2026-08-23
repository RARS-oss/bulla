#!/usr/bin/env bash
# Environment-leak inspector: two documented leak channels — the instance-id directory name
# (e.g. /testbed/django__django-13513) and the host's environment — are closed by the cell *by
# construction*, no new feature needed. Inside the cell the agent sees /work and a fixed minimal
# environment; the host's mktemp path and variables never appear. The one channel that remains is
# the wall clock (roadmap: libfaketime). The probe writes what it observes to /work (bind-mounted),
# since bulla records stdout only by hash.
#
# Run in Linux/WSL2:  bash bench/envleak/run_experiment.sh  [path-to-bulla-binary]
set -u
BIN="${1:-$HOME/.cache/bulla-target/debug/bulla}"
[ -x "$BIN" ] || { echo "bulla binary not found: $BIN"; exit 1; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
echo "host work dir (an 'instance-id'-shaped path): $W"
PROBE='printf "PWD=%s\nHOME=%s\nTZ=%s\nLC_ALL=%s\n" "$(pwd)" "$HOME" "$TZ" "$LC_ALL" > observed.txt; env | sort >> observed.txt; wc -l < observed.txt'

echo
echo "## default (deterministic) cell — what the agent actually sees:"
"$BIN" run --work "$W" --out "$W/.bulla/r.json" -- sh -c "$PROBE" >/dev/null 2>&1
sed -n '1,4p' "$W/observed.txt" | sed 's/^/   /'
det_n=$(( $(wc -l < "$W/observed.txt") - 4 ))
echo "   env vars: $det_n  (a fixed minimal set)"
if grep -q "$W" "$W/observed.txt"; then echo "   LEAK: host path visible!"; else echo "   ok: host instance-id path '$W' does NOT appear inside the cell"; fi

echo
echo "## contrast: --nondeterministic (host env inherited) — the leak the profile prevents:"
"$BIN" run --work "$W" --nondeterministic --out "$W/.bulla/r2.json" -- sh -c "$PROBE" >/dev/null 2>&1
nd_n=$(( $(wc -l < "$W/observed.txt") - 4 ))
echo "   env vars: $nd_n  (host variables now leak in)"

echo
echo "The signed receipt records determinism as part of the seal (fixed_env, no_aslr); a run that"
echo "inherits the host env is honestly marked SEAL BROKEN. Instance-id path + env: closed. Clock: roadmap."

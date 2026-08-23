#!/usr/bin/env bash
# A REAL agent (Claude) solving a real multi-file bug from source, wrapped + signed by bulla eval.
# Baseline (no fix) must FAIL under the seal (proves the hidden grader really runs); the agent's
# from-source fix must PASS — with a signed receipt that no network / no git leak was used.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HOME/.cache/bulla-target/debug/bulla}"
EVAL='--grade "python3 check.py" --solution statskit/window.py --grader check.py'
mk() { local d; d="$(mktemp -d)"; cp -r "$HERE/repo/." "$d/"; cp "$HERE/solution.sh" "$d/"; echo "$d"; }
verdict() { "$BIN" verify "$1" | grep -E "seal held|grade |outcome|network="; }

B="$(mk)"; S="$(mk)"; trap 'rm -rf "$B" "$S"' EXIT
echo "== A) baseline: agent does nothing (solve=true) =="
eval "\"$BIN\" eval --work \"$B\" --solve true $EVAL --out \"$B/r.json\"" | sed -n '1,3p'
verdict "$B/r.json" | sed 's/^/   /'
echo
echo "== B) agent solves from source (solve=sh solution.sh) =="
eval "\"$BIN\" eval --work \"$S\" --solve \"sh solution.sh\" $EVAL --out \"$S/r.json\"" | sed -n '1,3p'
verdict "$S/r.json" | sed 's/^/   /'
echo
gx() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['body']['grade']['outcome']['exit_code'])" "$1"; }
echo "RESULT: baseline grade_exit=$(gx "$B/r.json")  ·  agent-solve grade_exit=$(gx "$S/r.json")   (0 = PASS)"

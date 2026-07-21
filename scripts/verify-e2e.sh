#!/usr/bin/env bash
# End-to-end verification of the vulngraph CLI against a real dist directory.
#
# Usage: ./scripts/verify-e2e.sh [DIST_DIR]
#   DIST_DIR defaults to ../vulngraph-data/dist (offline install).
set -euo pipefail

DIST="${1:-../vulngraph-data/dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/vulngraph"
HOME_DIR="$(mktemp -d)"
export VULNGRAPH_HOME="$HOME_DIR"
trap 'rm -rf "$HOME_DIR"' EXIT

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

[ -x "$BIN" ] || cargo build --release -p vulngraph-cli
[ -d "$DIST" ] || fail "dist dir not found: $DIST"

expect_exit() { # <expected> <label> -- <cmd...>
  local want="$1" label="$2"; shift 3
  local got=0; "$@" >/dev/null 2>&1 || got=$?
  [ "$got" = "$want" ] && pass "$label (exit $got)" || fail "$label: exit $got, wanted $want"
}

echo "== install =="
expect_exit 0 "update --offline-dir" -- "$BIN" update --offline --offline-dir "$DIST"
expect_exit 0 "update noop"          -- "$BIN" update --offline --offline-dir "$DIST"
expect_exit 0 "status"               -- "$BIN" status

echo "== checks =="
"$BIN" check CVE-2024-4577 --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["schema"]=="vulngraph.command.v1", d["schema"]
assert d["snapshot_id"].startswith("sha256:")
v=d["data"][0]["verdict"]
assert v["disposition"]=="actively-exploited", v["disposition"]
print("  ok  CVE-2024-4577 -> actively-exploited")
'
"$BIN" check npm:no-such-pkg-zzz@1.0.0 --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["ok"] is True
assert d["data"][0]["verdict"]["disposition"]=="unknown"
print("  ok  unknown package -> unknown (exit 0)")
'
expect_exit 2 "bad target -> invalid invocation" -- "$BIN" check not-a-target
expect_exit 0 "package check"                    -- "$BIN" check npm:lodash@4.17.15

echo "== schemas =="
for s in command observation status; do
  "$BIN" schema "$s" | python3 -c 'import json,sys; json.load(sys.stdin)' \
    && pass "schema $s is valid JSON" || fail "schema $s invalid"
done

echo "== stale =="
snap_dir="$(find "$HOME_DIR/snapshots" -maxdepth 1 -mindepth 1 -type d | head -1)"
python3 -c "
import json
p='$snap_dir/installed-manifest.json'
m=json.load(open(p)); m['created_at']='2020-01-01T00:00:00Z'; json.dump(m,open(p,'w'))
"
expect_exit 4 "stale check refuses"  -- "$BIN" check CVE-2024-4577
expect_exit 4 "stale status"         -- "$BIN" status

printf '\n\033[32mALL E2E CHECKS PASSED\033[0m\n'

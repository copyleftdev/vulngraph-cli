#!/usr/bin/env bash
# Short fuzz smoke run over every target. Requires nightly + cargo-fuzz.
#   VULNGRAPH_FUZZ_SECONDS  per-target run time (default 60)
set -euo pipefail

SECONDS_PER="${VULNGRAPH_FUZZ_SECONDS:-60}"
cd "$(dirname "$0")/.."

for target in target_parse manifest_parse vrb_open; do
  echo "== fuzzing $target for ${SECONDS_PER}s =="
  cargo +nightly fuzz run "$target" -- -max_total_time="$SECONDS_PER"
done
echo "fuzz smoke complete"

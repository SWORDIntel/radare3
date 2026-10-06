#!/usr/bin/env bash
set -euo pipefail

runs="${RUNS:-20}"
warmup="${WARMUP:-3}"
result_dir="${RESULT_DIR:-.radare3/bench}"

if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  ./scripts/build-benchmark-corpus.sh >/dev/null
  targets=(.radare3/corpus/r3bench-o0 .radare3/corpus/r3bench-o2)
fi

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine is required" >&2
  exit 2
fi

cargo build --release -p radare3-cli >/dev/null
r3="./target/release/radare3"
mkdir -p "$result_dir"

for target in "${targets[@]}"; do
  name="$(basename "$target")"
  cache_dir="$result_dir/cache-$name"
  rm -rf "$cache_dir"

  "$r3" afl-cache "$target" "$cache_dir" >/dev/null 2>/dev/null

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  result="$result_dir/cache-$name-$stamp.json"

  hyperfine     --warmup "$warmup"     --runs "$runs"     --export-json "$result"     --command-name "radare3 cold analysis" "$r3 afl '$target' >/dev/null 2>/dev/null"     --command-name "radare3 warm cache" "$r3 afl-cache '$target' '$cache_dir' >/dev/null 2>/dev/null"

  python3 scripts/benchmark-metadata.py     --target "$target"     --results "$result"     --workload "cache-reopen"
done

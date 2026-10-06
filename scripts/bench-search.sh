#!/usr/bin/env bash
set -euo pipefail

runs="${RUNS:-10}"
warmup="${WARMUP:-3}"
result_dir="${RESULT_DIR:-.radare3/bench}"
pattern="${HEX_PATTERN:-524144415245335f5345415243485f4d41524b4552}"

if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  ./scripts/build-benchmark-corpus.sh >/dev/null
  targets=(.radare3/corpus/r3bench-o0 .radare3/corpus/r3bench-o2)
fi

cargo build --release -p radare3-cli >/dev/null
r3="./target/release/radare3"

if ! command -v r2 >/dev/null 2>&1; then
  echo "radare2 (r2) is required for comparison" >&2
  exit 2
fi
if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine is required for stored benchmark results" >&2
  exit 2
fi

mkdir -p "$result_dir"

for target in "${targets[@]}"; do
  echo
  echo "== $target =="

  r3_count="$("$r3" search "$target" "$pattern" 2>/dev/null | wc -l)"
  r2_count="$(r2 -2 -q -c "/xj $pattern" "$target" 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

  echo "search hits: radare3=$r3_count radare2=$r2_count"
  if [[ "$r3_count" != "$r2_count" ]]; then
    echo "ERROR: literal-search hit counts differ" >&2
    exit 3
  fi

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  name="$(basename "$target")"
  result="$result_dir/search-$name-$stamp.json"

  hyperfine     --warmup "$warmup"     --runs "$runs"     --export-json "$result"     --command-name "radare3 search" "$r3 search '$target' '$pattern' >/dev/null 2>/dev/null"     --command-name "radare2 /xj" "r2 -2 -q -c '/xj $pattern' '$target' >/dev/null 2>/dev/null"

  python3 scripts/benchmark-metadata.py     --target "$target"     --results "$result"     --workload "literal-search"
done

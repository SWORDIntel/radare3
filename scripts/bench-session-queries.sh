#!/usr/bin/env bash
set -euo pipefail

runs="${RUNS:-20}"
warmup="${WARMUP:-3}"
query_repeats="${QUERY_REPEATS:-100}"
result_dir="${RESULT_DIR:-.radare3/bench}"

if [[ "$query_repeats" -lt 1 ]]; then
  echo "QUERY_REPEATS must be >= 1" >&2
  exit 2
fi

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
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  "$r3" verify "$target" >/dev/null

  name="$(basename "$target")"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  function_input="$result_dir/.session-function-$name-$stamp.in"
  xref_input="$result_dir/.session-xref-$name-$stamp.in"
  function_result="$result_dir/session-function-queries-$name-$stamp.json"
  xref_result="$result_dir/session-xref-queries-$name-$stamp.json"

  {
    echo "afl"
    for ((i = 0; i < query_repeats; i++)); do
      echo "afij"
      echo "agfj"
    done
    echo "q"
  } > "$function_input"

  {
    echo "afl"
    for ((i = 0; i < query_repeats; i++)); do
      echo "axtj"
      echo "axfj"
    done
    echo "q"
  } > "$xref_input"

  hyperfine \
    --warmup "$warmup" \
    --runs "$runs" \
    --export-json "$function_result" \
    --command-name "radare3 session function queries" \
    "$r3 session '$target' < '$function_input' >/dev/null 2>/dev/null"

  python3 scripts/benchmark-metadata.py \
    --target "$target" \
    --results "$function_result" \
    --workload "session-function-queries-$query_repeats"

  hyperfine \
    --warmup "$warmup" \
    --runs "$runs" \
    --export-json "$xref_result" \
    --command-name "radare3 session xref queries" \
    "$r3 session '$target' < '$xref_input' >/dev/null 2>/dev/null"

  python3 scripts/benchmark-metadata.py \
    --target "$target" \
    --results "$xref_result" \
    --workload "session-xref-queries-$query_repeats"

  rm -f "$function_input" "$xref_input"
done

#!/usr/bin/env bash
set -euo pipefail

runs="${RUNS:-10}"
warmup="${WARMUP:-3}"
result_dir="${RESULT_DIR:-.radare3/bench}"

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

echo "radare3 threads: ${RAYON_NUM_THREADS:-auto}"
echo "radare2: $(r2 -v | head -n1)"

for target in "${targets[@]}"; do
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  echo
  echo "== $target =="

  "$r3" verify "$target" >/dev/null
  echo "structural verification: PASS"

  parallel_count="$("$r3" afl "$target" 2>/dev/null | wc -l)"
  sequential_count="$("$r3" afl-seq "$target" 2>/dev/null | wc -l)"
  r2_count="$(r2 -2 -q -c 'aaa;afl;q' "$target" 2>/dev/null | wc -l)"

  echo "function lines: radare3-parallel=$parallel_count radare3-sequential=$sequential_count radare2=$r2_count"

  if [[ "$parallel_count" != "$sequential_count" ]]; then
    echo "ERROR: radare3 parallel/sequential function counts differ" >&2
    exit 3
  fi

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  name="$(basename "$target")"
  result="$result_dir/analysis-$name-$stamp.json"

  hyperfine     --warmup "$warmup"     --runs "$runs"     --export-json "$result"     --command-name "radare3 parallel" "$r3 afl '$target' >/dev/null 2>/dev/null"     --command-name "radare3 sequential" "$r3 afl-seq '$target' >/dev/null 2>/dev/null"     --command-name "radare2 aaa+afl" "r2 -2 -q -c 'aaa;afl;q' '$target' >/dev/null 2>/dev/null"

  python3 scripts/benchmark-metadata.py     --target "$target"     --results "$result"     --workload "analysis"
done

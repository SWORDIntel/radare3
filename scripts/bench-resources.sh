#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

runs="${RUNS:-10}"
result_dir="${RESULT_DIR:-.radare3/bench-resources}"

if ! [[ "$runs" =~ ^[0-9]+$ ]] || (( runs < 1 )); then
  echo "RUNS must be a positive integer" >&2
  exit 2
fi

if [[ ! -x /usr/bin/time ]] || ! /usr/bin/time --version 2>&1 | grep -qi 'GNU time'; then
  echo "GNU /usr/bin/time is required for resource benchmarks" >&2
  exit 2
fi

if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  ./scripts/build-benchmark-corpus.sh >/dev/null
  targets=(.radare3/corpus/r3bench-o0 .radare3/corpus/r3bench-o2)
fi

cargo build --release -p radare3-cli >/dev/null
r3="./target/release/radare3"

if ! command -v r2 >/dev/null 2>&1; then
  echo "radare2 (r2) is required for resource comparison" >&2
  exit 2
fi

mkdir -p "$result_dir"

measure() {
  local output="$1"
  local label="$2"
  local run="$3"
  shift 3

  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  /usr/bin/time \
    -f '%e\t%U\t%S\t%M\t%R\t%F\t%c\t%w' \
    -o "$tmp" \
    "$@" >/dev/null 2>/dev/null

  local elapsed user system rss minor major involuntary voluntary
  IFS=$'\t' read -r elapsed user system rss minor major involuntary voluntary < "$tmp"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$run" "$elapsed" "$user" "$system" "$rss" "$minor" "$major" "$involuntary" "$voluntary" \
    >> "$output"

  rm -f "$tmp"
  trap - RETURN
}

for target in "${targets[@]}"; do
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  "$r3" verify "$target" >/dev/null

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  name="$(basename "$target")"
  output="$result_dir/resources-$name-$stamp.tsv"

  printf 'command\trun\telapsed_seconds\tuser_seconds\tsystem_seconds\tmax_rss_kib\tminor_faults\tmajor_faults\tinvoluntary_ctx_switches\tvoluntary_ctx_switches\n' > "$output"

  for ((run = 1; run <= runs; run++)); do
    measure "$output" "radare3-parallel" "$run" "$r3" afl "$target"
    measure "$output" "radare3-sequential" "$run" "$r3" afl-seq "$target"
    measure "$output" "radare2-aaa-afl" "$run" r2 -2 -q -c 'aaa;afl;q' "$target"
  done

  python3 scripts/benchmark-metadata.py \
    --target "$target" \
    --results "$output" \
    --workload "analysis-resources"

  echo "$output"
done

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
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  "$r3" verify "$target" >/dev/null
  name="$(basename "$target")"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  result="$result_dir/session-$name-$stamp.json"

  one_shot="$r3 afl '$target' >/dev/null 2>/dev/null; $r3 pdf '$target' >/dev/null 2>/dev/null"
  session="printf 'afl\\npdf\\nq\\n' | $r3 session '$target' >/dev/null 2>/dev/null"

  hyperfine \
    --warmup "$warmup" \
    --runs "$runs" \
    --export-json "$result" \
    --command-name "radare3 one-shot afl+pdf" "$one_shot" \
    --command-name "radare3 session afl+pdf" "$session"

  python3 scripts/benchmark-metadata.py \
    --target "$target" \
    --results "$result" \
    --workload "session-reuse"
done

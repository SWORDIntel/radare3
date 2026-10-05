#!/usr/bin/env bash
set -euo pipefail

runs="${RUNS:-10}"
warmup="${WARMUP:-3}"

if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  targets=(/bin/ls /bin/bash)
fi

cargo build --release -p radare3-cli >/dev/null
r3="./target/release/radare3"

if ! command -v r2 >/dev/null 2>&1; then
  echo "radare2 (r2) is required for comparison" >&2
  exit 2
fi

for target in "${targets[@]}"; do
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  echo
  echo "== $target =="

  r3_count="$("$r3" afl "$target" 2>/dev/null | wc -l)"
  r2_count="$(r2 -2 -q -c 'aaa;afl;q' "$target" 2>/dev/null | wc -l)"
  echo "function lines: radare3=$r3_count radare2=$r2_count"
  echo "NOTE: counts are a correctness signal, not expected to match yet."

  if command -v hyperfine >/dev/null 2>&1; then
    hyperfine \
      --warmup "$warmup" \
      --runs "$runs" \
      --command-name "radare3 afl" "$r3 afl '$target' >/dev/null 2>/dev/null" \
      --command-name "radare2 aaa+afl" "r2 -2 -q -c 'aaa;afl;q' '$target' >/dev/null 2>/dev/null"
  else
    echo "hyperfine not installed; timing one run with /usr/bin/time"
    /usr/bin/time -f 'radare3 elapsed=%e rss_kb=%M' \
      "$r3" afl "$target" >/dev/null
    /usr/bin/time -f 'radare2 elapsed=%e rss_kb=%M' \
      r2 -2 -q -c 'aaa;afl;q' "$target" >/dev/null
  fi
done

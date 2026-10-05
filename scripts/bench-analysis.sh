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

echo "radare3 threads: ${RAYON_NUM_THREADS:-auto}"
echo "radare2: $(r2 -v | head -n1)"

for target in "${targets[@]}"; do
  if [[ ! -r "$target" ]]; then
    echo "skip unreadable target: $target" >&2
    continue
  fi

  echo
  echo "== $target =="

  parallel_count="$("$r3" afl "$target" 2>/dev/null | wc -l)"
  sequential_count="$("$r3" afl-seq "$target" 2>/dev/null | wc -l)"
  r2_count="$(r2 -2 -q -c 'aaa;afl;q' "$target" 2>/dev/null | wc -l)"

  echo "function lines: radare3-parallel=$parallel_count radare3-sequential=$sequential_count radare2=$r2_count"

  if [[ "$parallel_count" != "$sequential_count" ]]; then
    echo "ERROR: radare3 parallel/sequential function counts differ" >&2
    exit 3
  fi

  echo "NOTE: r2 parity is not claimed yet; its count is a coverage signal."

  if command -v hyperfine >/dev/null 2>&1; then
    hyperfine       --warmup "$warmup"       --runs "$runs"       --command-name "radare3 parallel" "$r3 afl '$target' >/dev/null 2>/dev/null"       --command-name "radare3 sequential" "$r3 afl-seq '$target' >/dev/null 2>/dev/null"       --command-name "radare2 aaa+afl" "r2 -2 -q -c 'aaa;afl;q' '$target' >/dev/null 2>/dev/null"
  else
    echo "hyperfine not installed; timing one run with /usr/bin/time"
    /usr/bin/time -f 'radare3-parallel elapsed=%e rss_kb=%M'       "$r3" afl "$target" >/dev/null
    /usr/bin/time -f 'radare3-sequential elapsed=%e rss_kb=%M'       "$r3" afl-seq "$target" >/dev/null
    /usr/bin/time -f 'radare2 elapsed=%e rss_kb=%M'       r2 -2 -q -c 'aaa;afl;q' "$target" >/dev/null
  fi
done

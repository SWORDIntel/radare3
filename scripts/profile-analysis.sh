#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if ! command -v perf >/dev/null 2>&1; then
  echo "perf is required" >&2
  exit 2
fi

if [[ "$#" -gt 0 ]]; then
  target="$1"
else
  ./scripts/build-benchmark-corpus.sh >/dev/null
  target=".radare3/corpus/r3bench-o2"
fi

threads="${RAYON_NUM_THREADS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}"
name="$(basename "$target")"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${PROFILE_DIR:-.radare3/profiles}/$name-$stamp"

mkdir -p "$out"
cargo build --release -p radare3-cli >/dev/null
r3="./target/release/radare3"

python3 scripts/machine-manifest.py > "$out/machine.json"
sha256sum "$target" > "$out/target.sha256"

echo "profiling $target with RAYON_NUM_THREADS=$threads"

RAYON_NUM_THREADS="$threads" perf stat -d -d -d   -o "$out/perf-stat.txt"   -- "$r3" afl "$target" >/dev/null 2>"$out/radare3-stderr.txt"

RAYON_NUM_THREADS="$threads" perf record -g --call-graph dwarf   -o "$out/perf.data"   -- "$r3" afl "$target" >/dev/null 2>>"$out/radare3-stderr.txt"

perf report --stdio -i "$out/perf.data" > "$out/perf-report.txt"

if command -v heaptrack >/dev/null 2>&1; then
  (
    cd "$out"
    RAYON_NUM_THREADS="$threads" heaptrack "$root/$r3" "$root/$target" >/dev/null 2>&1 || true
  )
fi

echo "profile written to $out"

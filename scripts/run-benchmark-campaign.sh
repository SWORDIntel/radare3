#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runs="${RUNS:-20}"
resource_runs="${RESOURCE_RUNS:-$runs}"
threads="${THREADS:-1 2 4 8 16 32}"
machine="${MACHINE_ID:-$(hostname -s 2>/dev/null || hostname)}"
machine="$(printf '%s' "$machine" | tr -cs 'A-Za-z0-9._-' '-')"
base_dir="${RESULT_ROOT:-.radare3/campaign}/$machine"

if [[ "$#" -gt 0 ]]; then
  targets=("$@")
else
  ./scripts/build-benchmark-corpus.sh >/dev/null
  targets=(.radare3/corpus/r3bench-o0 .radare3/corpus/r3bench-o2)
fi

logical="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
mkdir -p "$base_dir"

python3 scripts/machine-manifest.py > "$base_dir/machine.json"

echo "machine: $machine"
echo "logical CPUs: $logical"
echo "results: $base_dir"

for count in $threads; do
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    echo "invalid thread count: $count" >&2
    exit 2
  fi
  if (( count > logical )); then
    continue
  fi

  out="$base_dir/analysis-t$count"
  mkdir -p "$out"
  echo
  echo "== analysis: $count thread(s) =="
  RAYON_NUM_THREADS="$count" RUNS="$runs" RESULT_DIR="$out"     ./scripts/bench-analysis.sh "${targets[@]}"
done

search_out="$base_dir/search"
mkdir -p "$search_out"
echo
echo "== literal search =="
RUNS="$runs" RESULT_DIR="$search_out" ./scripts/bench-search.sh "${targets[@]}"

resource_out="$base_dir/resources"
mkdir -p "$resource_out"
echo
echo "== resource behavior =="
RUNS="$resource_runs" RESULT_DIR="$resource_out" ./scripts/bench-resources.sh "${targets[@]}"

echo
echo "== scaling summary =="
python3 scripts/summarize-benchmark-campaign.py "$base_dir"

echo
echo "campaign complete: $base_dir"

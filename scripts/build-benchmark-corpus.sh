#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cc="${CC:-cc}"
out=".radare3/corpus"
src="benchmarks/fixtures/r3bench.c"

mkdir -p "$out"

"$cc" -std=c11 -O0 -g0 -fno-pie -no-pie "$src" -o "$out/r3bench-o0"
"$cc" -std=c11 -O2 -g0 -s -fno-pie -no-pie "$src" -o "$out/r3bench-o2"

echo "built benchmark corpus:"
sha256sum "$out/r3bench-o0" "$out/r3bench-o2"

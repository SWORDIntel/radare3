#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The corpus recipe manifest (benchmarks/corpus.toml) is the source of truth;
# this wrapper keeps the historical entry point and output contract.
exec python3 scripts/build-corpus.py benchmarks/corpus.toml "$@"

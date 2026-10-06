# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary-analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

> Keep the useful radare workflow; replace the expensive analysis path.

## Status

The current static-analysis slice includes:

- ELF64 and PE32+ normalization
- x86/x86-64 decoding through an isolated iced-x86 backend
- read-only mmap-backed input
- ELF symbol, PE export, PE `.pdata`, entrypoint, and call-derived function seeds
- deterministic recursive-descent and function-level parallel analysis
- dense worker-local visited maps with sparse fallback
- deterministic canonical CFG merge
- exact sequential/parallel differential verification
- call/code xrefs
- ASCII and UTF-16LE string extraction across segments in parallel
- SIMD-dispatched single-byte and substring search through `memchr`
- `afl`, `afl-seq`, `agf`, `izz`, and `/x`-style CLI paths
- source-built benchmark corpus
- stored hyperfine JSON + machine metadata
- median regression gate

Still intentionally missing: persistent caching, broad radare2 command fallback, ARM64 analysis, and a committed hardware-specific performance baseline.

## Quick start

```sh
cargo build --workspace
cargo run -p radare3-cli -- info /bin/ls
cargo run -p radare3-cli -- afl /bin/ls
cargo run -p radare3-cli -- afl-seq /bin/ls
cargo run -p radare3-cli -- agf /bin/ls
cargo run -p radare3-cli -- izz /bin/ls
cargo run -p radare3-cli -- search /bin/ls 7f454c46
cargo run -p radare3-cli -- /x /bin/ls 7f454c46
cargo run -p radare3-cli -- verify /bin/ls
```

`afl` uses the parallel analyzer. `afl-seq` is the truth/performance oracle. `search` and `/x` are aliases and accept even-length hexadecimal patterns.

## Benchmarking

Build the reproducible local corpus:

```sh
./scripts/build-benchmark-corpus.sh
```

Then benchmark analysis or literal search:

```sh
RUNS=20 RAYON_NUM_THREADS=8 ./scripts/bench-analysis.sh
RUNS=20 ./scripts/bench-search.sh
```

Results land under `.radare3/bench/` as hyperfine JSON plus metadata. No speedup claim is valid until the compared outputs pass their correctness gate.

See [docs/BENCHMARKING.md](docs/BENCHMARKING.md).

## Quality gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-benchmark-regression.py \
  benchmarks/testdata/baseline.json \
  benchmarks/testdata/current-ok.json \
  --threshold 5
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

AGPL-3.0-or-later.

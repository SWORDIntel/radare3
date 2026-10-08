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
- call/code plus RIP-relative data xrefs
- ASCII and UTF-16LE string extraction across segments in parallel
- SIMD-dispatched single-byte and substring search through `memchr`
- native r2-style analysis, xref, symbols/imports, disassembly, strings, search, and JSON command paths
- versioned static-fact export for future Angryier/KP14-SUITE handoff
- single-load session mode with persistent seek and lazy in-memory analysis reuse
- source-built benchmark corpus
- stored hyperfine JSON + machine metadata
- median regression gate

Still intentionally missing: ARM64 analysis, deeper indirect/data-flow recovery, and a committed hardware-specific performance baseline. Persistent caching and explicit radare2 fallback are now present.

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
cargo run -p radare3-cli -- session /bin/ls
```

`afl` uses the parallel analyzer. `afl-seq` is the truth/performance oracle. `search` and `/x` are aliases and accept even-length hexadecimal patterns.



## Single-load session

For repeated work on one binary:

```sh
radare3 session ./sample
```

The first analysis-backed command computes analysis once; later analysis commands reuse the same in-memory result. The mmap and seek state remain live for the session.

Initial commands:

```text
s [address]
px [length]
pxj [length]
afl
pdf [function-address]
pdfj [function-address]
info / ij
iS / iSj
is / isj
ii / iij
? / help
q / quit
```

See [docs/SESSION.md](docs/SESSION.md).

## Resource limits

All analysis commands can be bounded without changing command syntax:

```sh
RADARE3_MAX_INSTRUCTIONS=100000 \
RADARE3_MAX_FUNCTIONS=10000 \
RADARE3_MAX_BLOCKS=100000 \
RADARE3_MAX_XREFS=250000 \
radare3 afl sample.bin
```

Unset variables mean unlimited. Budget failures identify which resource was exhausted, and every active budget is included in the persistent-cache identity.

See [docs/RESOURCE_LIMITS.md](docs/RESOURCE_LIMITS.md).

`radare3 export-static <file>` emits deterministic static facts with binary
identity and fidelity metadata. See [docs/STATIC_EXPORT.md](docs/STATIC_EXPORT.md).

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

## Roadmap

See [docs/MASTER_ROADMAP.md](docs/MASTER_ROADMAP.md) for the full engineering plan and [docs/ROADMAP.md](docs/ROADMAP.md) for the compact status checklist.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

AGPL-3.0-or-later.

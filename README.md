# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary-analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

> Keep the useful radare workflow; replace the expensive analysis path.

## Status

The current static-analysis slice includes:

- ELF64 normalization
- PE32+ normalization
- x86/x86-64 decoding through an isolated iced-x86 backend
- read-only mmap-backed input
- virtual-address / file-offset mapping
- typed function seeds:
  - image entry point
  - ELF function symbols
  - PE exports
  - PE x64 exception table (`.pdata`)
- deterministic recursive-descent function discovery
- function-level parallel discovery using Rayon work stealing
- reusable dense worker-local visited maps with a sparse fallback for large images
- deterministic canonical CFG merge after parallel discovery
- exact sequential/parallel differential fixtures
- basic-block and CFG recovery
- call-derived function seeds
- call/code xrefs
- ASCII and UTF-16LE string extraction
- `afl`, `afl-seq`, `agf`, and `izz`-style CLI paths
- radare3-vs-radare2 benchmark harness

Still intentionally missing: persistent caching, SIMD search, broad r2 command fallback, and ARM64 analysis.

## Quick start

```sh
cargo build --workspace
cargo run -p radare3-cli -- info /bin/ls
cargo run -p radare3-cli -- decode /bin/ls 0xADDRESS
cargo run -p radare3-cli -- afl /bin/ls
cargo run -p radare3-cli -- afl-seq /bin/ls
cargo run -p radare3-cli -- agf /bin/ls
cargo run -p radare3-cli -- izz /bin/ls
```

`afl` uses the parallel analyzer. `afl-seq` keeps the deterministic single-threaded analyzer available as a truth/performance oracle. Set `RAYON_NUM_THREADS` to pin the parallel worker count.

Analysis currently accepts x86-64 images only. String extraction is architecture-independent.

## Analysis model

The fast path is parallel without making output order depend on scheduling:

1. collect trusted loader seeds,
2. process function seeds in deterministic waves,
3. let worker tasks recursively discover local blocks, callees, and xrefs,
4. merge worker discoveries only after the wave completes,
5. canonicalize overlapping provisional blocks using the global block-start set,
6. rebuild per-function block membership from canonical CFG reachability,
7. assign function, block, and xref IDs from sorted addresses.

The sequential analyzer uses the same discovery/canonicalization logic and is tested for exact equality with the parallel result.

The mmap call is the only intentionally unsafe operation in this path and lives in the narrow `radare3-mmap` boundary crate. Core crates continue to forbid unsafe Rust.

## Benchmarking

With radare2 installed:

```sh
./scripts/bench-analysis.sh /bin/ls /bin/bash
```

The harness checks radare3 parallel/sequential function counts before timing. With `hyperfine`, it benchmarks:

- radare3 parallel
- radare3 sequential
- radare2 `aaa;afl`

For a fixed worker count:

```sh
RAYON_NUM_THREADS=8 RUNS=20 ./scripts/bench-analysis.sh /bin/ls /bin/bash
```

radare2 output coverage is still a correctness signal rather than a parity claim. No headline speedup should be published until the compared workloads are materially equivalent.

See [docs/BENCHMARKING.md](docs/BENCHMARKING.md).

## Quality gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

AGPL-3.0-or-later.

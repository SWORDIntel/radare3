# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary-analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

> Keep the useful radare workflow; replace the expensive analysis path.

## Status

The repository is now a **compiling architecture scaffold**. Analysis algorithms are intentionally not implemented yet.

Initial scope:

- Rust-native core
- ELF + PE first
- x86 / x86-64 first
- immutable binary images
- parallel function and CFG discovery
- deterministic canonical merge
- fast xref and string indexing
- SIMD-oriented search boundary
- persistent content-addressed analysis cache
- radare2 compatibility / fallback
- optional Angryier handoff for deep symbolic and concolic analysis

No performance claims until reproducible benchmarks exist.

## Workspace

```text
crates/
  radare3/            public API facade
  radare3-types/      stable IDs and shared value types
  radare3-image/      immutable loaded-image model
  radare3-arch/       architecture-neutral decoder contract
  radare3-loader/     loader contract and format normalization
  radare3-cfg/        functions, basic blocks, CFG representation
  radare3-xref/       code/data/call reference model
  radare3-search/     binary search contract
  radare3-cache/      persistent cache contract
  radare3-analysis/   analysis orchestration and result model
  radare3-r2/         radare2 compatibility boundary
  radare3-cli/        command-line frontend
```

## Build

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run the placeholder CLI:

```sh
cargo run -p radare3-cli -- --version
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Benchmarking

See [docs/BENCHMARKING.md](docs/BENCHMARKING.md). Performance work is gated on equivalent-output fixtures rather than wall-clock numbers alone.

## License

AGPL-3.0-or-later.

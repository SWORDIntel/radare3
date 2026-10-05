# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary-analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

> Keep the useful radare workflow; replace the expensive analysis path.

## Status

The first real execution path is live:

- ELF64 normalization
- PE32+ normalization
- x86/x86-64 decoding through an isolated iced-x86 backend
- virtual-address to file-offset mapping
- CLI binary inspection
- CLI single-instruction decode

Still intentionally missing: recursive function discovery, CFG construction, xrefs, caching, and radare2 command compatibility.

## Quick start

```sh
cargo build --workspace
cargo run -p radare3-cli -- info /bin/ls
cargo run -p radare3-cli -- decode /bin/ls 0xADDRESS
```

The decode command currently accepts x86-64 images only.

## Workspace

```text
crates/
  radare3/            public API facade
  radare3-types/      stable IDs and shared value types
  radare3-image/      immutable loaded-image model
  radare3-arch/       architecture-neutral decoder contract
  radare3-arch-x86/   iced-x86 decoder backend
  radare3-loader/     ELF64 / PE32+ normalization
  radare3-cfg/        functions, basic blocks, CFG representation
  radare3-xref/       code/data/call reference model
  radare3-search/     binary search contract
  radare3-cache/      persistent cache contract
  radare3-analysis/   analysis orchestration and result model
  radare3-r2/         radare2 compatibility boundary
  radare3-cli/        command-line frontend
```

## Quality gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Benchmarking

See [docs/BENCHMARKING.md](docs/BENCHMARKING.md). Performance work is gated on equivalent-output fixtures rather than wall-clock numbers alone.

## License

AGPL-3.0-or-later.

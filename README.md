# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary-analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

> Keep the useful radare workflow; replace the expensive analysis path.

## Status

The current static-analysis slice includes:

- ELF64 normalization
- PE32+ normalization
- x86/x86-64 decoding through an isolated iced-x86 backend
- virtual-address / file-offset mapping
- typed function seeds:
  - image entry point
  - ELF function symbols
  - PE exports
  - PE x64 exception table (`.pdata`)
- deterministic recursive-descent function discovery
- basic-block and CFG recovery
- call-derived function seeds
- call/code xrefs
- ASCII and UTF-16LE string extraction
- `afl`, `agf`, and `izz`-style CLI paths
- first radare3-vs-radare2 benchmark harness

Still intentionally missing: persistent caching, parallel discovery, SIMD search, broad r2 command fallback, and ARM64 analysis.

## Quick start

```sh
cargo build --workspace
cargo run -p radare3-cli -- info /bin/ls
cargo run -p radare3-cli -- decode /bin/ls 0xADDRESS
cargo run -p radare3-cli -- afl /bin/ls
cargo run -p radare3-cli -- agf /bin/ls
cargo run -p radare3-cli -- izz /bin/ls
```

Analysis currently accepts x86-64 images only. String extraction is architecture-independent.

## Analysis model

The current analyzer remains deterministic before it becomes parallel:

1. collect trusted loader seeds,
2. recursively decode basic blocks,
3. enqueue direct branch targets,
4. promote direct call targets to function seeds,
5. collect call/code xrefs,
6. assign function, block, and xref IDs from sorted addresses.

Named ELF symbols and PE exports are retained as function names. PE x64 `.pdata` records provide unnamed function seeds.

## Benchmarking

With radare2 installed:

```sh
./scripts/bench-analysis.sh /bin/ls /bin/bash
```

If `hyperfine` is installed, the script performs repeated warm benchmark runs. Otherwise it falls back to `/usr/bin/time`.

Function counts are printed alongside timings as a correctness signal. They are **not expected to match yet**, and no speedup claim should be made until output coverage is comparable.

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

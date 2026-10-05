# radare3 engineering rules

## Mission

Build a fast, deterministic binary-analysis core without recreating every radare2 subsystem.

## Rules

- Optimize measured hot paths only.
- Keep binary images immutable after loading.
- Prefer dense IDs and contiguous storage over pointer-heavy object graphs.
- Worker threads discover facts; canonical state is committed deterministically.
- Unsupported formats, architectures, and commands may fall back to radare2.
- Do not claim speedups without reproducible benchmark data.
- Do not claim semantic equivalence without differential fixtures.
- Core crates forbid unsafe Rust. Isolate any future FFI or mmap-specific unsafe code in narrow boundary crates.
- Preserve one-way dependencies. Lower-level crates must never depend on orchestration or CLI crates.
- Keep the first implementation focused on ELF/PE and x86/x86-64.

## Required checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

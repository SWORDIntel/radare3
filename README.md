# radare3

**Fast native binary analysis without throwing away the radare2 ecosystem.**

radare3 is an experimental high-performance binary analysis engine focused on the hot paths that make large-scale reversing slow: loading, decoding, function discovery, CFG recovery, cross-references, strings, search, and persistent analysis.

The design goal is simple:

> keep the useful radare workflow; replace the expensive analysis path.

## Status

Early architecture / empty implementation scaffold.

Initial targets:

- Rust-native core
- ELF + PE first
- x86 / x86-64 first
- immutable mmap-backed images
- parallel function and CFG discovery
- fast xref and string indexing
- SIMD search
- persistent content-addressed analysis cache
- radare2 compatibility / fallback
- optional Angryier handoff for deep symbolic and concolic analysis

No performance claims until reproducible benchmarks exist.

## License

AGPL-3.0-or-later.

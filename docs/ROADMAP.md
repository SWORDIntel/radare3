# Roadmap

## Phase 0 — Scaffold

- [x] workspace boundaries
- [x] shared IDs and image model
- [x] decoder / loader contracts
- [x] CFG / xref result model
- [x] compatibility boundary
- [x] CI and benchmark contract

## Phase 1 — First useful analyzer

- [x] ELF64 loader normalization
- [x] PE32+ loader normalization
- [x] x86/x86-64 decoder backend
- [x] entrypoint function seed
- [x] call-derived function seeds
- [x] ELF function-symbol seeds
- [x] PE export seeds
- [x] PE x64 exception-table (.pdata) seeds
- [x] basic-block discovery
- [x] deterministic CFG assembly
- [x] call/xref extraction
- [x] ASCII and UTF-16LE strings
- [x] CLI binary info and single-instruction decode
- [x] CLI `afl`, `agf`, and `izz`-style commands

## Phase 2 — Performance

- [x] first radare3-vs-radare2 benchmark harness
- [x] immutable mmap-backed image storage
- [x] isolated mmap unsafe boundary
- [x] reusable per-worker discovery arenas
- [x] Rayon work-stealing scheduler
- [x] deterministic wave merge
- [x] dense visited-address structures with sparse fallback
- [x] sequential-vs-parallel differential gate
- [ ] SIMD literal/string search
- [ ] reproducible benchmark corpus
- [ ] benchmark result storage / regression gate
- [ ] address lookup acceleration for very high segment-count images

## Phase 3 — Persistence and compatibility

- [ ] content-addressed cache
- [ ] incremental invalidation
- [ ] radare2 analysis import/export
- [ ] r2 command compatibility layer
- [ ] fallback execution through radare2

## Phase 4 — Deep analysis

- [ ] Angryier handoff API
- [ ] signatures
- [ ] type recovery experiments
- [ ] ARM64 fast path

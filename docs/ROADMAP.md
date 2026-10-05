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
- [x] basic-block discovery
- [x] deterministic CFG assembly
- [x] call/xref extraction
- [ ] strings
- [x] CLI binary info and single-instruction decode
- [x] CLI `afl` and `agf`-style commands
- [ ] symbol/export-derived function seeds

## Phase 2 — Performance

- [ ] immutable mmap-backed image storage
- [ ] per-worker discovery arenas
- [ ] work-stealing scheduler
- [ ] dense visited-address structures
- [ ] SIMD literal/string search
- [ ] reproducible benchmark corpus

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

# Roadmap

## Phase 0 — Scaffold

- [x] workspace boundaries
- [x] shared IDs and image model
- [x] decoder / loader contracts
- [x] CFG / xref result model
- [x] compatibility boundary
- [x] CI and benchmark contract

## Phase 1 — First useful analyzer

- [ ] ELF64 loader
- [ ] PE32+ loader
- [ ] x86-64 decoder backend
- [ ] trusted function seeds
- [ ] basic-block discovery
- [ ] deterministic CFG assembly
- [ ] call/xref extraction
- [ ] strings
- [ ] CLI open / info / function-list commands

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

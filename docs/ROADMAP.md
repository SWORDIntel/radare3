# Roadmap

Cross-project delivery order for ISANITY, METHRA, radare3, and Angryier on KP14-SUITE / VM 9211: [Four-product unified roadmap](https://github.com/SWORDIntel/METHRA/blob/main/docs/VM9211_CORE_ROADMAP.md). Shared instruction identities and semantics: [ISANITY](https://github.com/SWORDIntel/ISANITY). This file remains the source of truth for radare3-specific implementation status.

This is the compact implementation-status view. The full engineering plan, release milestones, gates, and non-goals live in [MASTER_ROADMAP.md](MASTER_ROADMAP.md).

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
- [x] entrypoint, call-derived, symbol, export, and PE `.pdata` function seeds
- [x] basic-block discovery
- [x] deterministic CFG assembly
- [x] call/code xrefs
- [x] RIP-relative data xrefs
- [x] absolute-memory data xrefs
- [x] indirect import-slot call xrefs
- [x] ASCII and UTF-16LE strings
- [x] binary info, symbols, imports, sections, byte views, disassembly
- [x] native `afl`, `afi`, `agf`, `axt`, `axf`, `pdf`, `izz`, `/x` command paths
- [x] versioned JSON output for primary native commands

## Phase 2 — Parallel and query performance

- [x] immutable mmap-backed image storage
- [x] isolated mmap unsafe boundary
- [x] reusable per-worker discovery arenas
- [x] Rayon work-stealing scheduler
- [x] deterministic function waves and canonical merge
- [x] dense visited-address structures with sparse fallback
- [x] exact sequential-vs-parallel differential gate
- [x] SIMD-backed literal search via `memchr`
- [x] parallel deterministic string extraction
- [x] derived xref source/target index
- [x] flat immutable xref descriptor/postings index
- [x] prefix-count xref source-range queries
- [x] flat immutable function-entry index
- [x] flat immutable import-slot index
- [x] one-pass file-backed segment translation for instruction byte access
- [x] single-load interactive session
- [x] lazy in-session analysis reuse
- [x] lazy function/xref/import secondary-index reuse
- [ ] first committed hardware-specific benchmark baseline
- [ ] profile-driven interval acceleration if one-pass linear segment lookup remains hot
- [ ] evaluate freeze-time dense Vec CFG storage after profiling

## Phase 3 — Benchmark infrastructure

- [x] reproducible source-built benchmark corpus
- [x] Hyperfine JSON result storage + metadata
- [x] target SHA-256 and machine manifest
- [x] >5% median regression checker
- [x] thread-scaling campaign harness
- [x] automatic speedup/efficiency summaries
- [x] cache cold-vs-warm benchmark
- [x] session reuse benchmark
- [x] repeated function/xref session-query benchmark
- [x] profiling helper scripts
- [ ] realistic multi-language ELF/PE corpus recipes
- [ ] committed bare-metal baseline
- [ ] representative perf/flamegraph/heap profiles
- [x] RSS/minor-fault/major-fault resource benchmark harness
- [ ] committed large-target memory-ramp campaign
- [ ] workload-specific mmap advice experiments for linear scans vs CFG traversal
- [ ] ranked bottleneck list from measured profiles

## Phase 4 — Persistence

- [x] content-addressed cache identity
- [x] deterministic versioned analysis snapshot
- [x] persisted CFG/xrefs/strings/fidelity
- [x] checksummed file envelope
- [x] atomic same-directory writes
- [x] hostile/truncated cache parsing hardening
- [x] cache invalidation on loader/decoder/schema/options changes
- [x] resource-budget options included in cache identity
- [ ] incremental region/dependency invalidation

## Phase 5 — radare2 compatibility

- [x] Native / Fallback / Unsupported command classification
- [x] no-shell radare2 fallback executor
- [x] timeout/kill/reap and captured stdout/stderr
- [x] explicit CLI routing with observable fallback
- [x] native symbols/imports/sections/disassembly/xref/function/search paths
- [x] persistent-seek session mode
- [x] radare2 analysis export
- [ ] project/annotation interoperability
- [ ] broader fallback replacement where native engines mature

## Phase 6 — Analysis quality

- [x] ELF relocation-backed import slots
- [x] import annotations on xrefs
- [x] RIP-relative and explicit absolute data references
- [x] indirect call relationship preserved through import slots
- [ ] relocation-assisted non-import data references
- [ ] PLT/import thunk normalization
- [ ] jump-table and switch recovery
- [ ] indirect branch/call target recovery
- [ ] tail-call / thunk / noreturn normalization
- [ ] string/global-reference enrichment
- [ ] richer seed provenance and confidence

## Phase 7 — Resource governance and hardening

- [x] instruction budget
- [x] function budget
- [x] block budget
- [x] xref budget
- [x] typed budget-exhaustion reasons
- [x] CLI environment limits
- [x] cache hostile-input bounds checks before allocation
- [ ] max-memory governance
- [ ] wall-clock timeout governance
- [ ] fuzz targets for loader / CFG / cache / compatibility parsing
- [ ] large-binary stress corpus

## Phase 8 — Deep analysis and architecture expansion

- [x] local versioned static-fact JSON export (`radare3.static.v1`)
- [ ] Angryier handoff API
- [ ] versioned KP14-SUITE handoff carrying binary identity, image base, architecture, canonical functions/CFG/xrefs/imports, target hints, provenance, and fidelity gaps
- [ ] differential handoff fixtures against Ghidra discovery on representative Windows drivers
- [ ] function fingerprints/signatures
- [ ] binary diffing
- [ ] type/calling-convention recovery experiments
- [ ] ARM64 fast path
- [ ] Mach-O 64 normalization
- [ ] raw firmware / UEFI helpers
- [ ] batch analysis scheduler

## Immediate execution queue

1. Commit the first stable bare-metal benchmark campaign.
2. Profile realistic binaries and rank hotspots, including RSS and page-fault behavior.
3. Keep only profile-supported hot-path changes; compare flat query indexes against their previous tree forms.
4. Continue indirect-control-flow and relocation-backed data-reference recovery.
5. Add radare2 project/annotation interoperability.
6. Add loader/cache/compatibility hostile-input fuzz campaigns.
7. Start ARM64 once the x86-64 substrate and performance evidence are stable.

## KP14-SUITE integration order

1. Export deterministic static facts through the versioned handoff; keep radare3 responsible for discovery, not symbolic execution.
2. Let Angryier consume selected driver targets, including the capabilities currently implemented by KP14's POPKORN/angr path.
3. Validate the exporter and Ghidra comparison fixtures in the radare3 checkout before connecting other tools.
4. Let METHRA schedule bounded jobs and store evidence in QIHSE; KP14 owns the case workflow on VM 9211 after each tool passes its local gate.
5. Evaluate Capstone only later as an optional decoder backend, using semantic differential fixtures and measured costs against the existing decoder path.

Rule:

> Profile → change one thing → verify output → benchmark → keep or revert.

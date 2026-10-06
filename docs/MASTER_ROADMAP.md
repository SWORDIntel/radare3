# radare3 — Master Engineering Roadmap

## Mission

radare3 is a high-performance static binary-analysis engine designed to replace the expensive analysis paths of radare2 without attempting to replace the entire radare2 ecosystem.

The project should win by doing a relatively small number of operations extremely well:

- binary loading and normalization
- instruction decoding
- function discovery
- basic-block and CFG recovery
- cross-reference discovery
- string and byte-pattern search
- persistent analysis
- batch analysis
- deterministic parallel execution

radare2 remains the compatibility layer where replacement provides little benefit: obscure architectures and formats, debugging, mature plugins, specialist commands, decompilers, and legacy projects/scripts.

> Keep the useful radare workflow. Replace the expensive analysis path.

---

## 1. Engineering doctrine

### 1.1 Correctness before parallelism

Every optimized or parallel implementation must have a deterministic reference implementation or independently verifiable truth source.

Parallel execution must not alter discovered functions, block boundaries, CFG edges, xrefs, identifiers, output ordering, or fidelity classification.

### 1.2 No benchmark theatre

No performance claim is valid unless compared workloads are materially equivalent.

Minimum rules:

- at least 10 measured runs after warm-up
- report median and dispersion, never best run
- preserve benchmark metadata
- verify output coverage before timing
- retain exact target hashes
- identify CPU and thread configuration
- never use shared GitHub runners as performance baselines

A measured regression greater than 5% on an established stable-machine benchmark requires investigation, explanation, or rollback.

### 1.3 Immutable analysis substrate

The binary image is immutable after loading.

Workers may read mapped bytes, maintain local discovery state, and produce provisional facts. Workers do not mutate canonical analysis state.

Canonical state is created through deterministic merge.

### 1.4 Unsafe code stays isolated

Core crates continue to forbid unsafe Rust.

Unsafe operations are permitted only where they buy something concrete that cannot reasonably be obtained safely, and must live behind small audited boundaries.

Current example:

```text
radare3-mmap
    └── read-only mmap boundary
```

Future FFI backends follow the same rule.

### 1.5 Fidelity is explicit

A fast heuristic result must never silently masquerade as authoritative analysis.

Current coarse states:

```text
Canonical
Heuristic
Incomplete
```

Future provenance should allow finer-grained confidence on individual functions, xrefs, signatures, and recovered types.

---

## 2. Completed foundation

### Phase 0 — Foundation ✅

- Rust workspace
- crate boundaries
- shared address and identifier types
- immutable image model
- loader and decoder interfaces
- CFG and xref representations
- compatibility boundary
- CI
- strict Clippy
- formatting/test gates
- benchmark contract
- AGPL-3.0-or-later licensing

### Phase 1 — First useful analyzer ✅

#### Binary formats

- ELF64 normalization
- PE32+ normalization
- virtual-address ↔ file-offset mapping
- executable segment discovery

#### Function seeds

- image entry point
- ELF `STT_FUNC`
- PE exports
- PE x64 `.pdata`
- direct-call targets
- user-provided entry points

#### x86 analysis

- architecture-neutral decoder abstraction
- iced-x86 backend
- recursive-descent function discovery
- basic-block recovery
- conditional/unconditional branches
- direct calls
- returns and traps
- deterministic CFG construction
- call/code xrefs

#### User interface

Implemented or partially implemented equivalents:

```text
info
decode
afl
agf
izz
/x
```

### Phase 2 — Parallel performance substrate ✅

- read-only mmap-backed input
- isolated mmap unsafe boundary
- immutable shared image
- Rayon worker pool
- function-level work stealing
- deterministic function waves
- worker-local discovery arenas
- dense executable-address visited bitmap
- touched-word bitmap reset
- sparse fallback for large executable mappings
- deterministic canonical merge
- global block splitting
- stable function/block/xref IDs
- sequential truth analyzer
- parallel analyzer
- full sequential-vs-parallel structural verification

Current shape:

```text
                BinaryImage
                    │
          immutable mmap storage
                    │
          trusted function seeds
                    │
          deterministic seed wave
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      worker      worker      worker
        │           │           │
     blocks       blocks       blocks
     callees      callees      callees
     xrefs        xrefs        xrefs
        │           │           │
        └───────────┼───────────┘
                    ▼
             canonical merge
                    │
                    ▼
           deterministic CFG
```

### Phase 3 — Fast search and benchmark infrastructure ✅

#### Search

- SIMD-dispatched single-byte search
- SIMD-backed substring search via `memchr`
- overlapping binary matches
- segment-parallel search
- deterministic sorted output
- ASCII strings
- UTF-16LE strings
- parallel string extraction

#### Benchmarking

- source-built reproducible corpus
- O0 and O2/stripped benchmark binaries
- radare3 parallel-vs-sequential analysis harness
- radare3-vs-radare2 search harness
- hyperfine JSON export
- target SHA-256 metadata
- CPU/kernel/platform metadata
- radare2 version
- radare3 commit
- Rayon thread configuration
- positive regression fixture
- negative >5% regression fixture
- corpus/search CI smoke test

---

## 3. Phase 4 — Establish the real performance baseline

**Priority: immediate.**

Do not optimize blindly before this phase is complete.

### 4.1 Stable benchmark machine

Select at least one stable bare-metal reference machine and record:

```text
CPU model
physical cores
logical cores
RAM
kernel
compiler
Rust version
radare2 version
storage type
filesystem
CPU governor
NUMA topology
```

Virtualized measurements may be retained as supplementary results, but not the primary baseline.

### 4.2 Expand benchmark corpus

The current synthetic corpus proves the harness works. It does not represent realistic reversing workloads.

Add reproducible acquisition/build recipes for:

#### ELF

- tiny C
- medium C
- stripped C
- C++
- large C++
- Rust
- Go
- PIE
- non-PIE
- shared library
- statically linked executable

#### PE

- small PE32+
- large PE32+
- C++
- DLL
- Windows driver
- Go PE
- Rust PE

#### Firmware

Later:

- UEFI image
- embedded ELF
- raw firmware image

Where redistribution is questionable, store only SHA-256, source/acquisition recipe, compiler/build flags, expected size, format, and architecture.

### 4.3 Baseline workloads

Measure independently:

```text
startup
load + parse
symbols
strings
single-byte search
short pattern search
long pattern search
function discovery
CFG construction
xref construction
full current analysis
```

Do not collapse everything into one `aaa` comparison.

### 4.4 Thread scaling

Test:

```text
1
2
4
8
16
32
maximum logical CPUs
```

Track elapsed time, CPU time, efficiency, RSS, and work imbalance.

```text
speedup(N) = T1 / TN
parallel efficiency = speedup(N) / N
```

Poor scaling triggers profiling before additional concurrency work.

### 4.5 Profiling

Collect representative profiles using:

```text
perf stat
perf record
flamegraph
heaptrack
```

Rank:

- decoder time
- address-to-segment lookup
- BTreeMap/BTreeSet overhead
- allocation rate
- canonical merge
- sorting
- Rayon scheduling
- symbol parsing
- xref storage
- string allocation

### Exit criterion

- committed stable-machine baseline
- realistic corpus recipes
- thread-scaling results
- representative profiles
- ranked bottleneck list

---

## 4. Phase 5 — Hot-path data structure optimization

Performance changes must be driven by Phase 4 profiles.

### 5.1 Address lookup acceleration

Candidates:

```text
sorted segment ranges + binary search
page-indexed mapping
segment-relative direct lookup
```

Target: `O(log n)` worst-case lookup or effectively `O(1)` indexed lookup without unreasonable memory growth.

### 5.2 Remove tree structures from measured hot paths

Likely direction:

```text
worker hot path:
    dense vectors / bitsets / hash tables

canonicalization:
    sort once

final representation:
    dense ID-indexed Vec
```

Do not replace deterministic trees merely on aesthetics; profile first.

### 5.3 Worker allocation reduction

Recycle:

- pending-block vectors
- provisional xrefs
- call-target vectors
- decoder scratch
- successor lists

Possible techniques:

```text
Vec::clear reuse
SmallVec for tiny successor sets
arena/bump allocation only where measured useful
```

### 5.4 Decoder optimization

Benchmark iced-x86 cost independently.

If decoding dominates:

- reduce unnecessary metadata
- minimize construction
- batch decode where useful
- benchmark optional Intel XED backend

Potential shape:

```text
Decoder
 ├── iced-x86
 └── XED
```

XED remains optional and isolated behind FFI.

---

## 5. Phase 6 — Persistent content-addressed cache

This is likely the largest user-visible latency win after first analysis.

### 6.1 Cache identity

```text
BLAKE3(
    binary contents
    loader version
    decoder version
    analysis schema version
    relevant analysis options
)
```

Never key by filename or mtime.

### 6.2 Persisted objects

Initial cache:

```text
binary metadata
function seeds
functions
basic blocks
CFG edges
xrefs
strings
symbol names
analysis fidelity
```

### 6.3 Format requirements

Must be:

- versioned
- checksummed
- deterministic
- bounds checked
- corruption tolerant
- forward-detectable
- safe to delete
- safe against hostile cache files

Invalid cache behavior:

```text
cache invalid
    ↓
discard
    ↓
reanalyze
```

### 6.4 Warm-open objective

Target, not claim:

```text
20–100× faster reopen on sufficiently expensive targets
```

### 6.5 Incremental invalidation

Only after full-cache persistence works.

Potential later model:

```text
binary regions/chunks
       │
analysis dependencies
       │
invalidate affected graph
```

---

## 6. Phase 7 — radare2 compatibility plane

### 7.1 Command classification

```text
Native
Fallback
Unsupported
```

Initial target:

```text
aaa
afl
afi
pdf
axt
axf
izz
is
iS
px
s
agf
/x
/xj
```

### 7.2 Native execution

Operations radare3 does better execute natively.

```text
afl → radare3 CFG database
/x  → radare3 SIMD search
izz → radare3 string engine
```

### 7.3 Fallback execution

Unsupported commands may be delegated to radare2, but fallback must be observable.

### 7.4 r2 analysis export

Materialize:

- functions
- flags
- names
- xrefs
- comments
- CFG information where practical

Goal:

```text
radare3 performs expensive discovery
              ↓
radare2 consumes results
              ↓
mature r2 ecosystem remains available
```

### 7.5 Project interoperability

Later:

- import useful r2 project facts
- preserve analyst annotations
- export analysis
- never clobber manual work

---

## 7. Phase 8 — Analysis quality expansion

### 8.1 Better function discovery

Additional evidence:

- unwind metadata
- exception metadata
- relocation targets
- function tables
- startup/runtime patterns
- import thunks
- PLT/GOT
- compiler metadata
- conservative prologue heuristics

Every seed retains provenance and confidence.

### 8.2 Indirect control flow

Resolve progressively:

- jump tables
- switches
- indirect calls
- import stubs
- PLT/GOT dispatch
- vtables

Use cheap static evidence before symbolic execution.

### 8.3 Data xrefs

Recover:

```text
RIP-relative loads
absolute addresses
relocations
pointer tables
string references
global references
```

### 8.4 CFG normalization

Represent:

- tail calls
- shared blocks
- thunks
- noreturn functions
- external destinations
- unresolved indirect edges

---

## 8. Phase 9 — Signatures and identity

### 9.1 Function fingerprints

Use normalized instructions, CFG structure, constants, call topology, and imported APIs.

Applications:

- library identification
- malware family matching
- firmware comparison
- version diffing
- known-function recognition

### 9.2 External signature support

Consider:

- FLIRT-like signatures
- YARA metadata
- symbol databases
- compiler/runtime fingerprints

Signature databases remain outside the core engine.

---

## 9. Phase 10 — Type and semantic recovery

Start with cheap deterministic inference.

### 10.1 Calling conventions

Recover:

- argument registers
- stack arguments
- return values
- callee-saved registers
- stack frame properties

### 10.2 Local type constraints

Use:

- instruction widths
- pointer dereferences
- API signatures
- comparisons
- arithmetic
- load/store patterns

### 10.3 Structure recovery

Later:

- structs
- arrays
- vtables
- object layouts

All inferred types retain confidence and provenance.

---

## 10. Phase 11 — ARM64 fast path

Second first-class architecture.

Required:

- ARM64 decoder backend
- direct branch/call classification
- conditional branches
- ADR/ADRP
- literal references
- executable-region traversal
- function seeds
- CFG
- xrefs
- deterministic parallel equality

Initial formats:

```text
ELF64 ARM64
PE32+ ARM64
```

Later: Mach-O ARM64.

---

## 11. Phase 12 — Additional file formats

Priority:

1. Mach-O 64
2. raw firmware
3. UEFI helpers
4. archive/container support
5. specialist embedded formats

Invariant:

```text
format parser
      ↓
normalized BinaryImage
```

Analysis logic remains format-independent.

---

## 12. Phase 13 — Angryier deep-analysis handoff

radare3 should not become a symbolic executor.

```text
radare3
  │
  ├─ broad static analysis
  ├─ select function/path
  ▼
Angryier
  │
  ├─ symbolic execution
  ├─ concolic exploration
  ├─ path constraints
  └─ proof/result
  ▼
radare3 knowledge layer
```

Potential command:

```text
aangry <function>
aangry tainted_input
```

Handoff includes binary identity, architecture, functions, blocks, CFG, call targets, imports, selected state, and known data references.

Angryier returns structured results such as reachable addresses, unsatisfiable paths, input constraints, tainted sinks, findings, and proof artifacts.

---

## 13. Phase 14 — Analysis database / knowledge layer

Candidate entities:

```text
Binary
Segment
Section
Function
BasicBlock
Instruction
Xref
String
Symbol
Import
Export
Type
Signature
Finding
Evidence
```

Relations:

```text
Function CALLS Function
Instruction REFERENCES String
Block FLOWS_TO Block
Function MATCHES Signature
Function HAS_TYPE CandidateType
Finding SUPPORTED_BY Evidence
```

Keep it local and efficient; do not turn the core into an enterprise graph database.

---

## 14. Phase 15 — Diffing

Target UX:

```sh
radare3 diff old.bin new.bin
```

Output:

- added functions
- removed functions
- modified functions
- CFG changes
- call-graph changes
- string changes
- import changes
- likely patched vulnerabilities

Applications: firmware analysis, malware evolution, patch diffing, vendor updates.

---

## 15. Phase 16 — Batch analysis

Target:

```sh
radare3 batch samples/
```

Scheduler considers:

- CPU count
- NUMA
- target size
- estimated cost
- memory budget

Avoid machine oversubscription.

---

## 16. Phase 17 — NUMA-aware execution

Only after profiling proves value.

Potential work:

- NUMA-local worker pools
- local discovery arenas
- locality-aware page access
- merge scheduling
- CPU pinning

---

## 17. Phase 18 — Plugin and library API

Once internal contracts stabilize, expose:

```text
Rust API
JSON
streaming JSON
C ABI
r2pipe-compatible process interface
```

Do not stabilize prematurely.

---

## 18. Phase 19 — Structured output

Important commands should gain machine-readable variants:

```text
aflj
agfj
axtj
izzj
/xj
ij
```

Human output is a rendering layer, not the internal data model.

---

## 19. Phase 20 — Hostile-input hardening

Fuzz:

- ELF/PE integration
- address mapping
- seed normalization
- decoder boundary
- CFG canonicalizer
- cache loader
- search APIs
- JSON import/export
- compatibility parsing

Use cargo-fuzz and AFL++ where appropriate.

Malformed input must not cause panic, uncontrolled allocation, overflow, endless traversal, unsafe memory access, or nondeterministic corruption.

---

## 20. Phase 21 — Resource governance

Potential limits:

```text
--max-functions
--max-blocks
--max-xrefs
--max-instructions
--max-memory
--threads
--timeout
```

Budget termination must produce `Fidelity::Incomplete` with a retained reason.

---

## 21. Phase 22 — Packaging

### Linux

- release tarball
- static build where sensible
- Debian package
- cargo install path
- later RPM/Arch

### Windows

Native executable.

### macOS

Once Mach-O support warrants it.

---

## 22. Phase 23 — Release gates

Before performance-focused releases:

```text
cargo fmt
cargo clippy
cargo test
fuzz smoke
corpus correctness
parallel/sequential verification
benchmark regression gate
```

On stable benchmark machines:

```text
analysis baseline
search baseline
thread-scaling baseline
RSS baseline
```

---

## 23. Version milestones

### v0.1 — Analyzer exists

Essentially complete:

- ELF64
- PE32+
- x86-64
- functions
- blocks
- CFG
- xrefs
- strings
- `/x`
- mmap
- deterministic parallel analysis

### v0.2 — Performance validated

Requires:

- realistic benchmark corpus
- committed bare-metal baseline
- profiles
- thread scaling
- first profile-driven data-structure optimizations
- no unexplained >5% regression

This is the first point where serious performance claims should be published.

### v0.3 — Persistent analysis

Requires:

- cache schema
- content-addressed cache
- safe warm reopen
- version invalidation
- corruption handling

### v0.4 — radare interoperability

Requires:

- native/fallback command router
- r2 export
- basic project interoperability
- JSON command output

### v0.5 — Analysis quality

Requires:

- data xrefs
- jump tables
- improved indirect control flow
- thunk handling
- richer seeds
- imports/relocations integrated

### v0.6 — ARM64

Requires:

- ARM64 ELF
- ARM64 PE
- CFG/xref parity with x86-64
- differential fixtures

### v0.7 — Identification and diffing

Requires:

- fingerprints
- signatures
- binary diffing
- structured comparison

### v0.8 — Deep-analysis integration

Requires:

- stable Angryier handoff
- symbolic result ingestion
- evidence/provenance
- selected semantic/type recovery

### v0.9 — Hardening

Requires:

- substantial fuzzing
- hostile-input limits
- cache fuzzing
- compatibility tests
- large-binary stress tests
- documented stable API candidates

### v1.0 — Production-grade fast static analysis core

Does not mean “everything radare2 does.”

Requires:

- deterministic analysis
- stable cache
- stable analysis schema
- robust ELF/PE x86-64
- robust ARM64
- measured advantage on defined workloads
- mature r2 fallback
- machine-readable output
- hostile-input hardening
- documented CLI
- reproducible benchmark evidence
- backwards compatibility policy
- migration/versioning policy

---

## 24. Explicit non-goals before v1.0

Unless profiling or real users demonstrate a strong reason, do not spend major effort on:

- replacing the radare2 debugger
- hundreds of obscure architectures
- a new decompiler from scratch
- a GUI
- a scripting language
- recreating the whole r2 plugin ecosystem
- symbolic execution inside the static core
- distributed analysis infrastructure
- cloud services
- premature GPU acceleration

---

## 25. Immediate execution queue

1. Run the first real benchmark campaign.
2. Commit one stable-machine baseline.
3. Profile representative binaries.
4. Rank hotspots by CPU time.
5. Optimize address lookup if significant.
6. Replace tree-heavy hot-path structures where measured worthwhile.
7. Re-run the benchmark suite.
8. Measure decoder cost.
9. Decide iced-x86 vs optional XED from evidence.
10. Build persistent content-addressed cache.
11. Implement r2 command routing/fallback.
12. Improve data xrefs and indirect control flow.
13. Add ARM64.
14. Add Angryier handoff after the static substrate is stable.

Rule:

> Profile → change one thing → verify output → benchmark → keep or revert.

---

## 26. Success criteria

radare3 succeeds if it becomes:

```text
faster than radare2
for the analysis paths it claims to replace,

deterministic enough
for automated workflows,

compatible enough
to preserve the radare ecosystem,

modular enough
to hand difficult functions to Angryier,

and small enough
that performance remains understandable.
```

The end state is not “radare2 rewritten in Rust.”

```text
                   radare3
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   FAST PLANE      TRUTH PLANE   COMPAT PLANE
       │              │              │
 mmap / SIMD      deterministic     radare2
 parallel CFG     canonical merge   fallback
 fast xrefs       provenance        plugins
 caching          validation        debugger
       │              │              │
       └──────────────┼──────────────┘
                      │
                 DEEP ANALYSIS
                      │
                   Angryier
                      │
             symbolic / concolic
```

Every future feature is judged against this architecture.

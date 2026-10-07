# Architecture

## Planes

radare3 separates work into three operational planes:

1. **Fast plane** — immutable image access, decoding, parallel discovery, CFG/xref/search work.
2. **Truth plane** — deterministic canonicalization, validation, provenance, reproducible outputs.
3. **Compatibility plane** — radare2 command/project interoperability and fallback.

## Dependency direction

```text
types
 ├── image
 │    └── mmap boundary
 ├── arch
 ├── cfg
 ├── xref
 └── cache
      │
image + arch + cfg + xref
      │
   analysis
      │
  ┌───┴────┐
  r2     radare3
           │
          cli
```

Loaders normalize file formats into `BinaryImage`. They do not own analysis policy.

## Core invariants

### Immutable image

After loading, the byte image and segment mapping are immutable. The CLI maps regular files read-only and workers share the same backing bytes. Analysis never mutates a process-global seek cursor.

The only mmap-specific unsafe operation is isolated in `radare3-mmap`. The core image/loader/analysis crates still forbid unsafe Rust.

### Local discovery, deterministic commit

Function workers do not mutate canonical CFG state. Each worker produces a local discovery record containing provisional blocks, direct callees, xrefs, fidelity, and instruction count.

Parallel execution happens in waves:

```text
sorted pending function seeds
          │
          ▼
    Rayon work stealing
   ┌──────┼──────┐
   ▼      ▼      ▼
 worker worker worker
   │      │      │
   └── local discoveries ──┐
                            ▼
                 deterministic merge
                            │
                            ▼
                    next callee wave
```

Scheduling order therefore cannot assign canonical IDs.

### Canonical block merge

Different function seeds can overlap the same instruction stream. Worker-local blocks are provisional.

The truth plane:

1. collects every provisional block start,
2. chooses deterministic candidates for duplicate starts,
3. splits a block if another globally known block start lies inside it,
4. rebuilds each function's block membership by canonical CFG reachability,
5. assigns IDs only after sorting canonical addresses.

This is what lets sequential and parallel analysis use the same output contract.

### Reusable visited-address maps

Workers reuse a bitset indexed over executable file-backed bytes. Clearing is proportional to the words actually touched, not the entire image.

For unusually large executable mappings, the arena switches to a sparse set rather than allocating an unbounded per-worker bitset.

### Stable identifiers

Functions, blocks, and xrefs use compact numeric IDs. IDs are not raw pointers and must be serializable.

### Build for mutation, freeze for queries

Discovery and canonicalization may use ordered maps and sets because deterministic insertion, merging, splitting, and validation are the priority there.

After canonical facts are stable, derived query indexes should prefer immutable contiguous storage: sorted key descriptors, flat posting arrays, dense identifiers, and prefix counts. The query plane must not mutate canonical analysis to gain speed.

This follows a strict rule:

```text
worker-local mutable discovery
          ↓
deterministic ordered merge
          ↓
      validation
          ↓
       freeze
          ↓
flat immutable query indexes
```

The tree representation remains a correctness-friendly construction tool. A flat representation is adopted only where tests prove semantic equivalence and benchmarks justify it.

### Compatibility is a boundary

radare3 does not initially reimplement every radare2 feature. Unsupported commands, formats, architectures, debugging operations, and specialist plugins belong behind the compatibility boundary.

### No silent approximation

If a fast path produces incomplete or heuristic results, the result carries an explicit fidelity/status marker rather than silently masquerading as canonical truth.

## Current implementation order

1. PE/ELF loader normalization. ✓
2. x86/x86-64 decoder backend. ✓
3. trusted function seed extraction. ✓
4. basic-block discovery. ✓
5. deterministic CFG merge. ✓
6. call/xref collection. ✓
7. string extraction. ✓
8. mmap-backed immutable storage. ✓
9. parallel function discovery. ✓
10. sequential/parallel differential validation. ✓
11. SIMD search. ✓
12. persistent cache. ✓
13. radare2 import/export bridge. ✓
14. flat immutable function/import/xref query indexes. ✓
15. bare-metal profiling and evidence-driven query-plane refinement.

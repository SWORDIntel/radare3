# Architecture

## Planes

radare3 separates work into three operational planes:

1. **Fast plane** — immutable image access, decoding, discovery, CFG/xref/search work.
2. **Truth plane** — deterministic canonicalization, validation, provenance, reproducible outputs.
3. **Compatibility plane** — radare2 command/project interoperability and fallback.

## Dependency direction

```text
types
 ├── image
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

After loading, the byte image and segment mapping are immutable. Analysis workers receive shared references and never mutate a process-global seek cursor.

### Local discovery, deterministic commit

Parallel workers produce discovery records locally. Canonical functions, blocks, and references are resolved in a deterministic merge phase.

### Stable identifiers

Functions, blocks, and xrefs use compact numeric IDs. IDs are not raw pointers and must be serializable.

### Compatibility is a boundary

radare3 does not initially reimplement every radare2 feature. Unsupported commands, formats, architectures, debugging operations, and specialist plugins belong behind the compatibility boundary.

### No silent approximation

If a future fast path produces incomplete or heuristic results, the result must carry an explicit fidelity/status marker rather than silently masquerading as canonical truth.

## Initial implementation order

1. PE/ELF loader normalization.
2. x86/x86-64 decoder backend.
3. trusted function seed extraction.
4. basic-block discovery.
5. deterministic CFG merge.
6. call/xref collection.
7. string and literal search.
8. persistent cache.
9. radare2 import/export bridge.
10. parallel scheduling and tuning after correctness fixtures are stable.

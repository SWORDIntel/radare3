# KEYSTONE lessons applied to radare3

KEYSTONE and radare3 solve different problems, but they share a useful systems pattern: mutable construction should not dictate the representation used by the read-heavy hot path.

## Adopted now

### Build-friendly truth plane, flat query plane

radare3 keeps ordered maps/sets where they make canonicalization easy to reason about, then derives immutable read-optimized indexes after analysis.

Current applications:

- function entry lookup: sorted flat `Vec<(Address, FunctionId)>`
- import slot lookup: sorted flat `Vec<(Address, usize)>`
- xrefs: sorted address descriptors plus contiguous posting positions
- xref source-range counts: prefix counts over sorted source descriptors
- instruction byte lookup: a single segment scan performs both containment and address-to-file-offset translation

These are derived indexes. They do not replace the canonical CFG/xref truth representation.

## Already converged independently

Both projects use a touched-set reset pattern for large dense bitmaps:

- KEYSTONE trigram per-document dedup tracks touched bytes
- radare3 worker discovery tracks touched visited-map words

The common rule is to make reset cost proportional to changed state rather than total capacity.

## Benchmark lessons to adopt

The bare-metal campaign should include more than wall time:

- median and dispersion
- RSS
- minor and major page faults
- instructions and cycles
- branches and branch misses
- cache/LLC misses where available
- thread-scaling efficiency
- cold/warm cache behavior

mmap advice such as `MADV_SEQUENTIAL`, `MADV_RANDOM`, `MADV_WILLNEED`, or huge-page hints must be workload-specific and benchmarked. Literal search/string scans and CFG traversal do not have the same access pattern.

## Runtime policy lessons to evaluate

KEYSTONE calibrates backends by workload shape rather than ISA availability alone. radare3 should eventually evaluate automatic sequential-vs-parallel dispatch using binary size, executable bytes, seed count, thread count, and measured startup overhead.

A candidate policy should require a material repeatable win before replacing the simpler path.

## Hardening lessons to adopt

Hostile-input campaigns should mutate persisted caches and loader inputs with:

- truncation
- bit flips
- count/length corruption
- trailing garbage
- integer-overflow-shaped values
- allocation-bomb metadata

The contract is fail closed or return a valid bounded result; never panic or allocate based on untrusted sizes before validating bounds.

## Explicitly not adopted without evidence

The following KEYSTONE techniques are not automatically appropriate for radare3:

- 64 MiB direct trigram directories
- anchor-guided search
- custom AVX-512 search paths where `memchr` already dispatches well
- AMX for CFG/disassembly work
- global huge-page or sequential-access advice
- network/federation machinery

The governing rule remains:

> Profile → change one thing → verify exact output → benchmark → keep or revert.

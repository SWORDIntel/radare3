# Cache architecture

The cache is content-addressed. Paths and modification times are not cache identity.

## Key

Current key domain:

```text
radare3-cache-key-v1
```

The BLAKE3 key is derived from length-prefixed components:

```text
binary contents
loader semantic version
decoder semantic version
analysis schema version
analysis-options fingerprint
```

Length prefixes prevent concatenation ambiguity.

The current crate deliberately stops at key/schema identity. It does **not** yet commit the project to a serialization or storage backend.

## Why the storage engine is deferred

Before persistence lands, the project needs to settle:

- which analysis objects are canonical cache payloads
- serialization versioning
- corruption/checksum handling
- maximum allocation bounds for hostile cache files
- atomic write/rename behavior
- cache directory policy
- compatibility/migration policy

The first storage implementation must treat cache files as hostile input.

## Required invalidation

A cache miss is mandatory when any of the following changes:

- binary bytes
- loader semantics
- decoder semantics
- analysis schema
- relevant analysis options

## Planned next step

Define a versioned, deterministic cache payload for:

- binary metadata
- function seeds
- functions and blocks
- CFG edges
- xrefs
- strings
- names
- fidelity

Then add safe atomic file persistence and warm-open benchmarks.

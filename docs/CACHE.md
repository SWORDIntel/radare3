# Cache architecture

The cache is content-addressed. Paths and modification times are not cache identity.

## Identity

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

## Opaque storage container

`FileCache` stores opaque payload bytes. Analysis serialization remains a separate concern.

Current file envelope:

```text
8 bytes   magic: R3CACHE\0
4 bytes   cache file version (LE)
32 bytes  expected cache key
8 bytes   payload length (LE)
32 bytes  BLAKE3(payload)
N bytes   opaque payload
```

Reads reject:

- bad magic
- unsupported file version
- key mismatch
- payloads above the configured size limit
- truncated files
- trailing bytes
- checksum mismatch

The default maximum payload is 512 MiB and can be lowered by callers.

## Atomic writes

Entries are written to a unique temporary file in the destination directory, flushed with `sync_all`, then renamed into place.

The content-addressed key means a concurrent writer producing the same final key may safely win the race; the loser discards its temporary file.

## Directory layout

```text
<root>/
  ab/
    abcdef...r3c
```

The first key byte is used as a shard directory.

## Required invalidation

A cache miss is mandatory when any of the following changes:

- binary bytes
- loader semantics
- decoder semantics
- analysis schema
- relevant analysis options

## Next step

Define the deterministic versioned analysis payload containing:

- binary metadata
- function seeds
- functions and blocks
- CFG edges
- xrefs
- strings
- names
- fidelity

Then connect the payload to `FileCache` and add cold-vs-warm reopen benchmarks.

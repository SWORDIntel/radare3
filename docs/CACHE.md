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

## Analysis payload

`AnalysisSnapshot` now has a deterministic bounded binary codec for:

- functions and names
- basic blocks and successors
- CFG membership
- xrefs
- fidelity
- extracted strings

Decoding rejects duplicate IDs, invalid enum tags, dangling block references, oversized collections/strings, malformed UTF-8, invalid block ranges, and trailing bytes.

The CLI command:

```sh
radare3 afl-cache <file> [cache-dir]
```

derives a key from binary contents, loader/decoder semantic versions, analysis options, and the string threshold. Invalid cache entries are discarded and rebuilt rather than treated as authoritative.

Cold-vs-warm timing:

```sh
RUNS=20 ./scripts/bench-cache.sh
```

## Next step

Move cached reopening into the default analysis path after baseline measurements establish the overhead/benefit, then expand the payload with normalized binary metadata and function-seed provenance.

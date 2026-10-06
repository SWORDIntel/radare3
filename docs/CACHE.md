# Cache architecture

The cache is content-addressed and treats persisted data as hostile input.

## Identity

BLAKE3 keys cover binary contents, loader semantics, decoder semantics, analysis schema, and relevant analysis options. Paths and mtimes are not identity.

## File envelope

The versioned `.r3c` envelope contains magic, file version, cache key, payload length, BLAKE3 payload hash, and the opaque analysis payload.

Before allocating payload memory, readers verify:

- declared payload is below the configured maximum,
- the on-disk file length exactly matches header + declared payload,
- the stored key matches the requested key.

Unexpected EOF while reading an existing cache entry is corruption, not a generic I/O failure, so callers can safely discard and rebuild truncated entries.

## Analysis payload hardening

The deterministic analysis codec validates collection counts against both hard limits and the bytes actually remaining before allocating nested vectors.

It rejects:

- truncated payloads,
- impossible collection counts,
- duplicate IDs,
- dangling block references,
- invalid block ranges,
- invalid enum tags,
- malformed UTF-8,
- oversized strings/collections,
- trailing bytes.

The parser never trusts a count merely because it fits an integer type.

## Atomic writes

Entries are written to unique same-directory temporary files, flushed with `sync_all`, then renamed into their content-addressed final path. Concurrent same-key writers may race safely; the losing temporary file is discarded.

## CLI

```sh
radare3 afl-cache <file> [cache-dir]
```

Invalid or incompatible entries are discarded and rebuilt. Use `scripts/bench-cache.sh` for cold-vs-warm timing.

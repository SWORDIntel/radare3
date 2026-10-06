# Xref indexing

`XrefIndex` is a deterministic secondary index over an immutable xref slice.

It keeps two maps:

```text
source address -> positions in AnalysisResult.xrefs
target address -> positions in AnalysisResult.xrefs
```

The index stores positions rather than cloning xrefs, so the canonical xref vector remains the source of truth.

## Why this is separate from AnalysisResult

The persistent analysis payload remains compact and deterministic. An index is derived state: it can be built once for an interactive session or other repeated-query workload and discarded without changing cache serialization.

## Complexity

After an `O(n log k)` build over `n` xrefs and distinct-address map cardinality `k`:

- outgoing lookup is map lookup + number of matching xrefs,
- incoming lookup is map lookup + number of matching xrefs,
- no full xref-vector scan is needed per query.

The order of results follows the canonical xref vector.


## Session integration

Session mode builds the index lazily. Commands that never query xrefs do not pay the index-build cost.

The first session `axt/axtj/axf/axfj` command emits:

```text
session-xref-index=miss
```

and constructs the index from the already-canonical `AnalysisResult.xrefs`. Later xref queries emit `session-xref-index=hit` and reuse the same derived index.

Analysis remains the source of truth; the index is discarded with the session and is never persisted in the content-addressed cache.

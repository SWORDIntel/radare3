# Function-entry indexing

`FunctionIndex` is a deterministic secondary index over the canonical control-flow graph.

It maps:

```text
function entry address -> FunctionId
```

The canonical `ControlFlowGraph.functions` map remains the source of truth. The index stores only IDs and can be rebuilt at any time.

## Why this exists

Interactive commands such as `afi`, `agf`, and `pdf` resolve a function from an entry address. Repeatedly scanning every function is unnecessary once analysis is immutable.

After an `O(n log n)` build over `n` functions, entry lookup is a deterministic map lookup.

## Persistence

The index is derived state and is not part of the analysis cache schema. Session mode may build it lazily and discard it when the session closes.

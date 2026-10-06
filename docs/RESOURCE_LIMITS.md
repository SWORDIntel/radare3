# Resource governance

radare3 analysis can be bounded by four independent limits:

```text
RADARE3_MAX_INSTRUCTIONS
RADARE3_MAX_FUNCTIONS
RADARE3_MAX_BLOCKS
RADARE3_MAX_XREFS
```

Unset variables mean unlimited.

The Rust API exposes the same controls through `AnalysisOptions`:

```rust
AnalysisOptions {
    max_instructions: Some(...),
    max_functions: Some(...),
    max_blocks: Some(...),
    max_xrefs: Some(...),
    ..
}
```

## Failure semantics

Budget exhaustion is explicit:

```text
AnalysisError::BudgetExceeded(Instructions)
AnalysisError::BudgetExceeded(Functions)
AnalysisError::BudgetExceeded(Blocks)
AnalysisError::BudgetExceeded(Xrefs)
```

Parallel analysis checks the function budget before dispatching a wave. Worker-local block/xref limits are checked before inserting new provisional state, and global totals are checked again during deterministic merge accounting.

## Cache safety

All four limits are part of the analysis-options fingerprint. A cache entry created under one resource policy cannot be reused under a different policy.

Changing the resource-budget schema increments the analysis cache schema so older identities cannot alias new analysis semantics.

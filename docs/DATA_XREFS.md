# Data cross-references

The x86/x86-64 decoder reports one allocation-free optional data target for directly resolvable memory operands.

For an instruction such as:

```text
mov rax, [rip + displacement]
```

iced-x86 resolves the effective IP-relative virtual address during decoding. radare3 records:

```text
instruction address --Data--> referenced virtual address
```

This extends the existing call/code xref stream with `XrefKind::Data`.

## Scope

The current deterministic pass covers:

- RIP/EIP-relative memory operands,
- explicit absolute memory operands with no base or index register.

It does not infer addresses that require register state. It still does not claim:

- stack references,
- pointer chasing,
- jump-table resolution,
- relocation-assisted references,
- implicit string-instruction memory references.

The decoder carries `data_target: Option<Address>`, not a heap-allocated vector, so the common decode path does not gain a per-instruction allocation.

The decoder semantic version is bumped so persistent cache identities cannot reuse analysis generated before data-xref recovery existed.


## Indirect import calls

When an x86/x86-64 instruction is classified as a call, has no direct branch target, and uses an IP-relative memory operand, radare3 preserves two distinct facts about the same slot:

```text
instruction --Call--> import slot
instruction --Data--> import slot
```

The `Call` xref represents the control-transfer relationship through the unresolved slot. The `Data` xref represents the memory reference used to obtain the destination.

The slot itself is not treated as executable and is not added as a discovered callee. When loader metadata resolves that slot to an import, the normal xref renderer can annotate both references with the import identity.

Indirect jumps are not promoted to code xrefs merely because they use an IP-relative slot. Their eventual target is still unresolved.

This changes analysis output, so the analysis cache schema is incremented.


## Absolute memory operands

An explicit memory operand with no base register and no index register is treated as an absolute data target:

```text
mov rax, [0x12345678]
        │
        └── Data xref -> 0x12345678
```

Memory such as `[rbx + 0x20]` is not promoted to an absolute xref because its runtime address depends on register state.

The decoder still carries only one `Option<Address>`; this expansion does not add per-instruction heap allocation.

The decoder semantic version is bumped from the RIP-relative implementation, which invalidates persistent cache identity automatically.

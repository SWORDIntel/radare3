# Data cross-references

The x86-64 decoder now reports one allocation-free optional data target for RIP/EIP-relative memory operands.

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

This first data-xref pass intentionally covers RIP/EIP-relative memory addressing only. It does not yet claim:

- absolute-address recovery from arbitrary register state,
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

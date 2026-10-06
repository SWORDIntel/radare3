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

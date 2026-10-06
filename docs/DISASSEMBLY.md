# x86 disassembly formatting

The x86 backend exposes a formatting path separate from analysis decoding.

`IcedX86Decoder::disassemble(address, bytes)` returns:

```text
address
length
formatted text
```

Formatting uses iced-x86 `FastFormatter`, whose purpose is high-speed disassembly formatting. The analysis decoder remains unchanged and does not allocate formatted strings.

This split is deliberate:

- analysis asks only for control/data-flow facts,
- user-facing disassembly pays formatting cost only when requested,
- future `pdf/pdfj` output can format canonical CFG block ranges without contaminating the hot analysis path.

The formatter currently uses the fast formatter's MASM-like syntax with spaces after operand separators.

# Static analysis export

`radare3 export-static <file>` prints one JSON document with schema
`radare3.static.v1`. It is the local, versioned static-fact export for future
Angryier and KP14-SUITE handoff work. The command does not select IOCTL targets
or execute symbolic paths.

The document contains the input's SHA-256, format, architecture, base and entry
addresses, producer and loader/decoder semantics versions, analysis options,
analysis fidelity, canonical functions and basic
blocks, xrefs, and imports. Addresses are absolute virtual addresses expressed
as JSON integers. IDs are scoped to this export; consumers should use the binary
hash and virtual address when identifying facts across runs or tools. A block's
end is exclusive. `fidelity: incomplete` must remain visible to consumers and
must not be treated as a complete discovery claim.

The JSON is deterministic for the same binary, radare3 version, analysis
options, and decoder semantics. Future target-selection metadata should be an
additive, versioned contract rather than inferred from an import name or xref
alone.

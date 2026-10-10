# Structured JSON output

radare3 now has native JSON renderers for the first high-value command surface:

```text
ij
iSj
isj
iij
pxj
aflj
afij
pdfj
agfj
axtj
axfj
izzj
/xj
```

These command names intentionally follow radare2 conventions, but the payloads are **radare3 schemas**, not a claim of byte-for-byte radare2 JSON compatibility.

Every top-level payload carries a schema identifier:

```text
radare3.info.v1
radare3.sections.v1
radare3.symbols.v1
radare3.imports.v1
radare3.px.v1
radare3.afl.v1
radare3.afi.v1
radare3.pdf.v1
radare3.agf.v1
radare3.axt.v2
radare3.axf.v2
radare3.izz.v1
radare3.search.v1
```

Addresses are emitted as numeric virtual addresses rather than presentation-formatted hexadecimal strings. IDs are compact numeric radare3 IDs.

The JSON layer lives in the CLI. Core analysis types are not coupled to serde or a serialization framework.

## Version-scoped x86 decode evidence

`radare3 decode-evidence <32|64> <address> <hex-bytes>` emits one compact JSON observation for one instruction. For example:

```sh
radare3 decode-evidence 64 0x401000 4889e590
```

The `input_bytes_hex` field preserves the complete supplied byte slice, while
`decoded_bytes_hex` records only the bytes consumed by the instruction. The
observation includes the x86 mode, address, iced-x86 version, and both the
version-scoped numeric `Code` discriminant and enum variant name. Neither is a
cross-decoder identity: `canonical_isanity_id` is currently null, and
`identity_scope` explicitly limits the provider identity to iced-x86. JSON
object key order is not a compatibility guarantee; consumers should use the
field names and schema string `radare3.iced-x86.decode-observation.v1`.
For direct ISANITY ingestion, the same response also contains
`isanity_observation`, a nested record shaped as
`decode-observation-v1.schema.json` (schema version 1). Its
`source_identifier.namespace` is `iced-x86::Code`; `name` and
`numeric_value` are the pinned provider's enum name and discriminant. The CLI
implements this stable field contract locally and does not read or depend on
the neighboring ISANITY checkout at build time.

### Decode handoff record

The same response carries an additive `handoff` field: a nested record
serialized from the library-level `IcedX86HandoffV1` produced by
`IcedX86Decoder::observe_handoff_v1`, so non-CLI consumers can rely on the
same typed contract.

```json
"handoff": {
  "schema": "radare3.iced-x86.decode-handoff.v1",
  "provider": "iced-x86",
  "provider_version": "1.21.0",
  "architecture": "x86",
  "execution_mode": "64-bit",
  "input_bytes_hex": "4889e590",
  "consumed_bytes_hex": "4889e5",
  "consumed_length": 3,
  "source_namespace": "iced-x86::Code",
  "source_name": "Mov_rm64_r64",
  "source_numeric_value": 282,
  "canonical_mapping": {
    "status": "unresolved",
    "reason": "no ratified ISANITY catalogue mapping is available"
  }
}
```

- `schema` is `radare3.iced-x86.decode-handoff.v1`
  (`ICED_X86_HANDOFF_SCHEMA`); `provider` is `iced-x86` and
  `provider_version` is the pinned crate version. `execution_mode` echoes the
  submitted mode as `32-bit` or `64-bit`.
- `input_bytes_hex` preserves the complete submitted byte slice, while
  `consumed_bytes_hex` and `consumed_length` record only the bytes consumed
  by the single decoded instruction.
- The provider-scoped `Code` identity is reported verbatim as
  `source_namespace` (`iced-x86::Code`), `source_name` (the pinned enum
  variant name), and `source_numeric_value` (the version-scoped numeric
  discriminant). It remains provider-version-specific, not a cross-decoder
  identity.
- `canonical_mapping` is explicitly unresolved: `status` is `unresolved` and
  `reason` explains why. The handoff never synthesizes an ISANITY ID;
  provider enum values are not promoted by name until a ratified mapping
  artifact exists.
- The field is additive: every pre-existing top-level field of
  `radare3.iced-x86.decode-observation.v1` (`schema`, `provider`,
  `decoder_version`, `mode_bits`, `address`, `input_bytes_hex`,
  `decoded_bytes_hex`, `decoded_length`, `code_discriminant`, `code_name`,
  `canonical_isanity_id`, `identity_scope`, `isanity_observation`) is emitted
  unchanged alongside `handoff`. Serialization is deterministic for identical
  input, and invalid mode, empty, truncated, or malformed input fails closed
  with the same errors as the pre-handoff path.

## Compatibility direction

The compatibility router should classify these commands as native once this renderer is merged:

```text
ij
aflj
afij
agfj
axtj
axfj
izzj
/xj
```

Future schema changes require a new schema suffix instead of silently mutating an existing `.v1` contract.


### Xref import annotation

`radare3.axt.v2` and `radare3.axf.v2` add an `import` field to each xref. It is either `null` or a normalized import object when the xref target matches a known import slot.

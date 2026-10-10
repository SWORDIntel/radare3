# Import normalization

Imports are normalized separately from local symbols and function seeds.

Each import carries:

```text
slot: Option<Address>
library: Option<String>
name: String
ordinal: Option<u16>
kind: Function | Object | Other
```

## PE

goblin synthesizes each PE import with an `offset` based on the import address table RVA. radare3 converts that RVA to a virtual IAT slot using the image base.

Ordinal is populated only for ordinal-only entries; the PE hint field is not mislabeled as an ordinal for name-based imports.

## ELF

Undefined named `.dynsym` entries become imports. ELF symbol type maps to function/object/other.

No slot or provider library is invented at this stage. Accurate ELF slot/provider attribution requires relocation and version/dependency resolution.

## CLI

```sh
radare3 ii <file>
radare3 iij <file>
```

JSON schema: `radare3.imports.v1`.


## ELF relocation-backed slots

ELF imports now consult dynamic relocations. Slot selection is deterministic:

1. `pltrelocs`
2. `dynrelas`
3. `dynrels`

The first relocation for a dynamic-symbol index wins. The relocation's `r_offset` becomes the normalized import slot address.

This makes typical x86-64 PLT/GOT imports directly addressable by `ii/iij` and allows data xrefs landing on a GOT slot to be annotated with the import name.


## Derived slot index

`ImportIndex` is a deterministic secondary index:

```text
import slot address -> position in BinaryImage.imports
```

It stores only positions into the canonical import vector and is not persisted.

If multiple canonical import records share a slot, the first record in canonical import order wins. This matches the existing `BinaryImage::import_at_slot` behavior while avoiding repeated full-vector scans in interactive workloads.


## Session integration

Session xref rendering builds `ImportIndex` lazily on the first `axt/axf` query:

```text
session-import-index=miss
```

Later xref queries reuse it and emit `session-import-index=hit`.

The index is not built for `afi` or other commands that do not render import annotations. One-shot xref commands retain the simple linear lookup path as a reference implementation.


## PLT/import thunk normalization

radare3 normalizes recognized import thunks to their underlying function imports:
- Exact x86-64 ELF `FF 25` RIP-relative indirect jumps to function import GOT slots (`jmp qword ptr [rip+disp32]`).
- One-hop x86-64 ELF `E9` rel32 executable veneers targeting an already-recognized exact `FF 25` import thunk.

Normalization preserves the original xref target address (`entry`) while exposing the final import slot, function import metadata, and any intermediate `veneer_destination` as evidence. Cycles, invalid address arithmetic, non-executable targets/veneers, unsupported platforms, and arbitrary branches are rejected.

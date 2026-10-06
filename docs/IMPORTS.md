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

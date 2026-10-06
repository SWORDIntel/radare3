# Symbol normalization

radare3 keeps symbols separate from function seeds.

`BinaryImage::symbols` is a deterministic normalized table of named, defined symbols used for inspection and compatibility output. Function discovery still uses `function_seeds`, so adding a non-function symbol never makes it executable analysis work.

## Current sources

- ELF `.symtab` and `.dynsym` named defined function symbols
- ELF named defined object and other symbols
- PE named exports

Each symbol carries:

```text
address
size
kind
name
```

PE export size is currently `0` because the PE export table does not provide a trustworthy object/function extent.

## CLI

```sh
radare3 is <file>
radare3 isj <file>
```

The JSON schema is `radare3.symbols.v1`.

Imports are not local symbols and will be normalized separately for an `ii`-class command.

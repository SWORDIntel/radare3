# Structured JSON output

radare3 now has native JSON renderers for the first high-value command surface:

```text
ij
aflj
agfj
izzj
/xj
```

These command names intentionally follow radare2 conventions, but the payloads are **radare3 schemas**, not a claim of byte-for-byte radare2 JSON compatibility.

Every top-level payload carries a schema identifier:

```text
radare3.info.v1
radare3.afl.v1
radare3.agf.v1
radare3.izz.v1
radare3.search.v1
```

Addresses are emitted as numeric virtual addresses rather than presentation-formatted hexadecimal strings. IDs are compact numeric radare3 IDs.

The JSON layer lives in the CLI. Core analysis types are not coupled to serde or a serialization framework.

## Compatibility direction

The compatibility router should classify these commands as native once this renderer is merged:

```text
ij
aflj
agfj
izzj
/xj
```

Future schema changes require a new schema suffix instead of silently mutating an existing `.v1` contract.

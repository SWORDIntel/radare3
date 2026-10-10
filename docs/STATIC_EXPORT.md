# Static analysis export

`radare3 export-static <file>` prints one JSON document with schema
`radare3.static.v1`. It is the local, versioned static-fact export for future
Angryier, ISANITY, METHRA, and KP14-SUITE handoff work. The command does not
select IOCTL targets or execute symbolic paths.

The command loads the input with the goblin loader, runs the parallel
recursive-descent analyzer over the iced-x86 decoder, and prints the result as
one compact single-line JSON value followed by a newline. On any failure —
unreadable file, non-x86-64 image, or an analysis budget exceeded — nothing is
printed to stdout; the error goes to stderr and the process exits with status 2.

## Producer and consumer contract

An independent consumer can ingest the document deterministically by checking
`schema`, `producer`, the two semantics-version strings, and `binary_sha256`,
then reading the arrays below. Consumers must ignore unknown top-level and
nested fields; additions are the compatibility mechanism (see
[Versioning](#versioning-and-compatibility)). The document is a static-fact
snapshot: it asserts what the analyzer found, not what the binary can do.

## Top-level fields

All addresses are absolute virtual addresses expressed as JSON integers
(unsigned 64-bit); `base_address` is already applied, so consumers must not
rebase. Null means the producer had no value, never "zero".

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `schema` | string | Constant `"radare3.static.v1"`. Consumers must gate on this exact value. |
| `producer.name` | string | Constant `"radare3"`. |
| `producer.version` | string | The `CARGO_PKG_VERSION` of the emitting CLI (e.g. `"0.0.1"`). |
| `loader_semantics_version` | string | Loader semantics tag, e.g. `"goblin-0.10.7/radare3-loader-v4-elf-import-slots"`. Pins the loader + format interpretation that produced segments, imports, and seeds. |
| `decoder_semantics_version` | string | Decoder semantics tag, e.g. `"iced-x86-1.21.0/radare3-x86-v3-absolute-data-xrefs"`. Pins the decode behavior behind every block range and xref. |
| `binary_sha256` | string | Lowercase hex SHA-256 of the exact input bytes that were loaded (64 hex chars). The binary identity anchor for cross-tool and cross-run joins. |
| `format` | string enum | `elf`, `pe`, `macho`, `raw`, or `unknown`. The loader currently emits `elf` and `pe`. |
| `architecture` | string enum | `x86`, `x86_64`, `arm64`, or `unknown`. `export-static` rejects non-`x86_64` images before analysis, so only `x86_64` is emitted today. |
| `base_address` | integer | Image preferred load base; every VA in the document is `base_address` + file-relative offset. |
| `entry_point` | integer \| null | Image entry VA, or `null` when the format carries none. |
| `fidelity` | string enum | `canonical`, `heuristic`, or `incomplete`. See [Fidelity](#fidelity). |
| `analysis_options` | object | The effective analysis limits used for this run; records truncation provenance. See below. |
| `functions` | array | Canonical discovered functions, ascending `id`. See below. |
| `blocks` | array | Canonical basic blocks, ascending `id`. See below. |
| `xrefs` | array | Cross-references, ascending `id`. See below. |
| `imports` | array | Image imports, in loader order (no per-import id). See below. |

### `analysis_options`

Echoes the `AnalysisOptions` the run used. `RADARE3_MAX_INSTRUCTIONS`,
`RADARE3_MAX_FUNCTIONS`, `RADARE3_MAX_BLOCKS`, and `RADARE3_MAX_XREFS`
environment variables set the corresponding limits; unset means `null`.

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `entrypoints` | integer[] | Pinned analysis entry VAs. Always `[]` from the CLI today; kept for future pinned-entry exports. |
| `max_instructions` | integer \| null | Instruction budget; the run fails (no export) when exceeded. |
| `max_functions` | integer \| null | Function budget; same failure semantics. |
| `max_blocks` | integer \| null | Block budget; same failure semantics. |
| `max_xrefs` | integer \| null | Xref budget; same failure semantics. |
| `deterministic` | boolean | The deterministic-analysis flag. Always `true` today. |

Note: a budget breach aborts the run instead of truncating it, so a delivered
document never silently reflects a partial budget. A missing field or a
different value here means the outputs are not comparable across runs.

### `functions[]`

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `id` | integer | Dense `FunctionId` (`u32`), enumerated in ascending `entry` order. Scoped to this export only. |
| `entry` | integer | Function entry VA. The stable key for cross-run joins: `(binary_sha256, entry)`. |
| `name` | string \| null | Preferred loader seed name when known, otherwise a synthesized `sub_<hex>` label; the field is nullable in the wire shape. |
| `block_ids` | integer[] | `blocks[].id` values reachable from `entry`. Resolves only within this document. |
| `seed_provenance` | string[] | Deterministically sorted evidence for why this function entry was analyzed. Values include `image_entry`, `symbol`, `export`, `exception_table`, `analysis_option_entrypoint`, and `direct_call_target`; `recursive_discovery` is used when no entry evidence is available. This records discovery provenance, not confidence or semantic certainty. |

### `blocks[]`

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `id` | integer | Dense `BlockId` (`u32`), enumerated in ascending `start` order. Scoped to this export only. |
| `start` | integer | Block first-instruction VA (inclusive). |
| `end` | integer | Block end VA, exclusive. `end - start` is the byte length. |
| `successor_ids` | integer[] | `blocks[].id` targets of the block's outgoing flow, ascending. Resolves only within this document. |

### `xrefs[]`

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `id` | integer | Dense `XrefId` (`u32`), enumerated in ascending `(from, to, kind)` order. Scoped to this export only. |
| `from` | integer | Source VA — the instruction or site producing the reference. |
| `to` | integer | Target VA — the referenced address. May point at a block, a function entry, an import slot, or any other VA. |
| `kind` | string enum | `call`, `code`, or `data`. `call` is a call-flow reference; `code` is non-call control flow; `data` is a data reference. |

### `imports[]`

| Field | JSON type | Meaning |
|-------|-----------|---------|
| `slot` | integer \| null | VA of the import slot (IAT thunk / PLT entry) that resolves this import at runtime, when the loader located one. `null` when no slot was identified — the import still exists. |
| `library` | string \| null | Supplying module name (e.g. `ntoskrnl.exe`), or `null` when the format does not record one. |
| `name` | string | Import symbol name. Always present. |
| `ordinal` | integer \| null | Import ordinal (`u16`) when imported by ordinal, else `null`. |
| `kind` | string enum | `function`, `object`, or `other`. |

## Identity and ordering

IDs are dense `u32`s scoped to this document only — a `FunctionId`/`BlockId`/
`XrefId` value says nothing about the underlying address and may collide across
exports of different binaries or producer versions. Cross-references
(`block_ids`, `successor_ids`) resolve only inside this document. The durable
join keys are `binary_sha256` plus virtual addresses (`entry`, `start`, `from`,
`to`, `slot`).

Ordering is deterministic: `functions`, `blocks`, and `xrefs` are emitted in
ascending `id` order (BTreeMap/BTreeSet-backed, so ids enumerate in ascending
entry, start, and `(from, to, kind)` order respectively). `imports` follows the
loader's image order. The document is compact single-line JSON with keys in
serializer insertion order; consumers must parse fields by name.

## Fidelity

`fidelity` is the aggregate claim about the analysis run, not about any single
fact:

- `incomplete` — at least one decode gap occurred during discovery: missing
  bytes at an in-range address, a decoder error, or an address-overflow while
  walking a block. `fidelity: incomplete` must remain visible to consumers and
  must not be treated as a complete discovery claim; functions or blocks may be
  missing.
- `heuristic` — discovery ran to completion without decode gaps, but
  recursive-descent discovery is heuristic by construction (the aggregate is
  downgraded to `heuristic` whenever any functions were discovered, even with
  no gaps).
- `canonical` — the analyzer degraded nothing and discovered no functions; an
  edge case, not a completeness proof for real images.

## Provenance and determinism

`producer`, `loader_semantics_version`, `decoder_semantics_version`,
`analysis_options`, and `binary_sha256` are the provenance record. The JSON is
deterministic for the same binary, radare3 version, analysis options, and
decoder semantics: the analyzer commits canonical state from sorted containers,
and the serializer walks those sorted maps. A change to any provenance input —
including `RADARE3_MAX_*` env limits — can change ids, names, ranges, and xref
sets, so cross-run comparisons must key on the full provenance tuple plus
addresses, never on ids alone.

## Versioning and compatibility

`schema` is the contract version (`radare3.static.v1`); consumers must gate on
it. Within a schema version the contract is additive: new optional fields may
appear and consumers must ignore fields they do not recognize. Field removals,
renames, meaning changes, and type changes require a new schema token. Future
target-selection metadata should be an additive, versioned contract rather than
inferred from an import name or xref alone.

## Deliberately unresolved in v1

- **No instruction-level facts.** Blocks carry address ranges and successors
  only — no bytes, mnemonics, or per-instruction records. Instruction detail is
  intentionally absent from this export.
- **No canonical ISANITY instruction identities.** This document carries no
  instruction form ids at all. The only ISANITY-adjacent surface is the
  `decode-evidence` handoff (`docs/JSON.md`), where the canonical mapping
  stays explicitly unresolved; nothing here synthesizes one.
- **No symbols, segments, strings, or relocations.** Only imports plus the
  analysis outputs are exported; richer image metadata lives in `ij`/`iSj`/
  `isj`/`iij` outputs, not this document.
- **No target-selection or IOCTL metadata.** Do not infer driver targets from
  `imports[].name` or xref targets.
- **`imports[].slot`, `library`, and `ordinal`** stay `null` when the loader
  cannot populate them — absence is semantic, not a serialization bug.
- **`analysis_options.entrypoints`** stays `[]` today; pinned-entry exports are
  a future additive change.

## Example

Reduced real shape (single function, one block, one call xref to an import
slot; `fidelity` shown as `incomplete`):

```json
{"schema":"radare3.static.v1","producer":{"name":"radare3","version":"0.0.1"},"loader_semantics_version":"goblin-0.10.7/radare3-loader-v4-elf-import-slots","decoder_semantics_version":"iced-x86-1.21.0/radare3-x86-v3-absolute-data-xrefs","binary_sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","format":"pe","architecture":"x86_64","base_address":5368709120,"entry_point":5368713216,"fidelity":"incomplete","analysis_options":{"entrypoints":[],"max_instructions":100,"max_functions":null,"max_blocks":null,"max_xrefs":null,"deterministic":true},"functions":[{"id":0,"entry":5368713216,"name":"dispatch","block_ids":[0]}],"blocks":[{"id":0,"start":5368713216,"end":5368713232,"successor_ids":[]}],"xrefs":[{"id":0,"from":5368713220,"to":5368721408,"kind":"call"}],"imports":[{"slot":5368721408,"library":"ntoskrnl.exe","name":"MmMapIoSpace","ordinal":null,"kind":"function"}]}
```

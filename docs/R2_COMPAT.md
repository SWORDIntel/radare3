# radare2 compatibility plane

radare3 does not need to reimplement every radare2 subsystem.

The compatibility layer classifies commands into:

```text
Native
Fallback
Unsupported
```

## Current native surface

These are already backed by radare3 functionality:

```text
afl
agf
izz
/x
/xj
aflj
agfj
izzj
ij
```

## Current fallback surface

These are recognized as useful r2 commands but are not yet implemented natively:

```text
aaa
px
pxj
s
```

## Fallback executor

`R2FallbackExecutor` now executes only commands classified as `Fallback`.

It invokes radare2 directly with explicit argv:

```text
r2 -2 -q -c <command> <binary>
```

There is no shell interpolation.

The executor:

- uses a configurable executable path,
- has a configurable timeout,
- drains stdout/stderr concurrently to avoid pipe deadlock,
- kills and reaps radare2 on timeout,
- returns stdout, stderr, exit code, and an explicit `timed_out` bit,
- refuses native and unsupported commands before spawning anything,
- reports spawn/I/O/thread failures separately.

## Explicit CLI routing

Fallback is exposed only through an explicit routing command:

```sh
radare3 route <file> <r2-style-command...>
```

The router classifies the command first:

- `Native` commands execute inside radare3.
- `Fallback` commands invoke `R2FallbackExecutor`.
- `Unsupported` commands fail without spawning anything.

Fallback is always announced on stderr with `route=fallback engine=radare2`. Normal radare3 commands never silently invoke radare2.

Native routing currently covers:

```text
afl
aflj
afi
afij
agf
agfj
axt
axtj
axf
axfj
pdf
pdfj
izz
izzj
/x
/xj
ij
```

The remaining fallback surface can be replaced one command at a time as native engines mature.


## Native xref/query semantics

The current native `axt` and `axf` query the exact address against radare3's current analysis xref set. They do not yet claim every stateful or heuristic behavior of radare2's richer xref database.

`afi` resolves a discovered function by entry address (or the binary entry point by default), reports block count, incoming xrefs to the function entry, and outgoing xrefs whose source address lies inside one of the function's canonical blocks.


## Sections and byte views

`iS` and `iSj` are now native because they map directly to radare3's normalized segment model.

The standalone CLI also provides stateless byte views:

```sh
radare3 px <file> <address> [length]
radare3 pxj <file> <address> [length]
```

Routed `px`/`pxj` remain radare2 fallbacks because r2's command semantics depend on the session seek state. radare3 does not pretend a one-shot CLI address is the same thing as a persistent r2 seek cursor.


## Symbols

`is` and `isj` are native. The normalized symbol table currently includes:

- named defined ELF function symbols from `.symtab` and `.dynsym`,
- named defined ELF object/other symbols,
- named PE exports.

Undefined/import symbols are intentionally not reported as local symbols; import normalization belongs on a separate `ii`-class surface.


## Imports

`ii` and `iij` are native.

PE imports include the loader-patched IAT slot virtual address when it can be represented safely, plus DLL/name and ordinal for ordinal-only imports.

ELF imports are undefined named entries from `.dynsym`. They are deliberately emitted without a fabricated slot or provider library because resolving those requires relocation/version/dependency information beyond the symbol table itself.


## Function disassembly

`pdf` and `pdfj` are native.

They first run radare3 analysis, resolve a discovered function by entry address (or use the binary entry point), then format the canonical basic-block ranges belonging to that function. This deliberately avoids treating an arbitrary contiguous byte range as equivalent to a recovered function.


## Native session state

`radare3 session <file>` introduces a native persistent seek and a lazy in-memory analysis result without changing one-shot routing semantics.

Inside a session, `s`, `px`, and `pxj` are native against the current seek. Analysis-backed commands such as `afl` and `pdf` compute analysis once and reuse it for subsequent commands.

One-shot routed `s`/`px`/`pxj` remain radare2 fallbacks for now because a single routed command has no persistent native seek context.


## Analysis export

`radare3 export-r2 <file>` emits a deterministic additive radare2 command script from radare3's canonical analysis.

The current export contains:

```text
af+   discovered functions
afb+  canonical basic blocks
axC   call xrefs
axc   code xrefs
axd   data xrefs
```

Function names are sanitized to command-safe tokens and duplicate names receive a deterministic address suffix.

The export deliberately emits no destructive reset commands such as `af-`, flag wipes, or project clears. It is intended to layer radare3 discovery into an existing radare2 workflow rather than erase analyst state.

Example:

```sh
radare3 export-r2 sample.bin > sample.r2
r2 -q -i sample.r2 sample.bin
```

Malformed CFG references or invalid block ranges fail export instead of generating a partial script.

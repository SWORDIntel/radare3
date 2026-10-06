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
pdf
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

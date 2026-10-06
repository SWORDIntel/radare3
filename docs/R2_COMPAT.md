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
afi
pdf
axt
axf
is
iS
px
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
agf
agfj
izz
izzj
/x
/xj
ij
```

The remaining fallback surface can be replaced one command at a time as native engines mature.

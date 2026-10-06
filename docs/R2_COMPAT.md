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
/xj
aflj
agfj
izzj
ij
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

The executor exists at the compatibility-library layer. The CLI does not automatically fall back yet; that remains an explicit integration decision so fallback is never invisible.

## Next step

Expose explicit CLI fallback/routing mode, then replace fallback JSON commands with native radare3 renderers one at a time.

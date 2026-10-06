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

The current router only classifies. It does not yet spawn radare2.

## Next step

Add an explicit fallback executor that:

1. receives a command classified as `Fallback`,
2. invokes a configured radare2 executable,
3. forwards the current binary,
4. captures exit status/stdout/stderr,
5. makes fallback observable to the caller,
6. never silently turns execution failure into native success.

Native JSON variants should replace fallback one command at a time.

# Single-load session

The first session implementation is deliberately small: keep one mapped binary alive, maintain a seek address, and lazily compute one deterministic analysis result for reuse.

```sh
radare3 session <file>
```

Input is line-oriented, so the same engine works interactively or through pipes.

## State

A session owns:

```text
BinaryImage       one mmap-backed normalized image
seek              persistent virtual address
AnalysisOptions   resource policy captured at session start
AnalysisResult    absent until first analysis-backed command
```

The first `afl`/`pdf` command emits `session-analysis=miss` on stderr. Later analysis-backed commands emit `session-analysis=hit` and reuse the same result.

## Commands

```text
s [address]                    show or change seek
px [length]                    bytes at seek
pxj [length]                   JSON bytes at seek
afl                            function list
pdf [function-address]         CFG-backed function disassembly
pdfj [function-address]        JSON CFG-backed disassembly
info / ij                     binary metadata
iS / iSj                      normalized segments
is / isj                      normalized symbols
ii / iij                      normalized imports
? / help                      session help
q / quit                      exit
```

When `pdf` has no explicit function address, it resolves the function at the current seek. The initial seek is the binary entry point when present, otherwise the normalized base address.

Malformed or unsupported session commands report an error and leave the session running. Input I/O failure terminates the session.

## Deliberate limits

This is not yet a clone of radare2's complete interactive state model. It does not currently persist flags, comments, typed variables, debugger state, analysis mutations, or arbitrary r2 configuration. Those should be added only where they serve measured workflows.

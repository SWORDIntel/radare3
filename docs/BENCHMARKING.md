# Benchmarking contract

Speed without equivalent output is not a win.

## Minimum measurements

Every benchmark record should capture:

- target hash
- target size
- format and architecture
- command/workload
- wall-clock time
- CPU time
- peak RSS
- functions discovered
- basic blocks discovered
- CFG edges
- xrefs
- strings
- tool version / commit
- host CPU and thread count

## Initial workloads

Compare equivalent radare2 and radare3 operations for:

- open + headers
- symbol enumeration
- string scan
- literal byte search
- function discovery
- CFG recovery
- xref recovery
- full `aaa`-class analysis once feature parity exists
- cached reopen

## Corpus classes

- small ELF utilities
- stripped ELF executables
- large C++ ELF binaries
- PE executables
- Windows drivers
- Go binaries
- firmware / raw blobs

Do not add malware samples, proprietary binaries, or redistributability-sensitive fixtures directly to the repository. Store hashes and acquisition/build recipes instead.

## Gates

- No headline speed claim without at least 10 measured runs per target after warm-up.
- Report median and dispersion, not the best run.
- Correctness regressions block performance merges.
- A >5% median regression on an established hot-path benchmark requires explanation or rollback.

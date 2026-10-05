# Benchmarking contract

Speed without equivalent output is not a win.

## Required comparisons

For function/CFG work, every performance run should include:

- radare3 parallel
- radare3 sequential truth oracle
- radare2 equivalent workload

The parallel and sequential radare3 results must agree before a timing is considered valid.

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
- radare3 commit
- radare2 version
- host CPU
- logical CPU count
- `RAYON_NUM_THREADS`

## Harness

```sh
./scripts/bench-analysis.sh /bin/ls /bin/bash
```

Pin threads when comparing hosts or scaling:

```sh
RAYON_NUM_THREADS=1 RUNS=20 ./scripts/bench-analysis.sh /bin/ls
RAYON_NUM_THREADS=2 RUNS=20 ./scripts/bench-analysis.sh /bin/ls
RAYON_NUM_THREADS=4 RUNS=20 ./scripts/bench-analysis.sh /bin/ls
RAYON_NUM_THREADS=8 RUNS=20 ./scripts/bench-analysis.sh /bin/ls
```

The harness refuses to proceed if parallel and sequential radare3 function counts differ. Full structural equality is enforced separately in unit fixtures.

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

- Parallel output must match the sequential truth oracle on differential fixtures.
- No headline speed claim without at least 10 measured runs per target after warm-up.
- Report median and dispersion, not the best run.
- Correctness regressions block performance merges.
- A >5% median regression on an established hot-path benchmark requires explanation or rollback.
- radare2 function counts are a coverage signal until analysis parity is materially closer; timing dissimilar outputs is not a valid speed claim.

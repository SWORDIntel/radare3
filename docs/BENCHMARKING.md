# Benchmarking contract

Speed without equivalent output is not a win.

## Required comparisons

For function/CFG work:

- radare3 parallel
- radare3 sequential truth oracle
- radare2 equivalent workload

For literal search:

- radare3 SIMD-backed search
- radare2 `/xj`
- identical hit counts before timing

## Reproducible corpus

The repository includes source, not generated binaries:

```sh
./scripts/build-benchmark-corpus.sh
```

The wrapper runs `scripts/build-corpus.py`, which executes the `[[target]]`
recipes in `benchmarks/corpus.toml` (schema 2). Each recipe runs from the
repository root with `TARGET_OUT` set inside `.radare3/corpus/`. Nothing is
downloaded; every binary comes from a committed fixture under
`benchmarks/fixtures/`.

Current recipe matrix:

| Target | Language | Format | Notes |
|--------|----------|--------|-------|
| `r3bench-o0` | C | ELF (ET_EXEC) | `-O0`, unstripped |
| `r3bench-o2` | C | ELF (ET_EXEC) | `-O2 -s`, stripped |
| `r3bench-pie` | C | ELF (ET_DYN) | `-O2 -fPIE -pie` |
| `r3bench-cpp` | C++17 | ELF | exceptions, virtual dispatch, unstripped |
| `r3bench-rs` | Rust | ELF | `rustc -C opt-level=2`, unstripped |
| `r3bench-go` | Go | ELF | static, `-trimpath -s -w`; optional (`go`) |
| `r3bench-pe-o0.exe` | C | PE32+ | `-O0`, unstripped; optional (mingw-w64) |
| `r3bench-pe-o2.exe` | C | PE32+ | `-O2 -s`; optional (mingw-w64) |

Optional targets are skipped with a note when their `requires` toolchain is
absent, so the corpus still builds on minimal machines. The build writes
`.radare3/corpus/manifest.json` with each target's size and SHA-256; the
manifest carries no timestamps, so a byte-identical manifest across two
builds confirms toolchain determinism:

```sh
./scripts/build-benchmark-corpus.sh >/dev/null
sha256sum .radare3/corpus/manifest.json
./scripts/build-benchmark-corpus.sh >/dev/null
sha256sum .radare3/corpus/manifest.json   # identical digest expected
```

The search marker is recorded in `benchmarks/corpus.toml`. Generated corpus
binaries and the manifest remain ignored.

## Stored results

Analysis:

```sh
RUNS=20 RAYON_NUM_THREADS=8 ./scripts/bench-analysis.sh
```

Literal search:

```sh
RUNS=20 ./scripts/bench-search.sh
```

Both scripts require `hyperfine` and write JSON into `.radare3/bench/` by default. Each hyperfine result gets a sibling `.meta.json` with target SHA-256, file size, radare3 commit, radare2 version, CPU, kernel, logical CPU count, and Rayon thread setting.

Resource behavior:

```sh
RUNS=10 RAYON_NUM_THREADS=8 ./scripts/bench-resources.sh
```

The resource benchmark uses GNU `/usr/bin/time` and stores raw per-run TSV samples for radare3 parallel, radare3 sequential, and radare2 analysis. Each sample records elapsed/user/system time, maximum RSS, minor and major page faults, and voluntary/involuntary context switches. It verifies radare3 structural equivalence before measuring.

To preserve a significant run, copy the JSON and metadata into `benchmarks/results/<machine>/` in a dedicated benchmark commit.

## Bare-metal runner

`scripts/bench-baremetal.py` is the portable whole-corpus runner. It needs
only Python 3 and the built `radare3` binary — no hyperfine, radare2, or
GNU time — so it runs on machines where the comparison stack is missing.
Per-run wall/user/system time, maximum RSS, and minor/major page faults are
captured with `wait4(2)` rusage; where `wait4` is unavailable only wall time
is recorded.

```sh
cargo build --release -p radare3-cli
python3 scripts/bench-baremetal.py --runs 10 --warmup 3 --threads 8
```

Useful variations:

```sh
# sequential scheduler workload
python3 scripts/bench-baremetal.py --workload analysis-sequential

# subset of the corpus, report to stdout
python3 scripts/bench-baremetal.py --target r3bench-rs --out -

# preserve a candidate report for review
python3 scripts/bench-baremetal.py \
  --out benchmarks/results/<machine>/candidate-baremetal-$(date -u +%Y%m%dT%H%M%SZ).json
```

Each report (`radare3.baremetal.v1`) records host identity (machine
manifest), build identity (radare3 SHA-256, git commit and dirty flag,
rustc), workload identity (per-target SHA-256/size/format/architecture,
runs, warmup, `RAYON_NUM_THREADS`, corpus manifest SHA-256), all raw
samples, medians, and throughput (`target_size_bytes / median_wall_seconds`).
The same structural gates as the hyperfine harness apply: `radare3 verify`
and the parallel/sequential function-count check must pass before timing.

Default output lands in `.radare3/baremetal/` and stays ignored. A report is
a **single-host record**: absolute numbers are not comparable across
machines and must never be used to rank hosts — re-measure each
configuration. Only a report written explicitly under
`benchmarks/results/<machine>/` may be committed, after the baseline
checklist in `benchmarks/BASELINE.md`.

## Regression gate

Compare an established baseline with a new hyperfine result:

```sh
python3 scripts/check-benchmark-regression.py \
  benchmarks/results/<machine>/baseline.json \
  .radare3/bench/current.json \
  --threshold 5
```

The checker uses per-command medians and exits non-zero when any matched command is more than 5% slower. CI exercises the checker against synthetic JSON fixtures; CI does **not** pretend its shared runner is a stable performance baseline.

## Minimum measurements

A preserved benchmark should capture:

- target SHA-256 and size
- format and architecture
- workload
- wall-clock samples and median
- maximum RSS and page-fault behavior for preserved resource campaigns
- functions / blocks / xrefs or search hits as appropriate
- radare3 commit
- radare2 version
- host CPU and logical CPU count
- `RAYON_NUM_THREADS`

## Gates

- Parallel output must match the sequential truth oracle before analysis timing.
- Literal-search hit counts must match radare2 before search timing.
- No headline speed claim without at least 10 measured runs after warm-up.
- Report median and dispersion, not the best run.
- Correctness regressions block performance merges.
- A >5% median regression on a stable machine requires explanation or rollback.
- Shared GitHub-hosted runners are validation infrastructure, not benchmark baselines.
- radare2 function counts remain a coverage signal until analysis parity is materially closer.


## Full benchmark campaign

For a stable bare-metal machine:

```sh
MACHINE_ID=<machine> RUNS=20 THREADS="1 2 4 8 16 32" \
  ./scripts/run-benchmark-campaign.sh
```

This captures a machine manifest once, runs the analysis benchmark across every requested thread count supported by the host, then runs literal-search and resource-behavior benchmarks. Set `RESOURCE_RUNS` separately when the resource campaign should use fewer samples than the timing campaign.

See [benchmarks/BASELINE.md](../benchmarks/BASELINE.md).

## Profiling

Use the same representative target used for the baseline:

```sh
RAYON_NUM_THREADS=<count> ./scripts/profile-analysis.sh
```

The profile directory contains `perf stat`, `perf record`, a text `perf report`, the target SHA-256, and the machine manifest. If `heaptrack` is installed, an allocation profile is attempted as a supplementary artifact.

Profiling is diagnostic evidence, not a benchmark result. Optimize the largest measured costs first.


## Thread-scaling summary

A full campaign now produces `summary.json` and `summary.tsv` automatically.

The summarizer uses the one-thread `radare3 parallel` median as the per-target baseline:

```text
speedup(N) = T1 / TN
efficiency(N) = speedup(N) / N
```

Run it independently on an existing campaign:

```sh
python3 scripts/summarize-benchmark-campaign.py .radare3/campaign/<machine>
```

The JSON retains the parallel, sequential, and radare2 medians for each target/thread point so scaling can be inspected without losing the comparison context.


## Session reuse

Measure repeated analysis work as two equivalent user workflows:

```sh
RUNS=20 ./scripts/bench-session.sh
```

The benchmark compares:

```text
one-shot: radare3 afl <file> ; radare3 pdf <file>
session:  printf 'afl\npdf\nq\n' | radare3 session <file>
```

The one-shot path maps and analyzes the binary independently for each command. The session path maps once and reuses one in-memory analysis result.

This benchmark measures the end-to-end workflow benefit of reuse. It is not a substitute for the analysis benchmark, and no speedup claim should be made until the same stable-machine requirements are met.


## Repeated session query benchmark

Secondary indexes are measured with a dedicated repeated-query workload rather than inferred from broad session timings:

```sh
RUNS=20 QUERY_REPEATS=100 ./scripts/bench-session-queries.sh
```

For each target it records two independent hyperfine result sets:

- `session-function-queries`: repeated `afij` + `agfj`
- `session-xref-queries`: repeated `axtj` + `axfj`

Each measured session performs analysis once, then exercises the same immutable analysis repeatedly. This makes before/after index changes comparable without pretending function and xref queries are equivalent workloads.

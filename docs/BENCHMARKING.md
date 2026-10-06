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

This builds:

- `.radare3/corpus/r3bench-o0`
- `.radare3/corpus/r3bench-o2`

The recipes and search marker are recorded in `benchmarks/corpus.toml`. Generated corpus binaries remain ignored.

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

To preserve a significant run, copy the JSON and metadata into `benchmarks/results/<machine>/` in a dedicated benchmark commit.

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

This captures a machine manifest once, runs the analysis benchmark across every requested thread count supported by the host, then runs literal-search benchmarks.

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

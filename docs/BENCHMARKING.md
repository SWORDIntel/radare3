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

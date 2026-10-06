# Stable-machine benchmark baseline

A project baseline must come from a stable, identified machine. Shared CI runners are not accepted as performance baselines.

## First campaign

```sh
MACHINE_ID=<short-machine-name> \
RUNS=20 \
THREADS="1 2 4 8 16 32" \
./scripts/run-benchmark-campaign.sh
```

Results are written below:

```text
.radare3/campaign/<machine>/
  machine.json
  analysis-t1/
  analysis-t2/
  ...
  search/
```

For a profile of the representative O2 target:

```sh
RAYON_NUM_THREADS=<physical-or-logical-count> ./scripts/profile-analysis.sh
```

Preserve a chosen baseline under `benchmarks/results/<machine>/` only after checking:

- CPU governor is appropriate and stable.
- No thermal throttling occurred.
- Background load was low.
- At least 10 post-warm-up runs were recorded.
- Parallel/sequential structural verification passed.
- Search hit counts matched radare2.
- Target hashes and tool versions are present.

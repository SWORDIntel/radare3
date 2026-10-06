#!/usr/bin/env python3
import argparse
import json
import re
import statistics
import sys
from pathlib import Path

THREAD_DIR = re.compile(r"^analysis-t([1-9][0-9]*)$")


def median_for(payload, command):
    for result in payload.get("results", []):
        if result.get("command") != command:
            continue
        if "median" in result:
            return float(result["median"])
        times = result.get("times")
        if times:
            return float(statistics.median(times))
        raise ValueError(f"{command!r} has no median or times")
    raise ValueError(f"missing benchmark command {command!r}")


def target_for(result_path):
    meta_path = result_path.with_suffix(".meta.json")
    if meta_path.exists():
        payload = json.loads(meta_path.read_text())
        target = payload.get("target")
        if isinstance(target, str) and target:
            return target
    name = result_path.stem
    if name.startswith("analysis-"):
        name = name[len("analysis-") :]
    name = re.sub(r"-[0-9]{8}T[0-9]{6}Z$", "", name)
    return name


def discover(campaign_dir):
    records = []
    for thread_dir in sorted(campaign_dir.iterdir()):
        match = THREAD_DIR.match(thread_dir.name)
        if not match or not thread_dir.is_dir():
            continue
        threads = int(match.group(1))
        for result_path in sorted(thread_dir.glob("analysis-*.json")):
            if result_path.name.endswith(".meta.json"):
                continue
            payload = json.loads(result_path.read_text())
            records.append(
                {
                    "target": target_for(result_path),
                    "threads": threads,
                    "parallel_median_s": median_for(payload, "radare3 parallel"),
                    "sequential_median_s": median_for(payload, "radare3 sequential"),
                    "radare2_median_s": median_for(payload, "radare2 aaa+afl"),
                    "result": str(result_path),
                }
            )
    if not records:
        raise ValueError(f"{campaign_dir}: no analysis benchmark JSON files found")
    return records


def summarize(records):
    by_target = {}
    for record in records:
        key = (record["target"], record["threads"])
        if key in by_target:
            raise ValueError(
                f"duplicate target/thread benchmark: {record['target']} t{record['threads']}"
            )
        by_target[key] = record

    targets = sorted({record["target"] for record in records})
    rows = []

    for target in targets:
        baseline = by_target.get((target, 1))
        if baseline is None:
            raise ValueError(f"{target}: missing 1-thread baseline")
        base = baseline["parallel_median_s"]
        if base <= 0:
            raise ValueError(f"{target}: 1-thread median must be > 0")

        target_records = sorted(
            (record for record in records if record["target"] == target),
            key=lambda record: record["threads"],
        )
        for record in target_records:
            median = record["parallel_median_s"]
            if median <= 0:
                raise ValueError(
                    f"{target} t{record['threads']}: parallel median must be > 0"
                )
            speedup = base / median
            efficiency = speedup / record["threads"]
            rows.append(
                {
                    **record,
                    "speedup": speedup,
                    "efficiency": efficiency,
                }
            )

    return rows


def write_tsv(path, rows):
    header = (
        "target\tthreads\tparallel_median_s\tspeedup\tefficiency"
        "\tsequential_median_s\tradare2_median_s\n"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row['target']}\t{row['threads']}\t{row['parallel_median_s']:.9f}"
            f"\t{row['speedup']:.6f}\t{row['efficiency']:.6f}"
            f"\t{row['sequential_median_s']:.9f}\t{row['radare2_median_s']:.9f}\n"
        )
    path.write_text("".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Summarize a radare3 thread-scaling benchmark campaign."
    )
    parser.add_argument("campaign_dir")
    parser.add_argument("--output")
    parser.add_argument("--tsv")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir)
    rows = summarize(discover(campaign_dir))

    output = Path(args.output) if args.output else campaign_dir / "summary.json"
    tsv = Path(args.tsv) if args.tsv else campaign_dir / "summary.tsv"
    output.parent.mkdir(parents=True, exist_ok=True)
    tsv.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema": 1,
        "campaign_dir": str(campaign_dir),
        "rows": rows,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_tsv(tsv, rows)

    print(
        "target\tthreads\tparallel_s\tspeedup\tefficiency"
        "\tsequential_s\tradare2_s"
    )
    for row in rows:
        print(
            f"{row['target']}\t{row['threads']}\t{row['parallel_median_s']:.6f}"
            f"\t{row['speedup']:.3f}x\t{row['efficiency']:.3f}"
            f"\t{row['sequential_median_s']:.6f}\t{row['radare2_median_s']:.6f}"
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"benchmark summary error: {error}", file=sys.stderr)
        raise SystemExit(2)

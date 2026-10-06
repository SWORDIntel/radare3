#!/usr/bin/env python3
import argparse
import json
import statistics
import sys
from pathlib import Path


def median_of(result):
    if "median" in result:
        return float(result["median"])
    times = result.get("times")
    if not times:
        raise ValueError(f"result {result.get('command', '<unknown>')} has no median or times")
    return float(statistics.median(times))


def load(path):
    payload = json.loads(Path(path).read_text())
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError(f"{path}: expected non-empty hyperfine results array")

    mapped = {}
    for result in results:
        command = result.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError(f"{path}: every result needs a command")
        mapped[command] = median_of(result)
    return mapped


def main():
    parser = argparse.ArgumentParser(
        description="Fail when current hyperfine medians regress beyond the allowed percentage."
    )
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--threshold", type=float, default=5.0)
    args = parser.parse_args()

    baseline = load(args.baseline)
    current = load(args.current)

    missing = sorted(set(baseline) - set(current))
    if missing:
        print(f"missing current benchmark commands: {', '.join(missing)}", file=sys.stderr)
        return 2

    failed = False
    for command in sorted(baseline):
        before = baseline[command]
        after = current[command]
        if before <= 0:
            raise ValueError(f"baseline median for {command!r} must be > 0")

        delta = ((after - before) / before) * 100.0
        print(
            f"{command}: baseline={before:.6f}s current={after:.6f}s delta={delta:+.2f}%"
        )
        if delta > args.threshold:
            failed = True

    if failed:
        print(
            f"benchmark regression exceeds {args.threshold:.2f}% threshold",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"benchmark regression checker error: {error}", file=sys.stderr)
        raise SystemExit(2)

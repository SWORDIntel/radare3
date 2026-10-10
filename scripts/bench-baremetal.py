#!/usr/bin/env python3
"""Portable bare-metal benchmark runner for radare3 analysis.

Measures the source-built corpus (or selected targets) through radare3 and
writes one self-contained JSON report recording:

- host identity (via scripts/machine-manifest.py)
- workload identity (corpus target SHA-256/size/format/arch, run counts,
  thread setting)
- build identity (radare3 binary SHA-256, git commit/dirty, rustc/cargo)
- per-run wall/user/system time, maximum RSS, minor and major page faults
- derived throughput (target bytes per median wall second)

Portability: standard library only — no hyperfine, radare2, or GNU time is
required. Per-process resources come from wait4(2) rusage (Linux, macOS);
on platforms without wait4, only wall time is recorded and resource fields
are null. RSS units are normalized to KiB.

Comparability: a report is a single-host record of one build on one
workload. Absolute numbers are NOT comparable across machines — never rank
hosts or claim speedups from two reports; re-measure every configuration.
"""
import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "radare3.baremetal.v1"
DEFAULT_OUT_DIR = ".radare3/baremetal"
MARKER_HEX = "524144415245335f5345415243485f4d41524b4552"

WORKLOADS = {
    "analysis": "afl",
    "analysis-sequential": "afl-seq",
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_json(argv):
    output = subprocess.check_output(argv, cwd=ROOT, text=True, stderr=subprocess.DEVNULL)
    return json.loads(output)


def run_quiet(argv, env=None):
    return subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode


def count_lines(argv, env=None):
    output = subprocess.check_output(argv, cwd=ROOT, env=env, stderr=subprocess.DEVNULL)
    return len(output.splitlines())


def host_manifest():
    try:
        return run_json(["python3", "scripts/machine-manifest.py"])
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def build_identity(r3):
    def git(*args):
        try:
            return subprocess.check_output(
                ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    rustc = None
    try:
        rustc = subprocess.check_output(
            ["rustc", "--version"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except OSError:
        pass

    return {
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain")),
        "profile": "release",
        "binary": r3,
        "binary_sha256": sha256(ROOT / r3),
        "binary_size": (ROOT / r3).stat().st_size,
        "rustc": rustc,
        "rustflags": os.environ.get("RUSTFLAGS"),
    }


def measure_posix(argv, env):
    start = time.perf_counter()
    pid = os.fork()
    if pid == 0:
        os.chdir(ROOT)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.execvpe(argv[0], argv, env)
        os._exit(127)
    _, status, usage = os.wait4(pid, 0)
    wall = time.perf_counter() - start
    rss_kib = usage.ru_maxrss
    if sys.platform == "darwin":
        rss_kib //= 1024
    return {
        "wall_seconds": wall,
        "user_seconds": usage.ru_utime,
        "system_seconds": usage.ru_stime,
        "max_rss_kib": rss_kib,
        "minor_faults": usage.ru_minflt,
        "major_faults": usage.ru_majflt,
        "exit_code": os.waitstatus_to_exitcode(status),
    }


def measure_fallback(argv, env):
    start = time.perf_counter()
    code = run_quiet(argv, env=env)
    return {
        "wall_seconds": time.perf_counter() - start,
        "user_seconds": None,
        "system_seconds": None,
        "max_rss_kib": None,
        "minor_faults": None,
        "major_faults": None,
        "exit_code": code,
    }


def measure(argv, env):
    if hasattr(os, "wait4"):
        return measure_posix(argv, env)
    return measure_fallback(argv, env)


def median_or_null(values):
    present = [v for v in values if v is not None]
    return statistics.median(present) if present else None


def target_info(r3, path, env):
    try:
        payload = run_json([r3, "ij", str(path)])
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return {}
    return {
        "format_detected": payload.get("format"),
        "architecture": payload.get("architecture"),
        "function_seed_count": payload.get("function_seed_count"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Single-host bare-metal analysis benchmark runner."
    )
    parser.add_argument("--runs", type=int, default=10, help="timed runs per target")
    parser.add_argument("--warmup", type=int, default=3, help="untimed runs per target")
    parser.add_argument(
        "--workload",
        choices=sorted(WORKLOADS),
        default="analysis",
        help="measured workload (default: analysis = radare3 afl)",
    )
    parser.add_argument(
        "--corpus",
        help="corpus directory or manifest.json (default: build benchmarks/corpus.toml)",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="NAME",
        help="restrict to named manifest target(s) (repeatable)",
    )
    parser.add_argument("--threads", type=int, help="RAYON_NUM_THREADS for measured runs")
    parser.add_argument(
        "--r3", default="target/release/radare3", help="radare3 binary (built if missing)"
    )
    parser.add_argument(
        "--out",
        help=(
            "report path; default .radare3/baremetal/report-<ts>.json (ignored). "
            "Use an explicit path such as benchmarks/results/<machine>/candidate-*.json "
            "to preserve a candidate report."
        ),
    )
    args = parser.parse_args()

    if args.runs < 1 or args.warmup < 0:
        parser.error("--runs must be >= 1 and --warmup >= 0")
    if args.threads is not None and args.threads < 1:
        parser.error("--threads must be >= 1")

    r3 = args.r3
    if not (ROOT / r3).is_file():
        subprocess.run(["cargo", "build", "--release", "-p", "radare3-cli"], cwd=ROOT, check=True)
    if not (ROOT / r3).is_file():
        parser.error(f"radare3 binary not found: {r3}")

    if args.corpus:
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = ROOT / corpus_path
        manifest_path = corpus_path if corpus_path.is_file() else corpus_path / "manifest.json"
    else:
        code = run_quiet(["python3", "scripts/build-corpus.py"])
        if code != 0:
            print("corpus build failed", file=sys.stderr)
            return code
        manifest_path = ROOT / ".radare3/corpus/manifest.json"

    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"cannot read corpus manifest {manifest_path}: {error}")
    try:
        manifest_label = str(manifest_path.relative_to(ROOT))
    except ValueError:
        manifest_label = str(manifest_path)

    targets = manifest.get("targets", [])
    wanted = set(args.target)
    if wanted:
        targets = [t for t in targets if t["name"] in wanted or Path(t["path"]).name in wanted]
    missing = wanted - {t["name"] for t in targets} - {Path(t["path"]).name for t in targets}
    if missing:
        parser.error(f"unknown corpus target(s): {', '.join(sorted(missing))}")
    if not targets:
        parser.error("corpus manifest has no targets")

    env = dict(os.environ)
    if args.threads is not None:
        env["RAYON_NUM_THREADS"] = str(args.threads)
    threads = env.get("RAYON_NUM_THREADS", "auto")

    status_out = sys.stderr if args.out == "-" else sys.stdout

    def status(message):
        print(message, file=status_out)

    status(f"radare3: {r3} (threads={threads})")
    status(
        f"workload: {args.workload} ({WORKLOADS[args.workload]}), "
        f"{args.runs} runs +{args.warmup} warmup"
    )
    status(f"targets: {len(targets)}")

    results = []
    for target in targets:
        path = target["path"]
        name = target["name"]
        verify = run_quiet([r3, "verify", path], env=env)
        if verify != 0:
            print(f"{name}: verification failed", file=sys.stderr)
            return 3

        parallel = count_lines([r3, "afl", path], env=env)
        sequential = count_lines([r3, "afl-seq", path], env=env)
        if parallel != sequential:
            print(
                f"{name}: parallel/sequential function counts differ "
                f"({parallel} != {sequential})",
                file=sys.stderr,
            )
            return 3

        command = [r3, WORKLOADS[args.workload], path]
        for _ in range(args.warmup):
            if run_quiet(command, env=env) != 0:
                print(f"{name}: warm-up run failed", file=sys.stderr)
                return 3

        samples = []
        for _ in range(args.runs):
            sample = measure(command, env)
            if sample["exit_code"] != 0:
                print(f"{name}: measured run failed", file=sys.stderr)
                return 3
            samples.append(sample)

        medians = {
            key: median_or_null(sample[key] for sample in samples)
            for key in (
                "wall_seconds",
                "user_seconds",
                "system_seconds",
                "max_rss_kib",
                "minor_faults",
                "major_faults",
            )
        }
        wall = medians["wall_seconds"]
        throughput = target["size"] / wall if wall and wall > 0 else None

        results.append(
            {
                "target": {**target, **target_info(r3, path, env)},
                "verification": {
                    "status": "pass",
                    "functions_parallel": parallel,
                    "functions_sequential": sequential,
                },
                "command": command,
                "samples": samples,
                "median": medians,
                "throughput": {
                    "bytes_per_second": throughput,
                    "definition": "target_size_bytes / median_wall_seconds",
                },
            }
        )

        rss = medians["max_rss_kib"]
        status(
            f"{name}: wall={wall * 1000:.1f}ms rss={rss}KiB "
            f"faults(min/maj)={medians['minor_faults']}/{medians['major_faults']} "
            f"throughput={throughput / 1e6:.2f}MB/s funcs={parallel}"
        )

    report = {
        "schema": SCHEMA,
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "comparability": (
            "single-host record: absolute values describe this machine, build, "
            "and workload only; not valid for cross-machine comparison"
        ),
        "host": host_manifest(),
        "build": build_identity(r3),
        "workload": {
            "name": args.workload,
            "command": WORKLOADS[args.workload],
            "runs": args.runs,
            "warmup": args.warmup,
            "rayon_num_threads": threads,
            "corpus_manifest": manifest_label,
            "corpus_manifest_sha256": sha256(manifest_path),
            "corpus_config_sha256": manifest.get("config_sha256"),
        },
        "results": results,
    }

    if args.out == "-":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        if args.out:
            out = Path(args.out)
        else:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            out = ROOT / DEFAULT_OUT_DIR / f"report-{stamp}.json"
        if not out.is_absolute():
            out = ROOT / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        try:
            print(f"report: {out.relative_to(ROOT)}")
        except ValueError:
            print(f"report: {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

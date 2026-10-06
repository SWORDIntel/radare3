#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


def run(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_model():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--workload", required=True)
    args = parser.parse_args()

    target = Path(args.target)
    result = Path(args.results)
    output = result.with_suffix(".meta.json")

    payload = {
        "schema": 1,
        "workload": args.workload,
        "target": str(target),
        "target_size": target.stat().st_size,
        "target_sha256": sha256(target),
        "results": str(result),
        "radare3_commit": run("git", "rev-parse", "HEAD"),
        "radare2_version": run("r2", "-v"),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpu": cpu_model(),
            "logical_cpus": os.cpu_count(),
            "rayon_threads": os.environ.get("RAYON_NUM_THREADS", "auto"),
        },
    }

    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(output)


if __name__ == "__main__":
    main()

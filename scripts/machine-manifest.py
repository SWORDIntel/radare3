#!/usr/bin/env python3
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


def run(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def cpu_model():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or None


def physical_cores():
    value = run("lscpu", "-p=CORE,SOCKET")
    if value:
        pairs = {
            line
            for line in value.splitlines()
            if line and not line.startswith("#")
        }
        if pairs:
            return len(pairs)
    return None


def governor():
    path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    if path.exists():
        return path.read_text(errors="replace").strip()
    return None


def filesystem(path="."):
    output = run("df", "-T", path)
    if not output:
        return None
    lines = output.splitlines()
    if len(lines) < 2:
        return None
    fields = lines[-1].split()
    if len(fields) < 2:
        return None
    return {"device": fields[0], "type": fields[1]}


def tool_version(command, *args):
    if shutil.which(command) is None:
        return None
    return run(command, *args)


payload = {
    "schema": 1,
    "hostname": platform.node(),
    "system": platform.system(),
    "release": platform.release(),
    "machine": platform.machine(),
    "cpu_model": cpu_model(),
    "physical_cores": physical_cores(),
    "logical_cpus": os.cpu_count(),
    "cpu_governor": governor(),
    "filesystem": filesystem("."),
    "numa": run("lscpu", "-e=CPU,NODE,SOCKET,CORE"),
    "rustc": tool_version("rustc", "--version"),
    "cargo": tool_version("cargo", "--version"),
    "cc": tool_version(os.environ.get("CC", "cc"), "--version"),
    "radare2": tool_version("r2", "-v"),
    "hyperfine": tool_version("hyperfine", "--version"),
    "git_commit": run("git", "rev-parse", "HEAD"),
}

print(json.dumps(payload, indent=2, sort_keys=True))

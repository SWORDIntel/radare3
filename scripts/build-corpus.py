#!/usr/bin/env python3
"""Build the reproducible multi-language benchmark corpus from corpus.toml.

Each [[target]] recipe runs from the repository root with TARGET_OUT set to
the target's path inside [defaults].output_dir. Targets marked
`optional = true` are skipped with a note when a `requires` command is
missing; missing requirements on non-optional targets fail the build.

Every built target is recorded with size and SHA-256 in
<output_dir>/manifest.json. The manifest contains no timestamps, so a
reproducible rebuild produces a byte-identical manifest — compare two runs
to verify toolchain determinism.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message):
    print(f"build-corpus: {message}", file=sys.stderr)
    raise SystemExit(2)


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_config(path):
    try:
        payload = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if payload.get("schema") not in (1, 2):
        fail(f"{path}: unsupported schema {payload.get('schema')!r}")
    defaults = payload.get("defaults", {})
    output_dir = defaults.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        fail(f"{path}: [defaults].output_dir is required")
    targets = payload.get("target", [])
    if not isinstance(targets, list) or not targets:
        fail(f"{path}: no [[target]] entries")
    return defaults, targets


def main():
    parser = argparse.ArgumentParser(
        description="Build the reproducible benchmark corpus from corpus.toml."
    )
    parser.add_argument(
        "config",
        nargs="?",
        default="benchmarks/corpus.toml",
        help="corpus recipe file (default: benchmarks/corpus.toml)",
    )
    parser.add_argument(
        "--only",
        metavar="NAME",
        action="append",
        default=[],
        help="build only the named target(s) (repeatable)",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    defaults, targets = load_config(config_path)

    output_dir = Path(defaults["output_dir"])
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    selected = set(args.only)
    built = []
    skipped = []
    previous = {}
    manifest_path = output_dir / "manifest.json"
    if selected and manifest_path.is_file():
        try:
            prior = json.loads(manifest_path.read_text())
            previous = {t["name"]: t for t in prior.get("targets", [])}
        except (OSError, json.JSONDecodeError, TypeError):
            previous = {}

    for target in targets:
        name = target.get("name")
        recipe = target.get("recipe")
        if not isinstance(name, str) or not isinstance(recipe, str):
            fail(f"{config_path}: every [[target]] needs name and recipe")
        if selected and name not in selected:
            prior = previous.get(name)
            if prior is not None and (output_dir / name).is_file():
                built.append(prior)
            continue

        missing = [tool for tool in target.get("requires", []) if shutil.which(tool) is None]
        if missing:
            reason = f"missing toolchain: {' '.join(missing)}"
            if target.get("optional"):
                skipped.append({"name": name, "reason": reason})
                print(f"skipped {name}: {reason}", file=sys.stderr)
                continue
            fail(f"{name}: {reason}")

        source = target.get("source")
        if isinstance(source, str) and not (ROOT / source).is_file():
            fail(f"{name}: missing source {source}")

        target_out = output_dir / name
        env = {
            **os.environ,
            "CORPUS_DIR": str(output_dir),
            "TARGET_OUT": str(target_out),
        }
        result = subprocess.run(recipe, shell=True, cwd=ROOT, env=env)
        if result.returncode != 0:
            fail(f"{name}: recipe failed with exit {result.returncode}")
        if not target_out.is_file():
            fail(f"{name}: recipe did not produce {target_out}")

        built.append(
            {
                "name": name,
                "path": rel(target_out),
                "language": target.get("language"),
                "format": target.get("format"),
                "source": source,
                "size": target_out.stat().st_size,
                "sha256": sha256(target_out),
            }
        )

    manifest = {
        "schema": 1,
        "generator": "scripts/build-corpus.py",
        "config": rel(config_path),
        "config_sha256": sha256(config_path),
        "output_dir": rel(output_dir),
        "search_hex": defaults.get("search_hex"),
        "targets": built,
        "skipped": skipped,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print("built benchmark corpus:")
    for target in built:
        print(f"{target['sha256']}  {target['path']}")
    print(f"manifest: {rel(manifest_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fail-closed preflight for the exact Terminal-Bench 2.1 and Harbor inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import tomllib

TERMINAL_BENCH_COMMIT = "5c8eadf1f393183288fa08b8f73ca9a469cc5e00"
TERMINAL_BENCH_TASKS_TREE = "2f0f5fdc68f0befd9b4745386eb8698264b00d8a"
HARBOR_COMMIT = "5342956db1433368dd0b9b54286129ae415beebc"
HARBOR_VERSION = "0.20.0"
TASK_COUNT = 89
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_GIT_OUTPUT = 64 * 1024


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise ValueError("git is unavailable on the standard executable path")
    result = subprocess.run(
        [executable, "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=15,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    if len(result.stdout) > _MAX_GIT_OUTPUT or len(result.stderr) > _MAX_GIT_OUTPUT:
        raise ValueError("git preflight output exceeded its bound")
    if result.returncode != 0:
        raise ValueError("git preflight command failed")
    return result.stdout.decode("utf-8", "strict").strip()


def _repo(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("upstream repository paths must be absolute")
    if path.is_symlink() or not path.is_dir():
        raise ValueError("upstream repository must be a non-symlink directory")
    root = path.resolve(strict=True)
    if Path(_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True) != root:
        raise ValueError("upstream path must be the exact Git toplevel")
    return root


def _regular(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required upstream file is absent or unsafe: {relative}")
    if not path.resolve(strict=True).is_relative_to(root):
        raise ValueError(f"required upstream file escapes its repository: {relative}")
    return path


def _load_toml(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("upstream TOML file exceeds the 2 MiB bound")
    with path.open("rb") as source:
        return tomllib.load(source)


def _validate_harbor(path: Path) -> dict[str, Any]:
    root = _repo(path)
    if _git(root, "rev-parse", "HEAD") != HARBOR_COMMIT:
        raise ValueError("Harbor HEAD does not equal the audited commit")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Harbor checkout is not clean")
    document = _load_toml(_regular(root, "pyproject.toml"))
    if document.get("project", {}).get("version") != HARBOR_VERSION:
        raise ValueError("Harbor package version does not equal the audited version")
    return {"commit": HARBOR_COMMIT, "version": HARBOR_VERSION}


def _validate_terminal_bench(path: Path) -> dict[str, Any]:
    root = _repo(path)
    if _git(root, "rev-parse", "HEAD") != TERMINAL_BENCH_COMMIT:
        raise ValueError("Terminal-Bench HEAD does not equal the audited commit")
    if _git(root, "rev-parse", "HEAD:tasks") != TERMINAL_BENCH_TASKS_TREE:
        raise ValueError("Terminal-Bench tasks tree does not equal the audited tree")
    if _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        "tasks",
    ):
        raise ValueError("Terminal-Bench tasks checkout is not clean")

    tasks_root = root / "tasks"
    manifest_path = _regular(root, "tasks/dataset.toml")
    manifest = _load_toml(manifest_path)
    rows = manifest.get("tasks")
    if not isinstance(rows, list) or len(rows) != TASK_COUNT:
        raise ValueError("dataset manifest must contain exactly 89 tasks")

    manifest_names: set[str] = set()
    manifest_digests: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("dataset task entries must be tables")
        name = row.get("name")
        digest = row.get("digest")
        if (
            not isinstance(name, str)
            or not name.startswith("terminal-bench/")
            or not isinstance(digest, str)
            or _DIGEST_RE.fullmatch(digest) is None
            or name in manifest_names
            or digest in manifest_digests
        ):
            raise ValueError("dataset task identity or digest is invalid")
        manifest_names.add(name)
        manifest_digests.add(digest)

    directories = sorted(
        child.name
        for child in tasks_root.iterdir()
        if child.is_dir() and not child.is_symlink()
    )
    if len(directories) != TASK_COUNT:
        raise ValueError("tasks tree must contain exactly 89 safe task directories")
    if manifest_names != {f"terminal-bench/{name}" for name in directories}:
        raise ValueError("dataset manifest names do not exactly match task directories")

    agent_timeouts: Counter[str] = Counter()
    resources: Counter[str] = Counter()
    internet_tasks = 0
    for name in directories:
        prefix = f"tasks/{name}"
        for relative in (
            "task.toml",
            "instruction.md",
            "environment/Dockerfile",
            "tests/test.sh",
            "solution/solve.sh",
        ):
            _regular(root, f"{prefix}/{relative}")
        task = _load_toml(root / prefix / "task.toml")
        if task.get("task", {}).get("name") != f"terminal-bench/{name}":
            raise ValueError("task.toml name does not match its directory")
        timeout = task.get("agent", {}).get("timeout_sec")
        environment = task.get("environment", {})
        if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 12_000:
            raise ValueError("agent timeout is outside the audited bound")
        if environment.get("allow_internet") is not True:
            raise ValueError("all audited TB2.1 tasks must declare allow_internet=true")
        internet_tasks += 1
        agent_timeouts[str(timeout)] += 1
        resource = (
            environment.get("cpus"),
            environment.get("memory_mb"),
            environment.get("storage_mb"),
            environment.get("gpus"),
        )
        if resource[0] not in {1, 2, 4} or resource[1] not in {2048, 4096, 8192}:
            raise ValueError("task CPU or memory is outside the audited set")
        if resource[2] != 10_240 or resource[3] != 0:
            raise ValueError(
                "task storage or GPU contract differs from the audited set"
            )
        resources[json.dumps(resource, separators=(",", ":"))] += 1

    return {
        "commit": TERMINAL_BENCH_COMMIT,
        "tasks_tree": TERMINAL_BENCH_TASKS_TREE,
        "task_count": TASK_COUNT,
        "allow_internet_true": internet_tasks,
        "agent_timeout_distribution": dict(sorted(agent_timeouts.items())),
        "resource_distribution": dict(sorted(resources.items())),
        "dataset_manifest_sha256": hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terminal-bench-root", required=True, type=Path)
    parser.add_argument("--harbor-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = {
            "schema_version": 1,
            "terminal_bench_2_1": _validate_terminal_bench(
                arguments.terminal_bench_root
            ),
            "harbor": _validate_harbor(arguments.harbor_root),
        }
    except (
        OSError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"upstream preflight failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

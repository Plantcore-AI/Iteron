#!/usr/bin/env python3
"""Collect and verify bounded native-client runtime evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from common import (  # noqa: E402
    ReleaseToolError,
    atomic_write_bytes,
    canonical_json,
    run_main,
)
from client_runtime_receipt_schema import (  # noqa: E402
    BUILDER_WORKFLOW,
    CLIENTS,
    MAX_U64,
    PLATFORMS,
    RELEASE_WORKFLOW,
    REPOSITORY,
    RUNTIME_ROOT,
    Platform,
    _commit,
    _exact,
    _expect,
    _object,
    _positive,
    _sha256,
    _string,
    expected_steps,
    select_builder_jobs,
    validate_builder,
    validate_receipt,
    validate_referenced_workflows,
)

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ATTESTATION_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_JOBS = 100
MAX_STEPS = 128
ATTESTATION_TIMEOUT_SECONDS = 60
REQUIRED_STEPS = (
    "Run the complete target test suite",
    "Build an auditable release binary",
    "Verify architecture, linkage, and executable smoke tests",
    "Complete one task with the native release client",
)
VERSION_STEP = "Run native version-independence proof"


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseToolError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReleaseToolError(f"JSON contains non-standard constant {value}")


def _read_bytes(path: Path, label: str, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseToolError(f"{label} is not a regular non-symlink file")
        if metadata.st_size > maximum:
            raise ReleaseToolError(f"{label} exceeds its byte bound")
        with path.open("rb") as handle:
            payload = handle.read(maximum + 1)
    except ReleaseToolError:
        raise
    except OSError as error:
        raise ReleaseToolError(f"{label} is unavailable") from error
    if len(payload) > maximum:
        raise ReleaseToolError(f"{label} exceeds its byte bound")
    return payload


def _decode_json(payload: bytes, label: str) -> object:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ReleaseToolError(f"{label} is not strict UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except ReleaseToolError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as error:
        raise ReleaseToolError(f"{label} is not one strict JSON document") from error


def _read_json(path: Path, label: str, maximum: int = MAX_INPUT_BYTES) -> object:
    return _decode_json(_read_bytes(path, label, maximum), label)


def _run_identity(
    document: object,
    repository_id: int,
    tested_commit: str,
    builder_commit: str,
) -> dict[str, object]:
    run = _object(document, "workflow run response")
    run_id = _positive(run.get("id"), "workflow run id")
    attempt = _positive(run.get("run_attempt"), "workflow run attempt")
    for key, expected in (
        ("event", "workflow_dispatch"),
        ("head_branch", "main"),
        ("head_sha", tested_commit),
        ("path", RELEASE_WORKFLOW),
    ):
        _expect(run.get(key), expected, f"workflow run {key}")
    repository = _object(run.get("repository"), "workflow run repository")
    _expect(repository.get("id"), repository_id, "workflow repository id")
    _expect(repository.get("full_name"), REPOSITORY, "workflow repository name")
    validate_referenced_workflows(run.get("referenced_workflows"), builder_commit)
    url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    _expect(run.get("html_url"), url, "workflow run URL")
    return {
        "id": run_id,
        "attempt": attempt,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": tested_commit,
        "workflow_path": RELEASE_WORKFLOW,
        "url": url,
    }


def _collect_steps(raw: object, platform: Platform) -> dict[str, str]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_STEPS:
        raise ReleaseToolError(f"{platform.target} job has an invalid step list")
    steps = [_object(step, f"{platform.target} job step") for step in raw]
    outcomes = expected_steps(platform)
    named = [
        (name, "success") for name in REQUIRED_STEPS
    ] + [(VERSION_STEP, outcomes["version_independence"])]
    for name, conclusion in named:
        matches = [step for step in steps if step.get("name") == name]
        if len(matches) != 1:
            raise ReleaseToolError(
                f"{platform.target} job must contain one step {name!r}"
            )
        _expect(matches[0].get("status"), "completed", f"{name} status")
        _expect(
            matches[0].get("conclusion"),
            conclusion,
            f"{name} conclusion",
        )
    return outcomes


def _platform_jobs(
    document: object, run_id: int, run_attempt: int, tested_commit: str
) -> list[dict[str, object]]:
    response = _object(document, "workflow jobs response")
    jobs = response.get("jobs")
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= MAX_JOBS:
        raise ReleaseToolError("workflow jobs response has an invalid jobs list")
    _expect(response.get("total_count"), len(jobs), "workflow jobs total_count")
    objects = [_object(job, "workflow job") for job in jobs]
    output: list[dict[str, object]] = []
    selected = select_builder_jobs(objects)
    for platform, job in zip(PLATFORMS, selected):
        job_id = _positive(job.get("id"), f"{platform.target} job id")
        runner_id = _positive(job.get("runner_id"), f"{platform.target} runner id")
        for key, expected in (
            ("run_id", run_id),
            ("run_attempt", run_attempt),
            ("head_sha", tested_commit),
            ("status", "completed"),
            ("conclusion", "success"),
            ("labels", [platform.runner]),
            ("runner_name", f"GitHub Actions {runner_id}"),
            ("runner_group_id", 0),
            ("runner_group_name", "GitHub Actions"),
        ):
            _expect(job.get(key), expected, f"{platform.target} job {key}")
        output.append(
            {
                "platform": platform.platform,
                "target": platform.target,
                "runner": platform.runner,
                "job": {
                    "id": job_id,
                    "runner_id": runner_id,
                    "runner_name": f"GitHub Actions {runner_id}",
                    "runner_group_id": 0,
                    "runner_group_name": "GitHub Actions",
                    "labels": [platform.runner],
                    "conclusion": "success",
                },
                "steps": _collect_steps(job.get("steps"), platform),
            }
        )
    ids = [row["job"]["id"] for row in output]  # type: ignore[index]
    if len(set(ids)) != len(ids):
        raise ReleaseToolError("selected workflow jobs contain duplicate ids")
    runner_ids = [row["job"]["runner_id"] for row in output]  # type: ignore[index]
    if len(set(runner_ids)) != len(runner_ids):
        raise ReleaseToolError("selected workflow jobs contain duplicate runner ids")
    return output


def _reject_output_alias(output: Path, inputs: tuple[Path, ...]) -> None:
    try:
        resolved_output = output.resolve(strict=False)
        for path in inputs:
            if resolved_output == path.resolve(strict=True):
                raise ReleaseToolError("receipt output aliases an evidence input")
            if (output.exists() or output.is_symlink()) and output.samefile(path):
                raise ReleaseToolError("receipt output aliases an evidence input")
    except ReleaseToolError:
        raise
    except OSError as error:
        raise ReleaseToolError("receipt output alias check failed") from error


def collect(arguments: argparse.Namespace) -> None:
    _reject_output_alias(arguments.output, (arguments.jobs, arguments.run))
    _expect(arguments.repository, REPOSITORY, "repository")
    repository_id = _positive(arguments.repository_id, "repository id")
    tested_commit = _commit(arguments.tested_commit, "tested commit")
    tested_tree = _commit(arguments.tested_tree, "tested tree")
    builder_commit = _commit(
        arguments.builder_workflow_commit, "builder workflow commit"
    )
    run = _run_identity(
        _read_json(arguments.run, "workflow run response"),
        repository_id,
        tested_commit,
        builder_commit,
    )
    platforms = _platform_jobs(
        _read_json(arguments.jobs, "workflow jobs response"),
        run["id"],
        run["attempt"],
        tested_commit,
    )
    receipt = {
        "schema_version": 1,
        "type": "client_runtime_receipt",
        "repository": {"name": REPOSITORY, "id": repository_id},
        "tested_commit": tested_commit,
        "tested_tree": tested_tree,
        "builder_workflow": {
            "path": BUILDER_WORKFLOW,
            "commit": builder_commit,
        },
        "run": run,
        "platforms": platforms,
        "version_independence": [
            {
                "operating_system": PLATFORMS[index].version_os,
                "platform": PLATFORMS[index].platform,
                "job_id": platforms[index]["job"]["id"],
                "clients": list(CLIENTS),
                "conclusion": "success",
            }
            for index in (3, 4)
        ],
    }
    validate_receipt(receipt, tested_commit, builder_commit)
    payload = canonical_json(receipt).encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise ReleaseToolError("canonical runtime receipt exceeds its byte bound")
    atomic_write_bytes(arguments.output, payload)
    print(arguments.output)


def _rooted_file(root: Path, relative: str, label: str) -> Path:
    _string(relative, f"{label} path")
    pure = PurePosixPath(relative)
    parts = relative.split("/")
    if (
        pure.is_absolute()
        or "\\" in relative
        or ":" in relative
        or any(part in ("", ".", "..") for part in parts)
        or tuple(parts) != pure.parts
        or tuple(parts[: len(RUNTIME_ROOT)]) != RUNTIME_ROOT
        or len(parts) <= len(RUNTIME_ROOT)
    ):
        raise ReleaseToolError(f"{label} path is not canonical runtime evidence")
    try:
        cursor = root.resolve(strict=True)
        if not stat.S_ISDIR(cursor.stat().st_mode):
            raise ReleaseToolError("repository root is not a directory")
        for index, part in enumerate(parts):
            cursor /= part
            metadata = cursor.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ReleaseToolError(f"{label} path traverses a symbolic link")
            if index + 1 == len(parts):
                if not stat.S_ISREG(metadata.st_mode):
                    raise ReleaseToolError(f"{label} is not a regular file")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ReleaseToolError(f"{label} path traverses a non-directory")
    except ReleaseToolError:
        raise
    except OSError as error:
        raise ReleaseToolError(f"{label} path is unavailable") from error
    return cursor


def _verify_attestation(
    root: Path,
    receipt: Path,
    bundle: Path,
    trusted_commit: str,
    trusted_builder_commit: str,
) -> None:
    command = [
        "gh",
        "attestation",
        "verify",
        str(receipt),
        "--repo",
        REPOSITORY,
        "--bundle",
        str(bundle),
        "--signer-workflow",
        f"{REPOSITORY}/{BUILDER_WORKFLOW}",
        "--signer-digest",
        trusted_builder_commit,
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        trusted_commit,
        "--deny-self-hosted-runners",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=ATTESTATION_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ReleaseToolError("GitHub attestation verification timed out") from error
    except OSError as error:
        raise ReleaseToolError(
            "GitHub attestation verification could not run"
        ) from error
    if type(completed.returncode) is not int or completed.returncode != 0:
        raise ReleaseToolError("GitHub attestation verification failed")


def verify_evidence(arguments: argparse.Namespace) -> None:
    trusted_commit = _commit(arguments.trusted_commit, "trusted commit")
    root = arguments.root
    contract = _object(
        _read_json(
            root / "governance/client-conformance.json",
            "client conformance contract",
        ),
        "client conformance contract",
    )
    for field in ("runtime_builder", "runtime_receipt"):
        if field not in contract:
            raise ReleaseToolError(f"client conformance contract omits {field}")
    builder = None
    if contract["runtime_builder"] is not None:
        builder = validate_builder(contract["runtime_builder"], "runtime builder")
    if contract["runtime_receipt"] is None:
        return
    if builder is None:
        raise ReleaseToolError("runtime receipt requires runtime_builder")
    if builder["commit"] == trusted_commit:
        raise ReleaseToolError("runtime builder commit must predate trusted commit")
    supplied_builder = getattr(arguments, "trusted_builder_commit", None)
    if supplied_builder is None:
        raise ReleaseToolError("runtime receipt requires --trusted-builder-commit")
    trusted_builder_commit = _commit(
        supplied_builder, "trusted builder commit"
    )
    _expect(
        builder["commit"],
        trusted_builder_commit,
        "runtime builder commit",
    )
    reference = _exact(
        contract["runtime_receipt"],
        frozenset(("path", "sha256", "attestation_path", "attestation_sha256")),
        "runtime receipt reference",
    )
    receipt_relative = _string(reference["path"], "runtime receipt path")
    bundle_relative = _string(reference["attestation_path"], "attestation path")
    receipt_path = _rooted_file(root, receipt_relative, "runtime receipt")
    bundle_path = _rooted_file(root, bundle_relative, "runtime receipt attestation")
    if receipt_path == bundle_path:
        raise ReleaseToolError("receipt and attestation paths must differ")
    receipt_payload = _read_bytes(receipt_path, "runtime receipt", MAX_RECEIPT_BYTES)
    bundle_payload = _read_bytes(
        bundle_path, "attestation", MAX_ATTESTATION_BYTES
    )
    if hashlib.sha256(receipt_payload).hexdigest() != _sha256(
        reference["sha256"], "runtime receipt sha256"
    ):
        raise ReleaseToolError("runtime receipt SHA-256 does not match")
    if hashlib.sha256(bundle_payload).hexdigest() != _sha256(
        reference["attestation_sha256"], "attestation sha256"
    ):
        raise ReleaseToolError("attestation SHA-256 does not match")
    receipt = validate_receipt(
        _decode_json(receipt_payload, "runtime receipt"),
        trusted_commit,
        trusted_builder_commit,
    )
    _expect(receipt["builder_workflow"], builder, "receipt builder_workflow")
    if canonical_json(receipt).encode("utf-8") != receipt_payload:
        raise ReleaseToolError("runtime receipt is not canonical JSON")
    run = receipt["run"]
    stem = f"runtime-receipt-{run['id']}-attempt-{run['attempt']}"
    prefix = "/".join(RUNTIME_ROOT)
    _expect(receipt_relative, f"{prefix}/{stem}.json", "runtime receipt path")
    _expect(bundle_relative, f"{prefix}/{stem}.sigstore.json", "attestation path")
    if arguments.require_attestation:
        _verify_attestation(
            root.resolve(strict=True),
            receipt_path,
            bundle_path,
            trusted_commit,
            trusted_builder_commit,
        )


def _positive_argument(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if not 1 <= result <= MAX_U64 or str(result) != value:
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    for name, value_type in (
        ("jobs", Path),
        ("run", Path),
        ("repository", str),
        ("repository-id", _positive_argument),
        ("tested-commit", str),
        ("tested-tree", str),
        ("builder-workflow-commit", str),
        ("output", Path),
    ):
        collect_parser.add_argument(f"--{name}", required=True, type=value_type)
    verify_parser = commands.add_parser("verify-evidence")
    verify_parser.add_argument("--root", required=True, type=Path)
    verify_parser.add_argument("--trusted-commit", required=True)
    verify_parser.add_argument("--trusted-builder-commit")
    verify_parser.add_argument("--require-attestation", action="store_true")
    return result


def main() -> None:
    arguments = parser().parse_args()
    (collect if arguments.command == "collect" else verify_evidence)(arguments)


if __name__ == "__main__":
    run_main(main)

"""Exact schema authority for native-client runtime receipts."""

from __future__ import annotations

from typing import NamedTuple

from common import COMMIT_RE, SHA256_RE, ReleaseToolError

REPOSITORY = "Plantcore-AI/Iteron"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
BUILDER_WORKFLOW = ".github/workflows/runtime-receipt.yml"
RUNTIME_ROOT = ("governance", "client-conformance", "runtime")
CLIENTS = ("headless", "one-shot", "tui")
MAX_U64 = (1 << 64) - 1
MAX_REFERENCED_WORKFLOWS = 16
MAX_STRING_BYTES = 1024
BUILDER_JOB_NAME = "native client runtime"
RELEASE_WORKFLOW_NAME = "release"
RECEIPT_FIELDS = frozenset(
    "schema_version type repository tested_commit tested_tree "
    "builder_workflow run platforms version_independence".split()
)
RUN_FIELDS = frozenset(
    "id attempt event head_branch head_sha workflow_path url".split()
)
PLATFORM_FIELDS = frozenset(("platform", "target", "runner", "job", "steps"))
JOB_FIELDS = frozenset(
    "id runner_id runner_name runner_group_id runner_group_name "
    "labels conclusion".split()
)
STEP_FIELDS = frozenset(
    "target_tests binary_build binary_identity native_client_smoke "
    "version_independence".split()
)


class Platform(NamedTuple):
    platform: str
    target: str
    runner: str
    version_os: str | None


PLATFORMS = (
    Platform("macos-arm64", "aarch64-apple-darwin", "macos-15", None),
    Platform("macos-x86_64", "x86_64-apple-darwin", "macos-15-intel", None),
    Platform("linux-arm64", "aarch64-unknown-linux-musl", "ubuntu-24.04-arm", None),
    Platform("linux-x86_64", "x86_64-unknown-linux-musl", "ubuntu-24.04", "unix"),
    Platform(
        "windows-x86_64",
        "x86_64-pc-windows-msvc",
        "windows-2022",
        "windows-msvc",
    ),
)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseToolError(f"{label} must be an object")
    return value


def _exact(
    value: object, fields: frozenset[str], label: str
) -> dict[str, object]:
    result = _object(value, label)
    if frozenset(result) != fields:
        raise ReleaseToolError(f"{label} does not have its exact field set")
    return result


def _expect(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ReleaseToolError(f"{label} must equal {expected!r}")


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseToolError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ReleaseToolError(f"{label} is not valid UTF-8 text") from error
    if len(encoded) > MAX_STRING_BYTES or any(
        ord(character) < 0x20 for character in value
    ):
        raise ReleaseToolError(f"{label} is invalid or exceeds its string bound")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_U64:
        raise ReleaseToolError(f"{label} must be a positive unsigned 64-bit integer")
    return value


def _commit(value: object, label: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        raise ReleaseToolError(f"{label} must be a full lowercase SHA-1")
    return value


def _sha256(value: object, label: str) -> str:
    result = _string(value, label)
    if SHA256_RE.fullmatch(result) is None:
        raise ReleaseToolError(f"{label} has an invalid digest")
    return result


def expected_steps(platform: Platform) -> dict[str, str]:
    return {
        "target_tests": "success",
        "binary_build": "success",
        "binary_identity": "success",
        "native_client_smoke": "success",
        "version_independence": "success" if platform.version_os else "skipped",
    }


def validate_referenced_workflows(value: object, builder_commit: str) -> None:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= MAX_REFERENCED_WORKFLOWS
    ):
        raise ReleaseToolError("workflow run has an invalid referenced_workflows list")
    builder_prefix = f"{REPOSITORY}/{BUILDER_WORKFLOW}@"
    builders: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        entry = _object(raw, f"referenced workflow {index}")
        fields = frozenset(entry)
        if fields not in (
            frozenset(("path", "sha")),
            frozenset(("path", "sha", "ref")),
        ):
            raise ReleaseToolError(
                f"referenced workflow {index} does not have an exact API field set"
            )
        path = _string(entry["path"], f"referenced workflow {index} path")
        _commit(entry["sha"], f"referenced workflow {index} sha")
        if "ref" in entry:
            _string(entry["ref"], f"referenced workflow {index} ref")
        if path.startswith(builder_prefix):
            builders.append(entry)
    if len(builders) != 1:
        raise ReleaseToolError(
            "workflow run must reference exactly one runtime builder"
        )
    if frozenset(builders[0]) != frozenset(("path", "sha")):
        raise ReleaseToolError("pinned runtime builder reference must omit ref")
    expected_path = f"{builder_prefix}{builder_commit}"
    _expect(builders[0]["path"], expected_path, "runtime builder reference path")
    _expect(builders[0]["sha"], builder_commit, "runtime builder reference sha")


def _builder_job_prefix(name: str, target: str) -> str | None:
    suffix = f"{BUILDER_JOB_NAME} / {target}"
    if name == suffix:
        return ""
    marker = f" / {suffix}"
    if not name.endswith(marker):
        return None
    prefix = name[: -len(marker)]
    segments = prefix.split(" / ")
    if not prefix or any(
        not segment or segment != segment.strip() for segment in segments
    ):
        return None
    return prefix


def select_builder_jobs(
    jobs: list[dict[str, object]],
) -> list[dict[str, object]]:
    names = [(_string(job.get("name"), "workflow job name"), job) for job in jobs]
    selected: list[dict[str, object]] = []
    prefixes: list[str] = []
    for platform in PLATFORMS:
        matches: list[tuple[str, dict[str, object]]] = []
        for name, job in names:
            prefix = _builder_job_prefix(name, platform.target)
            if prefix is not None:
                matches.append((prefix, job))
        if len(matches) != 1:
            raise ReleaseToolError(
                f"jobs response must contain one builder job for {platform.target!r}"
            )
        prefix, job = matches[0]
        _expect(job.get("workflow_name"), RELEASE_WORKFLOW_NAME, "job workflow_name")
        prefixes.append(prefix)
        selected.append(job)
    if len(set(prefixes)) != 1:
        raise ReleaseToolError("runtime builder jobs do not share one exact prefix")
    return selected


def validate_builder(value: object, label: str) -> dict[str, object]:
    builder = _exact(value, frozenset(("path", "commit")), label)
    _expect(builder["path"], BUILDER_WORKFLOW, f"{label} path")
    _commit(builder["commit"], f"{label} commit")
    return builder


def validate_receipt(
    document: object,
    trusted_commit: str | None = None,
    trusted_builder_commit: str | None = None,
) -> dict[str, object]:
    receipt = _exact(document, RECEIPT_FIELDS, "runtime receipt")
    _expect(receipt["schema_version"], 1, "runtime receipt schema_version")
    _expect(receipt["type"], "client_runtime_receipt", "runtime receipt type")
    repository = _exact(
        receipt["repository"], frozenset(("name", "id")), "receipt repository"
    )
    _expect(repository["name"], REPOSITORY, "receipt repository name")
    _positive(repository["id"], "receipt repository id")
    tested_commit = _commit(receipt["tested_commit"], "receipt tested_commit")
    _commit(receipt["tested_tree"], "receipt tested_tree")
    builder = validate_builder(
        receipt["builder_workflow"],
        "receipt builder_workflow",
    )
    if builder["commit"] == tested_commit:
        raise ReleaseToolError(
            "receipt builder_workflow commit must predate tested_commit"
        )
    if trusted_commit is not None:
        _expect(tested_commit, trusted_commit, "receipt tested_commit")
    if trusted_builder_commit is not None:
        _expect(
            builder["commit"],
            trusted_builder_commit,
            "receipt builder_workflow commit",
        )

    run = _exact(receipt["run"], RUN_FIELDS, "receipt run")
    run_id = _positive(run["id"], "receipt run id")
    _positive(run["attempt"], "receipt run attempt")
    for key, expected in (
        ("event", "workflow_dispatch"),
        ("head_branch", "main"),
        ("head_sha", tested_commit),
        ("workflow_path", RELEASE_WORKFLOW),
        ("url", f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"),
    ):
        _expect(run[key], expected, f"receipt run {key}")

    platforms = receipt["platforms"]
    if not isinstance(platforms, list) or len(platforms) != len(PLATFORMS):
        raise ReleaseToolError("receipt has the wrong platform count")
    job_ids: list[int] = []
    runner_ids: list[int] = []
    for value, expected in zip(platforms, PLATFORMS):
        platform = _exact(value, PLATFORM_FIELDS, "receipt platform")
        for key in ("platform", "target", "runner"):
            _expect(platform[key], getattr(expected, key), f"receipt {key}")
        job = _exact(platform["job"], JOB_FIELDS, f"{expected.target} receipt job")
        job_id = _positive(job["id"], f"{expected.target} receipt job id")
        runner_id = _positive(job["runner_id"], f"{expected.target} runner id")
        for key, expected_value in (
            ("runner_name", f"GitHub Actions {runner_id}"),
            ("runner_group_id", 0),
            ("runner_group_name", "GitHub Actions"),
            ("labels", [expected.runner]),
            ("conclusion", "success"),
        ):
            _expect(job[key], expected_value, f"{expected.target} receipt {key}")
        steps = _exact(
            platform["steps"], STEP_FIELDS, f"{expected.target} receipt steps"
        )
        _expect(steps, expected_steps(expected), f"{expected.target} receipt steps")
        job_ids.append(job_id)
        runner_ids.append(runner_id)
    if len(set(job_ids)) != len(job_ids):
        raise ReleaseToolError("receipt platform jobs contain duplicate ids")
    if len(set(runner_ids)) != len(runner_ids):
        raise ReleaseToolError("receipt platform jobs contain duplicate runner ids")

    rows = receipt["version_independence"]
    if not isinstance(rows, list) or len(rows) != 2:
        raise ReleaseToolError("receipt must contain two version-independence rows")
    for value, platform, job_id in zip(
        rows, (PLATFORMS[3], PLATFORMS[4]), (job_ids[3], job_ids[4])
    ):
        row = _exact(
            value,
            frozenset(
                ("operating_system", "platform", "job_id", "clients", "conclusion")
            ),
            "version-independence row",
        )
        _expect(row["operating_system"], platform.version_os, "version OS")
        _expect(row["platform"], platform.platform, "version platform")
        _expect(row["job_id"], job_id, "version job id")
        _expect(row["clients"], list(CLIENTS), "version clients")
        _expect(row["conclusion"], "success", "version conclusion")
    return receipt

#!/usr/bin/env python3
"""Reproduce the checked-in SWE-bench Pro OS schema-v2 corpus slice.

The source JSONL is pinned by both repository revision and content digest. The
gold solution patch is used only to record its digest; it is never written to
the evaluation corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request


SOURCE_REVISION = "ca10a60a5fcae51e6948ffe1485d4153d421e6c5"
SOURCE_SHA256 = "b5b2462bfbf5aeb2cb7ba7d215778a1768b85f9d7ad7f748546c7f80a0ad1510"
MAX_SOURCE_BYTES = 256 * 1024 * 1024
SOURCE_URL = (
    "https://raw.githubusercontent.com/scaleapi/SWE-bench_Pro-os/"
    f"{SOURCE_REVISION}/helper_code/sweap_eval_full_v2.jsonl"
)
CORPUS_VERSION = f"swe-bench-pro-os-{SOURCE_REVISION}-slice-v2"
OUTPUT = pathlib.Path(__file__).with_name(
    f"swe-bench-pro-os-{SOURCE_REVISION[:7]}-slice-v2.json"
)

OPENLIBRARY = (
    "instance_internetarchive__openlibrary-"
    "8a5a63af6e0be406aa6c8c9b6d5f28b2f1b6af5a-"
    "v0f5aece3601a5b4419f7ccec1dbda2071be28ee4"
)
TELEPORT = (
    "instance_gravitational__teleport-"
    "0ac7334939981cf85b9591ac295c3816954e287e"
)
ANSIBLE = (
    "instance_ansible__ansible-"
    "be59caa59bf47ca78a4760eb7ff38568372a8260-"
    "v1055803c3a812189a1133297f7f5468579283f86"
)
TASKS = {
    OPENLIBRARY: {
        "partition": "train",
        "language": "python",
        "verify_command": (
            "python3 -m pytest -q "
            "scripts/monitoring/tests/test_utils_py.py::test_bash_run "
            "scripts/monitoring/tests/test_utils_py.py::test_limit_server --tb=short"
        ),
        "test_command": (
            "python3 -c 'import json,os,pytest,sys; "
            'tests=json.loads(os.environ["CORE_EVAL_TEST_IDS_JSON"]); '
            'sys.exit(pytest.main(["-q","--tb=short",*tests]))\''
        ),
    },
    ANSIBLE: {
        "partition": "held_out",
        "language": "python",
        "verify_command": (
            "python3 -m pytest -q "
            "test/units/modules/test_iptables.py::TestIptables::test_match_set "
            "--tb=short"
        ),
        "test_command": (
            "python3 -c 'import json,os,pytest,sys; "
            'tests=json.loads(os.environ["CORE_EVAL_TEST_IDS_JSON"]); '
            'sys.exit(pytest.main(["-q","--tb=short",*tests]))\''
        ),
    },
    TELEPORT: {
        "partition": "held_out",
        "language": "go",
        "verify_command": "go test -timeout=5m -v -run '^(TestHA)$' ./lib/srv/db",
        "test_command": (
            "python3 -c 'import json,os,re,subprocess,sys; "
            'tests=json.loads(os.environ["CORE_EVAL_TEST_IDS_JSON"]); '
            'pattern="^("+"|".join(re.escape(test) for test in tests)+")$"; '
            'sys.exit(subprocess.run(["go","test","-timeout=5m","-v",'
            '"-run",pattern,"./lib/srv/db"]).returncode)\''
        ),
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail unless the checked-in corpus equals a fresh import",
    )
    mode.add_argument(
        "--extract-gold",
        metavar="TASK_ID",
        help="extract one pinned upstream solution patch outside the repository",
    )
    parser.add_argument(
        "--gold-output",
        type=pathlib.Path,
        help="fresh destination required with --extract-gold",
    )
    return parser.parse_args()


def download() -> bytes:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "Plantcore-core-eval-corpus-importer/1"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise RuntimeError(
            f"pinned source exceeds the {MAX_SOURCE_BYTES}-byte import bound"
        )
    actual = hashlib.sha256(source).hexdigest()
    if actual != SOURCE_SHA256:
        raise RuntimeError(
            f"pinned source digest mismatch: expected {SOURCE_SHA256}, got {actual}"
        )
    return source


def decode_test_set(value: object) -> list[str]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError("benchmark test set is not a string array")
    return value


def dockerhub_image(instance_id: str, repo: str) -> str:
    """Mirror pinned helper_code/image_uri.py from SWE-bench Pro OS."""
    repo_base, repo_name = repo.lower().split("/")
    suffix = instance_id.removeprefix("instance_")
    if (
        instance_id
        == "instance_element-hq__element-web-ec0f940ef0e8e3b61078f145f34dc40d1938e6c5-vnan"
    ):
        repo_name = "element-web"
    elif "element-hq" in repo.lower() and "element-web" in repo.lower():
        repo_name = "element"
        if suffix.endswith("-vnan"):
            suffix = suffix[:-5]
    elif suffix.endswith("-vnan"):
        suffix = suffix[:-5]
    tag = f"{repo_base}.{repo_name}-{suffix}"[:128]
    return f"jefzda/sweap-images:{tag}"


def import_task(row: dict[str, object]) -> dict[str, object]:
    instance_id = str(row["instance_id"])
    selection = TASKS[instance_id]
    repo = str(row["repo"])
    fail_to_pass = decode_test_set(row["FAIL_TO_PASS"])
    pass_to_pass = decode_test_set(row["PASS_TO_PASS"])
    test_patch = str(row["test_patch"])
    image = dockerhub_image(instance_id, repo)
    return {
        "id": instance_id,
        "repo_url": f"https://github.com/{repo}.git",
        "commit": str(row["base_commit"]),
        "prompt": str(row["problem_statement"]),
        "verify_command": selection["verify_command"],
        "ground_truth_command": selection["verify_command"],
        "dockerhub_tag": image,
        "fail_to_pass": fail_to_pass,
        "pass_to_pass": pass_to_pass,
        "test_cmd": {selection["language"]: selection["test_command"]},
        "partition": selection["partition"],
        "provenance": {
            "source": SOURCE_URL,
            "task_id": instance_id,
            "license": "MIT",
        },
        "benchmark": {
            "name": "SWE-bench Pro OS",
            "instance_id": instance_id,
            "dataset_revision": SOURCE_REVISION,
            "environment_setup_commit": SOURCE_REVISION,
            "environment_image": image,
            "test_patch_sha256": (
                "sha256:" + hashlib.sha256(test_patch.encode()).hexdigest()
            ),
            "test_patch": test_patch,
        },
    }


def select_rows(source: bytes) -> dict[str, dict[str, object]]:
    selected: dict[str, dict[str, object]] = {}
    for line in source.splitlines():
        row = json.loads(line)
        instance_id = row.get("instance_id")
        if instance_id in TASKS:
            if instance_id in selected:
                raise RuntimeError(f"duplicate pinned task {instance_id}")
            selected[str(instance_id)] = row
    missing = TASKS.keys() - selected.keys()
    if missing:
        raise RuntimeError(f"pinned source is missing tasks: {sorted(missing)}")
    return selected


def build_manifest(source: bytes) -> dict[str, object]:
    selected = select_rows(source)
    tasks = [import_task(selected[instance_id]) for instance_id in TASKS]
    canonical = json.dumps(
        tasks, ensure_ascii=False, separators=(",", ":")
    ).encode()
    return {
        "schema_version": 2,
        "corpus_version": CORPUS_VERSION,
        "dataset_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "tasks": tasks,
    }


def encode(manifest: dict[str, object]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()


def main() -> int:
    args = parse_args()
    source = download()
    if args.extract_gold is not None:
        if args.gold_output is None:
            raise RuntimeError("--gold-output is required with --extract-gold")
        selected = select_rows(source)
        if args.extract_gold not in selected:
            raise RuntimeError(
                f"--extract-gold must select one of {sorted(selected)}"
            )
        destination = args.gold_output.resolve()
        repository = pathlib.Path(__file__).resolve().parents[3]
        if destination == repository or repository in destination.parents:
            raise RuntimeError("the upstream solution patch must stay outside the repository")
        patch = str(selected[args.extract_gold]["patch"]).encode()
        with destination.open("xb") as output:
            output.write(patch)
        print(
            f"{destination} sha256:{hashlib.sha256(patch).hexdigest()}",
            file=sys.stderr,
        )
        return 0
    if args.gold_output is not None:
        raise RuntimeError("--gold-output is only valid with --extract-gold")

    generated = encode(build_manifest(source))
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != generated:
            print(f"{OUTPUT} is stale; rerun {pathlib.Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"{OUTPUT} matches {SOURCE_REVISION}")
        return 0
    OUTPUT.write_bytes(generated)
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Select the immutable published schema base for a release candidate."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from common import ReleaseToolError, run_main

MAX_RELEASE_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RELEASES = 1_000
SEMVER = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def parse_version(tag: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(tag)
    if match is None:
        raise ReleaseToolError(f"release tag is not strict SemVer: {tag!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def load_releases(path: Path) -> list[dict]:
    encoded = path.read_bytes()
    if len(encoded) > MAX_RELEASE_RESPONSE_BYTES:
        raise ReleaseToolError("GitHub release response exceeds the 2 MiB limit")
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError("GitHub release response is not valid JSON") from error
    if not isinstance(payload, list):
        raise ReleaseToolError("GitHub release response must be an array of pages")
    if payload and all(isinstance(page, list) for page in payload):
        releases = [release for page in payload for release in page]
    elif all(isinstance(release, dict) for release in payload):
        releases = payload
    else:
        raise ReleaseToolError("GitHub release response has a mixed page shape")
    if len(releases) > MAX_RELEASES:
        raise ReleaseToolError("GitHub release response exceeds 1000 releases")
    if not all(isinstance(release, dict) for release in releases):
        raise ReleaseToolError("GitHub release response contains a non-object release")
    return releases


def published_stable_releases(
    releases: list[dict],
) -> dict[tuple[int, int, int], dict]:
    admitted: dict[tuple[int, int, int], dict] = {}
    for release in releases:
        draft = release.get("draft")
        prerelease = release.get("prerelease")
        if not isinstance(draft, bool) or not isinstance(prerelease, bool):
            raise ReleaseToolError("GitHub release lacks typed draft/prerelease state")
        if draft or prerelease:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            raise ReleaseToolError("published release lacks a string tag_name")
        match = SEMVER.fullmatch(tag)
        if match is None:
            continue
        version = tuple(int(part) for part in match.groups())
        if version in admitted:
            raise ReleaseToolError(f"published SemVer release is duplicated: {tag}")
        admitted[version] = release
    return admitted


def immutable_highest(admitted: dict[tuple[int, int, int], dict]) -> str | None:
    if not admitted:
        return None
    previous = admitted[max(admitted)]
    previous_tag = previous["tag_name"]
    if previous.get("immutable") is not True:
        raise ReleaseToolError(
            f"highest previous release {previous_tag} is not immutable"
        )
    return previous_tag


def select_previous(releases: list[dict], candidate_tag: str) -> str | None:
    candidate = parse_version(candidate_tag)
    admitted = published_stable_releases(releases)
    invalid = [version for version in admitted if version >= candidate]
    if invalid:
        tag = admitted[max(invalid)]["tag_name"]
        raise ReleaseToolError(
            f"published release {tag} is not older than candidate {candidate_tag}"
        )
    return immutable_highest(admitted)


def select_latest(releases: list[dict]) -> str | None:
    return immutable_highest(published_stable_releases(releases))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--candidate")
    mode.add_argument("--latest", action="store_true")
    arguments = parser.parse_args()
    releases = load_releases(arguments.input)
    previous = (
        select_latest(releases)
        if arguments.latest
        else select_previous(releases, arguments.candidate)
    )
    print(previous if previous is not None else "BOOTSTRAP")


if __name__ == "__main__":
    run_main(main)

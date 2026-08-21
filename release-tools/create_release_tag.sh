#!/usr/bin/env bash
# Create and push an annotated release tag only after all preconditions pass.
#
# Usage: release-tools/create_release_tag.sh [VERSION]
#
# If VERSION is omitted, it is read from the workspace manifest (Cargo.toml).
# The tag is always created as "vMAJOR.MINOR.PATCH".

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail() {
  printf 'release-tool: error: %s\n' "$1" >&2
  exit 1
}

workspace_version() {
  awk '
    /^\[workspace\.package\]$/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && /^version[[:space:]]*=/ {
      sub(/^[^"]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' Cargo.toml
}

version_input=${1:-}
if [[ -n "$version_input" ]]; then
  version=${version_input#v}
else
  version=$(workspace_version)
  [[ -n "$version" ]] || fail "could not read workspace version from Cargo.toml"
fi

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  fail "invalid semantic version: $version_input"
fi

tag="v$version"

# Require a working gh CLI with a usable token.
if ! command -v gh >/dev/null 2>&1; then
  fail "gh CLI is required (https://cli.github.com)"
fi
if ! gh auth status >/dev/null 2>&1; then
  fail "gh CLI is not authenticated; run 'gh auth login' or set GH_TOKEN"
fi

# Only release from a clean main branch.
branch=$(git branch --show-current)
if [[ "$branch" != main ]]; then
  fail "releases must be created from the 'main' branch (currently on '$branch')"
fi

if [[ -n "$(git status --porcelain)" ]]; then
  fail "working tree is not clean (uncommitted, staged, or untracked changes present)"
fi

commit=$(git rev-parse HEAD)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "could not determine current commit"

# Verify the workspace manifest still agrees with the requested version.
manifest_version=$(workspace_version)
[[ "$manifest_version" == "$version" ]] ||
  fail "requested version $version does not match Cargo.toml version $manifest_version"

# Require that the local main matches origin/main. A tag pushed from a stale
# local main will fail in release.yml anyway and burns a version number.
remote_url=$(git ls-remote --get-url origin 2>/dev/null) ||
  fail "could not determine remote origin"

git fetch --quiet origin main || fail "could not fetch origin/main"
main_commit=$(git rev-parse 'origin/main^{commit}')
if [[ "$commit" != "$main_commit" ]]; then
  fail "local HEAD ($commit) does not match origin/main ($main_commit); pull the latest main first"
fi

# Accept either https://github.com/OWNER/REPO(.git) or git@github.com:OWNER/REPO.git
if [[ "$remote_url" =~ github\.com[/:]([^/]+)/([^/]+)(\.git)?$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
  repo="${repo%.git}"
else
  fail "origin does not point to a github.com repository: $remote_url"
fi

# Bound API surface: at most one page of workflow runs (20 items, ~30s total)
# is sufficient for a commit that has just been dispatched.
successful_dispatch=$(
  gh api "repos/$owner/$repo/actions/workflows/release.yml/runs?per_page=20" \
    --jq ".workflow_runs[] | select(
      .head_sha == \"$commit\"
      and .event == \"workflow_dispatch\"
      and .conclusion == \"success\"
      and .head_branch == \"main\"
    ) | .id" \
    2>/dev/null | head -n 1
) || true

if [[ -z "$successful_dispatch" ]]; then
  fail "commit $commit has no successful workflow_dispatch run of release.yml on main; dispatch release.yml from this commit first"
fi

# Require successful protected CI evidence on main for this exact commit.
ci_evidence_run=$(
  gh api "repos/$owner/$repo/actions/workflows/ci.yml/runs?branch=main&event=push&status=success&head_sha=$commit&per_page=10" \
    --jq ".workflow_runs[] | select(
      .head_sha == \"$commit\"
      and .head_branch == \"main\"
      and .event == \"push\"
      and .status == \"completed\"
      and .conclusion == \"success\"
    ) | .id" \
    2>/dev/null | head -n 1
) || true

if [[ -z "$ci_evidence_run" ]]; then
  fail "commit $commit has no successful CI push run on main; push the commit to main and wait for CI first"
fi

ci_required_jobs=$(
  gh api "repos/$owner/$repo/actions/runs/$ci_evidence_run/jobs?filter=latest&per_page=100" \
    --jq '[.jobs[] | select(.name == "ci / required" and .status == "completed" and .conclusion == "success")] | length' \
    2>/dev/null
) || true

if [[ "$ci_required_jobs" != "1" ]]; then
  fail "CI evidence run $ci_evidence_run must contain exactly one successful \"ci / required\" job (found: ${ci_required_jobs:-none})"
fi

# Early local guard: the candidate version must be greater than the latest
# published immutable release. This does NOT prove schema compatibility; the
# immutable-schema gate in release.yml is the authoritative check. It only
# prevents an obvious stale-version tag from burning a version number.
#
# Bound the API surface: walk at most 10 pages of 100 releases. The sentinel
# exits early when a page returns fewer than 100 items.
latest_immutable_version=""
page=1
while [[ $page -le 10 ]]; do
  page_info=$(
    gh api "repos/$owner/$repo/releases?per_page=100&page=$page" \
      --jq '(([.[] | select(.draft == false and .prerelease == false and .immutable == true and (.tag_name | type) == "string") | .tag_name | capture("^v(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)$")] | map([(.major | tonumber), (.minor | tonumber), (.patch | tonumber)]) | sort | last | if . then "v\(.[0]).\(.[1]).\(.[2])" else "_" end) + "\t" + (length | tostring))' \
      2>/dev/null
  ) || fail "could not list releases from GitHub API (page $page)"

  IFS=$'\t' read -r page_latest count <<< "$page_info"
  [[ "$page_latest" == "_" ]] && page_latest=""

  if [[ -n "$page_latest" ]]; then
    latest_immutable_version="$page_latest"
  fi

  if [[ -z "$count" || "$count" -lt 100 ]]; then
    break
  fi
  page=$((page + 1))
done

if [[ -n "$latest_immutable_version" ]]; then
  semver_gt() {
    local a=$1 b=$2
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 <<< "$a"
    IFS=. read -r b1 b2 b3 <<< "$b"
    (( a1 > b1 || (a1 == b1 && a2 > b2) || (a1 == b1 && a2 == b2 && a3 > b3) ))
  }
  if ! semver_gt "$version" "${latest_immutable_version#v}"; then
    fail "version $version is not newer than the latest immutable release $latest_immutable_version"
  fi
fi

# Refuse to overwrite an existing tag locally or remotely.
if git rev-parse -q --verify "$tag" >/dev/null; then
  fail "tag $tag already exists locally"
fi
if git ls-remote --tags origin "refs/tags/$tag" | grep -q "refs/tags/$tag"; then
  fail "tag $tag already exists on origin"
fi

printf 'Preparing annotated tag %s for commit %s\n' "$tag" "$commit"
printf 'Verified successful main dispatch: run id %s\n' "$successful_dispatch"
printf '\nTag message: Iteron %s\n\n' "$version"

read -r -p "Push annotated tag $tag to origin? [y/N] " answer
if [[ ! "$answer" =~ ^[Yy]$ ]]; then
  printf 'Aborted. No tag was created or pushed.\n' >&2
  exit 1
fi

git tag -a "$tag" -m "Iteron $version"
git push origin "$tag"
printf 'Pushed annotated tag %s\n' "$tag"

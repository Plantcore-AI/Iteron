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

version_input=${1:-}
if [[ -n "$version_input" ]]; then
  version=${version_input#v}
else
  version=$(
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
  )
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

if ! git diff --quiet; then
  fail "working tree has uncommitted changes"
fi
if ! git diff --cached --quiet; then
  fail "index has staged but uncommitted changes"
fi

commit=$(git rev-parse HEAD)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "could not determine current commit"

# Verify the workspace manifest still agrees with the requested version.
manifest_version=$(
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
)
[[ "$manifest_version" == "$version" ]] ||
  fail "requested version $version does not match Cargo.toml version $manifest_version"

# Require a successful workflow_dispatch of release.yml for this exact commit.
remote_url=$(git ls-remote --get-url origin 2>/dev/null) ||
  fail "could not determine remote origin"

# Accept either https://github.com/OWNER/REPO(.git) or git@github.com:OWNER/REPO.git
if [[ "$remote_url" =~ github\.com[/:]([^/]+)/([^/]+)(\.git)?$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
else
  fail "origin does not point to a github.com repository: $remote_url"
fi

successful_dispatch=$(
  gh api "repos/$owner/$repo/actions/workflows/release.yml/runs" \
    --paginate \
    --jq ".workflow_runs[] | select(.head_sha == \"$commit\" and .event == \"workflow_dispatch\" and .conclusion == \"success\") | .id" \
    2>/dev/null | head -n 1
) || true

if [[ -z "$successful_dispatch" ]]; then
  fail "commit $commit has no successful workflow_dispatch run of release.yml; dispatch release.yml from this commit first"
fi

# Refuse to overwrite an existing tag locally or remotely.
if git rev-parse -q --verify "$tag" >/dev/null; then
  fail "tag $tag already exists locally"
fi
if git ls-remote --tags origin "refs/tags/$tag" | grep -q "refs/tags/$tag"; then
  fail "tag $tag already exists on origin"
fi

printf 'Preparing annotated tag %s for commit %s\n' "$tag" "$commit"
printf 'Verified successful branch dispatch: run id %s\n' "$successful_dispatch"
printf '\nTag message: Iteron %s\n\n' "$version"

read -r -p "Push annotated tag $tag to origin? [y/N] " answer
if [[ ! "$answer" =~ ^[Yy]$ ]]; then
  printf 'Aborted. No tag was created or pushed.\n' >&2
  exit 1
fi

git tag -a "$tag" -m "Iteron $version"
git push origin "$tag"
printf 'Pushed annotated tag %s\n' "$tag"

#!/usr/bin/env bash
# A one-time 0.0.23 release-only continuation may reuse the exact parent's CI.
# No application source, dependencies, or tests may change in this exception.
set -euo pipefail

candidate=${1:?candidate commit required}
version=${2:?candidate version required}
[[ "$version" == 0.0.23 ]] || exit 1

read -r commit parent extra < <(git rev-list --parents -n 1 "$candidate")
[[ "$commit" == "$candidate" && -n "${parent:-}" && -z "${extra:-}" ]] || exit 1

changed=$(git diff --name-only "$parent" "$candidate" | LC_ALL=C sort)
expected=$'.github/workflows/release.yml\ndocs/development/releasing.md\ngovernance/schema-compatibility.json\nrelease-tools/ci_evidence_parent.sh\nrelease-tools/create_release_tag.sh\nrelease-tools/tests/test_release_tools.py'
[[ "$changed" == "$expected" ]] || exit 1
git diff --check "$parent" "$candidate" >/dev/null

base_schema=$(mktemp)
trap 'rm -f "$base_schema"' EXIT
git show "$parent:governance/schema-compatibility.json" > "$base_schema"
[[ "$(jq -er '.release_ordinal' "$base_schema")" == 8 ]] || exit 1
[[ "$(jq -er '.release_ordinal' governance/schema-compatibility.json)" == 9 ]] || exit 1
diff -q \
  <(jq -S 'del(.release_ordinal)' "$base_schema") \
  <(jq -S 'del(.release_ordinal)' governance/schema-compatibility.json) \
  >/dev/null

printf '%s\n' "$parent"

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
host=${1:-}
if [[ -z "$host" ]]; then
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64|Darwin:aarch64) host=darwin-arm64 ;;
    Darwin:x86_64|Darwin:amd64) host=darwin-x86_64 ;;
    Linux:aarch64|Linux:arm64) host=linux-arm64 ;;
    Linux:x86_64|Linux:amd64) host=linux-x86_64 ;;
    *)
      printf 'unsupported release-validation host: %s %s\n' "$(uname -s)" "$(uname -m)" >&2
      exit 2
      ;;
  esac
fi
case "$host" in
  darwin-arm64|darwin-x86_64|linux-arm64|linux-x86_64) ;;
  *) printf 'unsupported release-validation host: %s\n' "$host" >&2; exit 2 ;;
esac

command -v python3 >/dev/null
command -v node >/dev/null
command -v shellcheck >/dev/null

temporary=$(mktemp -d "${TMPDIR:-/tmp}/core-supply-validate.XXXXXXXX")
trap 'rm -rf "$temporary"' EXIT

cd "$repo_root"
python3 -m compileall -q release-tools
python3 -m unittest discover -s release-tools/tests -p 'test_*.py' -v
node release-tools/tests/test_ci_route.js
shellcheck -s sh install.sh
shellcheck -s bash \
  release-tools/audit_dependencies.sh \
  release-tools/check_docs.sh \
  release-tools/validate.sh \
  release-tools/tests/test_install.sh
release-tools/check_docs.sh
release-tools/tests/test_install.sh
python3 release-tools/fetch_tool.py actionlint "$host" --output "$temporary/actionlint"
"$temporary/actionlint" .github/workflows/*.yml

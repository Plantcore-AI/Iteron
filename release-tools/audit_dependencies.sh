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
      printf 'unsupported dependency-audit host: %s %s\n' "$(uname -s)" "$(uname -m)" >&2
      exit 2
      ;;
  esac
fi
case "$host" in
  darwin-arm64|darwin-x86_64|linux-arm64|linux-x86_64) ;;
  *) printf 'unsupported dependency-audit host: %s\n' "$host" >&2; exit 2 ;;
esac

command -v python3 >/dev/null
temporary=$(mktemp -d "${TMPDIR:-/tmp}/core-dependency-audit.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

cd "$repo_root"
python3 release-tools/fetch_tool.py cargo-audit "$host" \
  --output "$temporary/cargo-audit"
python3 release-tools/fetch_advisory_db.py rustsec \
  --output "$temporary/advisory-db"
python3 release-tools/dependency_audit.py \
  --cargo-audit "$temporary/cargo-audit" \
  --database "$temporary/advisory-db" \
  --lockfile Cargo.lock
python3 release-tools/dependency_audit.py \
  --cargo-audit "$temporary/cargo-audit" \
  --database "$temporary/advisory-db" \
  --lockfile release-tools/fixtures/vulnerable-Cargo.lock \
  --expect-advisory RUSTSEC-2020-0071

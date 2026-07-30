#!/usr/bin/env bash
#
# Dependency audit gate.
#
# STANDING POLICY, decided 2026-07-30 for issue #56.
#
# A vulnerability fails. So does an advisory cargo-audit classifies as informational — `unsound`
# and `unmaintained` are denied here rather than printed. The default is the opposite, and that
# default is how RUSTSEC-2026-0002 was printed by every run for six months without being read: a
# gate that reports a potential-UB advisory and then reports success trains a reader to skip its
# output, which costs more than the advisory it surfaced.
#
# The escape hatch is a written one. An advisory stays out of the way only by an entry in
# `release-tools/audit-policy.json` carrying an id, a reason, and a tracking issue, so "we looked
# at this" is a recorded decision with an argument attached rather than a silent exit code. Every
# current exception argues reachability, not inconvenience.
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

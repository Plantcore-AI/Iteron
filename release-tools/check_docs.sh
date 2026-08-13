#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

legacy_pattern='\.core|target/(release|debug)/core|(^|[[:space:]])cd iteron([[:space:]]|$)'
if matches=$(git grep -n -E "$legacy_pattern" -- '*.md'); then
  printf '%s\n' 'documentation contains a retired state path, binary path, or clone directory:' >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

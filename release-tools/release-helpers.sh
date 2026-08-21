# Shared shell helpers for release validation steps.
# Sourced by .github/workflows/release.yml; not executed directly.

fail() {
  printf 'release validation failed: %s\n' "$*" >&2
  exit 1
}

require_eq() {
  local description=$1 expected=$2 actual=$3
  if [[ "$expected" != "$actual" ]]; then
    printf 'release validation failed: %s\n  expected: %q\n  actual:   %q\n' "$description" "$expected" "$actual" >&2
    exit 1
  fi
}

require_match() {
  local description=$1 regex=$2 value=$3
  if [[ ! "$value" =~ $regex ]]; then
    printf 'release validation failed: %s\n  value: %q\n  regex:  %q\n' "$description" "$value" "$regex" >&2
    exit 1
  fi
}

require_not_exists() {
  local description=$1 path=$2
  if [[ -e "$path" ]]; then
    printf 'release validation failed: %s\n  path should not exist: %q\n' "$description" "$path" >&2
    exit 1
  fi
}

require_empty() {
  local description=$1 path=$2
  if [[ -s "$path" ]]; then
    printf 'release validation failed: %s\n  file should be empty: %q\n' "$description" "$path" >&2
    exit 1
  fi
}

require_true() {
  local description=$1
  shift
  if ! "$@"; then
    printf 'release validation failed: %s\n' "$description" >&2
    exit 1
  fi
}

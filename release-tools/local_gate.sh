#!/usr/bin/env bash
# Run a CI lane off GitHub Actions and report the result as a commit status.
#
# The org's Actions minutes are a scarce shared resource, so the gates that do not need a
# GitHub-hosted runner run on hardware we already own: the macOS lane on a developer Mac before
# push, the Linux lane on the DGX box. The branch ruleset still requires the same status
# contexts, and a ruleset matches a context by NAME rather than by producer, so reporting the
# same names here keeps the protection intact without burning a runner minute.
#
#   ./release-tools/local_gate.sh macos                    # run + publish
#   ./release-tools/local_gate.sh linux --emit out.json    # run, record, publish nothing
#   ./release-tools/local_gate.sh --publish out.json       # publish a recorded run
#   ./release-tools/local_gate.sh linux --dry-run          # run, publish nothing, record nothing
#
# The emit/publish split exists so a runner does not need a token. The Linux box is shared, and a
# `statuses: write` credential there would let any of its users mint a green check for this
# repository; it also has no `gh` installed. So it records a result and an authenticated machine
# publishes it:
#
#   linux$ ./release-tools/local_gate.sh linux --emit /tmp/gate.json
#   mac$   scp linux:/tmp/gate.json . && ./release-tools/local_gate.sh --publish gate.json
#
# What this trades away, stated plainly because it must not be discovered later:
#
#   1. A reported status is only as trustworthy as whoever holds the token. Anyone with push
#      access can post a green status without running anything. This moves the gate from
#      machine-enforced to executor-attested. The audit trail is the status `description`, which
#      records the host and the commit actually tested.
#   2. A pull request nobody runs this for simply never acquires the contexts, so it stays
#      blocked. That is deliberate, not a malfunction, and CONTRIBUTING says so.
#
# `review / required-humans` is intentionally NOT reported here: it reads the pull request's own
# review state, which does not exist locally. It stays on GitHub, as does the Windows lane.

set -euo pipefail

# Git exports its internal environment to hooks: GIT_DIR, GIT_INDEX_FILE, GIT_WORK_TREE,
# GIT_QUARANTINE_PATH and friends. Those are inherited by everything this script runs, and the
# test suite creates throwaway repositories with `git init`. With GIT_DIR set, every one of those
# is redirected at the REAL repository instead of its fixture directory, which during `git push`
# shows up as
#
#     error: could not lock config file .../core/.git/config: File exists
#     fatal: could not set 'iteron.repositoryformatversion' to '0'
#
# and a batch of unrelated-looking test failures. The lock is the only reason those writes did not
# land in the live repository, so scrub the whole namespace rather than the variables seen so far.
while IFS='=' read -r name _; do
  case "$name" in
    GIT_*) unset "$name" ;;
  esac
done < <(env)

readonly REPO_SLUG="${GATE_REPO:-Plantcore-AI/Iteron}"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  printf 'usage: %s <macos|linux> [--dry-run] [--emit FILE]\n' "${BASH_SOURCE[0]}" >&2
  printf '       %s --publish FILE\n' "${BASH_SOURCE[0]}" >&2
  exit 2
}

lane=""
dry_run=0
emit=""
publish=""
while (( $# )); do
  case "$1" in
    macos|linux) [[ -z "$lane" ]] || usage; lane="$1" ;;
    --dry-run) dry_run=1 ;;
    --emit) shift; emit="${1:-}"; [[ -n "$emit" ]] || usage ;;
    --publish) shift; publish="${1:-}"; [[ -n "$publish" ]] || usage ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage ;;
  esac
  shift
done

# Publishing a recorded run is a separate mode: it needs a token but no toolchain, no checkout
# state, and no gates.
if [[ -n "$publish" ]]; then
  [[ -z "$lane" ]] || usage
  [[ -r "$publish" ]] || { printf 'cannot read %s\n' "$publish" >&2; exit 2; }
  python3 - "$publish" "$REPO_SLUG" "${GATE_PUBLISH_WAIT:-0}" <<'PY'
import json, subprocess, sys, time
path, slug, wait = sys.argv[1], sys.argv[2], int(sys.argv[3])
record = json.load(open(path))
sha, host, lane = record["sha"], record["host"], record["lane"]

# A status can only be attached to a commit the remote already has. When this runs straight out
# of a pre-push hook the push has not happened yet, so wait for the commit to appear rather than
# failing with a 422. If it never appears the push failed, and publishing nothing is correct.
def still_reachable():
    """Is this commit still on a local branch, i.e. could it ever be pushed?

    Waiting on the clock alone is wrong for the commonest development loop there is: amend,
    force-push, amend again. Each amended push leaves the previous SHA orphaned, and a publisher
    waiting on it polls GitHub every few seconds for the full timeout before giving up on a
    commit that stopped being reachable the moment it was rewritten. Give up as soon as no
    branch contains it -- that is the fact that decides the outcome, not elapsed time.
    """
    listed = subprocess.run(
        ["git", "branch", "--all", "--contains", sha, "--format=%(refname)"],
        capture_output=True,
    )
    # An unknown object also fails here, which is the same verdict: nothing will publish it.
    return listed.returncode == 0 and listed.stdout.strip() != b""


deadline = time.monotonic() + wait
while True:
    probe = subprocess.run(
        ["gh", "api", f"repos/{slug}/commits/{sha}", "--silent"],
        capture_output=True,
    )
    if probe.returncode == 0:
        break
    if not still_reachable():
        print(
            f"commit {sha[:8]} was rewritten and is on no branch; publishing nothing",
            file=sys.stderr,
        )
        sys.exit(1)
    if time.monotonic() >= deadline:
        print(f"commit {sha[:8]} is not on the remote; publishing nothing", file=sys.stderr)
        sys.exit(1)
    time.sleep(5)

failed = 0
for context, state in record["results"].items():
    if state != "success":
        failed = 1
    description = f"{lane} lane on {host} @ {sha[:8]}"[:139]
    subprocess.run(
        ["gh", "api", f"repos/{slug}/statuses/{sha}", "--method", "POST",
         "-f", f"state={state}", "-f", f"context={context}",
         "-f", f"description={description}", "--silent"],
        check=True,
    )
    print(f"  {context:<26} {state}")
sys.exit(failed)
PY
  exit $?
fi

[[ -n "$lane" ]] || usage

# Report against the commit that was actually tested, not a moving branch name.
readonly SHA="${GATE_SHA:-$(git rev-parse HEAD)}"
readonly HOST="$(uname -s)/$(uname -m) $(hostname -s 2>/dev/null || echo unknown)"

if [[ -n "$(git status --porcelain)" ]]; then
  printf 'refusing to gate a dirty worktree: the status would name a commit that was not what ran\n' >&2
  git status --short >&2
  exit 1
fi

# The dirty check above proves the tree matches *some* commit. It does not prove it matches the one
# whose name goes on the status, and nothing here ever checks $SHA out -- the lanes below build
# whatever HEAD already is. `.git/hooks/pre-push` passes the *pushed ref's* sha as GATE_SHA, so
# pushing a branch that is not the checked-out one published a green context for a tree that was
# never built. Refusing is the right move rather than checking out for the caller: a gate that
# silently moves your worktree is its own hazard, and the caller knows which commit it meant.
HEAD_SHA="$(git rev-parse HEAD)"
readonly HEAD_SHA
if [[ "$SHA" != "$HEAD_SHA" ]]; then
  printf 'refusing to gate %s while HEAD is %s: the lanes build HEAD, so the status would name a commit that never ran\n' \
    "${SHA:0:12}" "${HEAD_SHA:0:12}" >&2
  printf 'check out the commit you mean, then re-run\n' >&2
  exit 1
fi

# One lane at a time per repository. Every driver script `cd`s into the same checkout and runs
# `git checkout -f -B`, so a second concurrent run rebuilds the branch inside the first run's
# working tree mid-build -- and both then report against whatever survived. The shared `policy_root`
# worktree and the docs virtualenv below have the same problem. `flock` makes the second run wait
# rather than corrupt the first; if flock is unavailable the gate says so instead of pretending it
# serialised anything.
# macOS ships no flock(1), and macOS is where the pre-push hook runs, so a flock-only lock would
# have left the busiest host unprotected while reporting that it was serialised. Python is already
# a hard dependency of this directory, and `fcntl.flock` is the same advisory lock, released by the
# kernel when the holder dies -- which a pid file or a `mkdir` lock cannot promise after a SIGKILL.
# The lock is held by a background helper for exactly as long as this script lives.
if [[ -z "${GATE_NO_LOCK:-}" ]]; then
  LOCK_PATH="$(git rev-parse --git-common-dir)/gate-${lane}.lock"
  readonly LOCK_PATH
  lock_wait="${GATE_LOCK_WAIT_SECS:-3600}"
  lock_ready="$(mktemp "${TMPDIR:-/tmp}/core-gate-lock.XXXXXXXX")"
  lock_script="$(mktemp "${TMPDIR:-/tmp}/core-gate-lock-py.XXXXXXXX")"
  lock_pipe="$(mktemp -u "${TMPDIR:-/tmp}/core-gate-lock-fifo.XXXXXXXX")"
  mkfifo "$lock_pipe"
  cat >"$lock_script" <<'LOCKPY'
import fcntl, sys, time
path, wait, ready = sys.argv[1], float(sys.argv[2]), sys.argv[3]
handle = open(path, "w")
deadline = time.monotonic() + wait
while True:
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except OSError:
        if time.monotonic() >= deadline:
            open(ready, "w").write("busy")
            sys.exit(0)
        time.sleep(0.2)
open(ready, "w").write("held")
# Hold the lock until this pipe reports end-of-file, which happens when the gate process that
# opened the write end goes away -- including when it is SIGKILLed, which is the case a pid file
# or a lock directory cannot survive. Reading stdin from a heredoc instead would EOF the instant
# the script text was consumed, releasing the lock immediately and protecting nothing.
try:
    sys.stdin.read()
except Exception:
    pass
LOCKPY
  python3 "$lock_script" "$LOCK_PATH" "$lock_wait" "$lock_ready" <"$lock_pipe" &
  lock_pid=$!
  # The write end lives in this shell, so it closes exactly when this shell dies, by any means.
  # Descriptor 9 is named explicitly rather than allocated with `exec {VAR}>`: that syntax needs
  # bash 4, and macOS ships bash 3.2, where it fails with `exec: {LOCK_FD}: not found` -- leaving
  # the writer unopened, the helper blocked on the FIFO forever, and no lock held by anyone.
  exec 9>"$lock_pipe"
  # Nothing is unlinked yet. Opening the FIFO for reading blocks until this `exec` supplies the
  # writer, so the helper has not run -- and therefore has not opened its program file -- until the
  # line above. Deleting the program here instead of after the handshake raced it every time, with
  # python reporting a missing file and the gate then refusing itself as though a second lane held
  # the lock.
  rm -f "$lock_pipe"
  for _ in $(seq 1 "$(( lock_wait * 5 + 10 ))"); do
    [[ -s "$lock_ready" ]] && break
    sleep 0.2
  done
  rm -f "$lock_script"
  if [[ "$(cat "$lock_ready" 2>/dev/null)" != "held" ]]; then
    rm -f "$lock_ready"
    printf 'another %s lane is still running in this repository; refusing to run a second one\n' "$lane" >&2
    exit 1
  fi
  rm -f "$lock_ready"
fi

post_status() {
  local context="$1" state="$2" description="$3"
  if (( dry_run )) || [[ -n "$emit" ]]; then
    printf '  [not published] %-26s %s\n' "$context" "$state"
    return 0
  fi
  # A failure to publish must not be mistaken for a passing gate.
  if ! gh api "repos/${REPO_SLUG}/statuses/${SHA}" \
      --method POST \
      -f state="$state" \
      -f context="$context" \
      -f description="${description:0:139}" \
      --silent; then
    printf 'could not publish status %s for %s\n' "$context" "$SHA" >&2
    return 1
  fi
}

declare -a CONTEXTS
if [[ "$lane" == macos ]]; then
  CONTEXTS=("rust / macos-15")
else
  CONTEXTS=(
    "rust / ubuntu-24.04"
    "boundary / validate"
    "supply / validate"
    "docs / strict-build"
    "supply / dependency audit"
  )
fi

printf '== gate lane=%s sha=%s host=%s\n' "$lane" "${SHA:0:8}" "$HOST"
for context in "${CONTEXTS[@]}"; do
  post_status "$context" pending "queued on ${HOST}"
done

# Each gate records its own outcome so one failure does not hide the rest.
#
# Deliberately an indexed array parallel to CONTEXTS rather than an associative one: macOS ships
# bash 3.2, where `declare -A` is a syntax error, and the macOS lane has to run on the Mac.
#
# `run_gate` must ALWAYS succeed: the script runs under `set -e`, so a non-zero return here would
# abort before the publishing loop and strand every context on `pending` — the exact opposite of
# recording a failure. A gate's verdict travels in RESULTS, never in the exit status.
RESULTS=()
for _ in "${CONTEXTS[@]}"; do RESULTS+=(""); done

index_of() {
  local needle="$1" i
  for i in "${!CONTEXTS[@]}"; do
    [[ "${CONTEXTS[$i]}" == "$needle" ]] && { printf '%s' "$i"; return 0; }
  done
  return 1
}

result_of() {
  local i
  i="$(index_of "$1")" || return 1
  printf '%s' "${RESULTS[$i]}"
}

run_gate() {
  local context="$1"; shift
  local i
  i="$(index_of "$context")" || { printf 'unknown context %s\n' "$context" >&2; return 0; }
  printf '\n-- %s\n' "$context"
  if "$@"; then
    RESULTS[$i]=success
    printf -- '-- %s: PASS\n' "$context"
  else
    RESULTS[$i]=failure
    printf -- '-- %s: FAIL\n' "$context"
  fi
  return 0
}

# A crash between the `pending` posts and the publishing loop would otherwise leave the contexts
# pending forever, which reads as "still running" rather than "this run died".
publish_pending_as_failure() {
  local code=$?
  (( code == 0 )) && return 0
  printf '\ngate aborted (exit %s); marking unresolved contexts failed\n' "$code" >&2
  local context
  for context in "${CONTEXTS[@]}"; do
    [[ -n "$(result_of "$context" || true)" ]] && continue
    post_status "$context" failure "gate aborted on ${HOST} @ ${SHA:0:8}" || true
  done
}
trap publish_pending_as_failure EXIT

rust_lane() {
  cargo fmt --all -- --check \
    && cargo check --workspace --all-targets --locked \
    && cargo clippy --workspace --all-targets --locked -- -D warnings \
    && cargo test --workspace --all-targets --locked
}

boundary_lane() {
  # Mirrors the boundary job, including the part that is easy to leave out and thereby ship a
  # weaker gate under the same context name.
  #
  # The workflow does NOT validate a candidate with the candidate's own validator: it builds
  # iteron-xtask from the merge base and runs THAT binary against the working tree, so a change
  # cannot loosen the rule that is judging it. Reproduce that here or do not claim this context.
  #
  # Needs full history: the W1 freeze commit is resolved through `git rev-parse`.
  set -o pipefail
  cargo run --locked -p iteron-xtask -- conformance kernel || return 1
  cargo run --locked -p iteron-xtask -- boundaries check || return 1

  local base
  base="$(git merge-base "${GATE_BASE_REF:-origin/main}" HEAD)" || return 1
  if [[ "$base" == "$(git rev-parse HEAD)" ]]; then
    printf 'HEAD is the base; no base-relative boundary checks to run\n'
    return 0
  fi
  printf 'base-relative checks against %s\n' "${base:0:8}"

  local policy_root="${TMPDIR:-/tmp}/core-policy-base-${base:0:12}"
  if [[ ! -d "$policy_root" ]]; then
    git worktree add --detach "$policy_root" "$base" >/dev/null || return 1
  fi
  # The base validator needs its OWN target directory. An ambient CARGO_TARGET_DIR is shared with
  # the candidate build, so without this the base `iteron-xtask` overwrites the candidate's binary
  # in a directory both builds treat as theirs — and the validator that judges the change would
  # be whichever one was compiled last.
  local policy_target="$policy_root/.gate-target"
  local policy_bin="$policy_target/debug/iteron-xtask"
  ( cd "$policy_root" && CARGO_TARGET_DIR="$policy_target" cargo build --locked -p iteron-xtask ) \
    || return 1
  [[ -x "$policy_bin" ]] || { printf 'base validator did not build at %s\n' "$policy_bin" >&2; return 1; }

  "$policy_bin" --repo "$ROOT" boundaries check-base --base "$base" || return 1
  "$policy_bin" --repo "$ROOT" schema-compat check-base --base "$base" || return 1
  "$policy_bin" --repo "$ROOT" boundaries check || return 1

  # `check-pr` validates that the pull request BODY declares the boundaries and overlays the diff
  # touches, so it needs text that only exists once a pull request does. The workflow guards this
  # same step on `pull_request`, so requiring one here is parity rather than an extra hurdle.
  #
  # It is deliberately not skipped-and-still-green: this context is required by the ruleset, and
  # publishing it after quietly dropping one of its checks is the silent downgrade this whole
  # lane exists to avoid.
  local body_file="${GATE_PR_BODY_FILE:-}"
  if [[ -z "$body_file" && -z "${PR_BODY:-}" ]] && command -v gh >/dev/null; then
    body_file="$(mktemp)"
    if ! gh pr view --repo "$REPO_SLUG" --json body --jq .body > "$body_file" 2>/dev/null \
       || [[ ! -s "$body_file" ]]; then
      rm -f "$body_file"
      body_file=""
    fi
  fi
  if [[ -n "$body_file" ]]; then
    PR_BODY="$(cat "$body_file")"
  fi
  if [[ -z "${PR_BODY:-}" ]]; then
    printf 'cannot run `boundaries check-pr`: no pull request body available.\n' >&2
    printf 'Open the pull request first, or pass one explicitly:\n' >&2
    printf '  gh pr view --json body --jq .body > /tmp/body.txt\n' >&2
    printf '  GATE_PR_BODY_FILE=/tmp/body.txt %s linux\n' "${BASH_SOURCE[0]}" >&2
    return 1
  fi
  PR_BODY="$PR_BODY" "$policy_bin" --repo "$ROOT" boundaries check-pr --base "$base" || return 1
}

docs_lane() {
  # Hash-locked, same as the workflow. The venv is cached next to the target dir, not in the tree.
  local venv="${GATE_DOCS_VENV:-${TMPDIR:-/tmp}/core-docs-venv}"
  bash release-tools/check_docs.sh || return 1
  cargo run --locked -p iteron-xtask -- docs check || return 1
  cargo run --locked -p iteron-xtask -- tunables check-params || return 1
  cargo run --locked -p iteron-xtask -- tunables surface || return 1
  cargo run --locked -p iteron-xtask -- tunables census-check || return 1
  if [[ ! -x "$venv/bin/mkdocs" ]]; then
    python3 -m venv "$venv" || return 1
    "$venv/bin/python" -m pip install --disable-pip-version-check --require-hashes \
      -r requirements-docs.lock >/dev/null || return 1
  fi
  NO_MKDOCS_2_WARNING=true PYTHONUTF8=1 "$venv/bin/mkdocs" build --strict --clean
}

if [[ "$lane" == macos ]]; then
  run_gate "rust / macos-15" rust_lane
else
  run_gate "rust / ubuntu-24.04" rust_lane
  run_gate "boundary / validate" boundary_lane
  run_gate "supply / validate" bash release-tools/validate.sh
  run_gate "docs / strict-build" docs_lane
  # No host argument: the script detects its own. The workflow passes `linux-x86_64` because a
  # GitHub runner is x86_64; naming that here would fetch an x86_64 `cargo-audit` onto whatever
  # this box actually is, and it fails its own version pin rather than running.
  run_gate "supply / dependency audit" bash release-tools/audit_dependencies.sh
fi

printf '\n== results\n'
failed=0
for context in "${CONTEXTS[@]}"; do
  # `|| true`: under `set -e` a lookup miss here would abort mid-publish.
  state="$(result_of "$context" || true)"; state="${state:-failure}"
  [[ "$state" == success ]] || failed=1
  post_status "$context" "$state" "${lane} lane on ${HOST} @ ${SHA:0:8}"
  printf '  %-26s %s\n' "$context" "$state"
done

if [[ -n "$emit" ]]; then
  # A gate that cannot record its verdict has not produced evidence, so this failing is fatal
  # even when every gate passed.
  {
    printf '{"sha":"%s","host":"%s","lane":"%s","results":{' "$SHA" "$HOST" "$lane"
    sep=""
    for context in "${CONTEXTS[@]}"; do
      emit_state="$(result_of "$context" || true)"
      printf '%s"%s":"%s"' "$sep" "$context" "${emit_state:-failure}"
      sep=","
    done
    printf '}}\n'
  } > "$emit" || { printf 'could not write %s\n' "$emit" >&2; exit 1; }
  printf '\nrecorded to %s; publish it from a machine with a token:\n' "$emit"
  printf '  ./release-tools/local_gate.sh --publish %s\n' "$(basename "$emit")"
fi

exit "$failed"

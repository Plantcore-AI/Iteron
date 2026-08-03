#!/bin/sh
# Core Code release installer. Release packaging replaces the marker below with
# an immutable tag such as v0.0.1. Keep the entire mutating path behind main so
# a truncated `curl | sh` stream cannot perform a partial installation.

CORE_CODE_EMBEDDED_VERSION='@CORE_CODE_VERSION@'
CORE_CODE_RELEASE_ROOT='https://github.com/Plantcore-AI/core/releases/download'
CORE_CODE_MAX_MANIFEST_BYTES=1048576
CORE_CODE_MAX_ARCHIVE_BYTES=268435456
CORE_CODE_MAX_UNPACKED_BYTES=134217728

core_code_usage() {
    cat <<'EOF'
Install Core Code from an immutable GitHub release.

Usage:
  install.sh [--version vX.Y.Z] [--bin-dir PATH]

Options:
  --version VERSION  Install an exact release tag. The release asset embeds its
                     own version, so this is optional for normal curl installs.
  --bin-dir PATH     Install the `core` command into PATH. Defaults to
                     $CORE_CODE_INSTALL_DIR, $XDG_BIN_HOME, or ~/.local/bin.
  -h, --help         Show this help.

The installer never invokes sudo and never edits shell startup files.
EOF
}

core_code_die() {
    printf 'core-code: error: %s\n' "$*" >&2
    exit 1
}

core_code_warn() {
    printf 'core-code: warning: %s\n' "$*" >&2
}

# Code execution is confined by bubblewrap on Linux, and the backend fails CLOSED: no usable
# `bwrap`, no bash/build/test tool at all. Two things break it, and neither was mentioned anywhere
# a new user would look. The package may simply be absent, and Ubuntu 24.04 restricts unprivileged
# user namespaces unless the invoking binary has an AppArmor profile — the project's own CI has to
# install one. Run the same probe the backend runs and print the exact remedy. A WARNING, never a
# hard failure: `core` is perfectly usable for reading and editing without a sandbox.
core_code_linux_preflight() {
    [ "$1" = Linux ] || return 0

    core_code_bwrap=
    for core_code_candidate in /usr/bin/bwrap /bin/bwrap /usr/local/bin/bwrap; do
        if [ -f "$core_code_candidate" ] && [ ! -L "$core_code_candidate" ]; then
            core_code_bwrap=$core_code_candidate
            break
        fi
    done

    if [ -z "$core_code_bwrap" ]; then
        core_code_warn 'code execution (bash/build/test) will refuse to run: bubblewrap is not installed'
        cat <<'EOF' >&2
Install it, then re-run `core`:
  Debian/Ubuntu:  sudo apt-get install -y bubblewrap
  Fedora/RHEL:    sudo dnf install -y bubblewrap
  Alpine:         sudo apk add bubblewrap
  Arch:           sudo pacman -S bubblewrap
EOF
        return 0
    fi

    if "$core_code_bwrap" --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
        --die-with-parent --new-session --unshare-pid --unshare-ipc --unshare-uts \
        --unshare-net /bin/true >/dev/null 2>&1; then
        return 0
    fi

    core_code_warn "code execution (bash/build/test) will refuse to run: $core_code_bwrap cannot create the required namespaces"
    cat <<EOF >&2
This is the Ubuntu 24.04 unprivileged-user-namespace restriction. Grant it to this
one binary rather than disabling the system-wide control:
  sudo apt-get install -y apparmor apparmor-utils
  printf 'abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile core-bwrap $core_code_bwrap flags=(unconfined) {\n  userns,\n}\n' | sudo tee /etc/apparmor.d/core-bwrap >/dev/null
  sudo apparmor_parser --replace /etc/apparmor.d/core-bwrap
See https://plantcore-ai.github.io/core/reference/platforms/ for the full contract.
EOF
}

core_code_require() {
    command -v "$1" >/dev/null 2>&1 || core_code_die "required command not found: $1"
}

core_code_download() {
    core_code_url=$1
    core_code_destination=$2
    core_code_max_bytes=$3

    curl \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --fail \
        --location \
        --silent \
        --show-error \
        --retry 3 \
        --retry-delay 1 \
        --retry-connrefused \
        --connect-timeout 10 \
        --max-time 300 \
        --max-filesize "$core_code_max_bytes" \
        --output "$core_code_destination" \
        "$core_code_url"
}

core_code_file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

core_code_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        core_code_die 'neither sha256sum nor shasum is available'
    fi
}

core_code_unpack_archive() {
    core_code_compressed=$1
    core_code_unpacked=$2
    # POSIX ulimit -f uses 512-byte blocks. Bounding the decompressor's output
    # prevents a small, checksum-valid gzip bomb from exhausting the filesystem
    # before tar ever has a chance to inspect member paths and types.
    core_code_file_blocks=$(( (CORE_CODE_MAX_UNPACKED_BYTES + 511) / 512 ))
    (
        ulimit -f "$core_code_file_blocks" || exit 1
        gzip -dc "$core_code_compressed" > "$core_code_unpacked"
    ) || core_code_die 'release archive exceeds the safe unpacked size limit or is corrupt'
    core_code_unpacked_size=$(core_code_file_size "$core_code_unpacked")
    if [ "$core_code_unpacked_size" -le 0 ] \
        || [ "$core_code_unpacked_size" -gt "$CORE_CODE_MAX_UNPACKED_BYTES" ]; then
        core_code_die 'release archive is empty or exceeds the safe unpacked size limit'
    fi
}

core_code_validate_archive() {
    core_code_tar=$1
    core_code_root=$2
    core_code_members=$3
    core_code_verbose=$4
    core_code_expected=$5
    core_code_sorted_members=$6
    core_code_sorted_expected=$7

    tar -tf "$core_code_tar" > "$core_code_members" \
        || core_code_die 'release archive cannot be listed'
    tar -tvf "$core_code_tar" > "$core_code_verbose" \
        || core_code_die 'release archive metadata cannot be inspected'

    # A release archive is deliberately tiny and exact. Matching the complete
    # member set rejects absolute paths, dot-dot traversal, duplicates, hidden
    # payloads, and unexpected files before extraction.
    {
        printf '%s/\n' "$core_code_root"
        printf '%s/%s\n' "$core_code_root" core
        printf '%s/%s\n' "$core_code_root" LICENSE
        printf '%s/%s\n' "$core_code_root" README.md
        printf '%s/%s\n' "$core_code_root" THIRD_PARTY_LICENSES.html
        printf '%s/%s\n' "$core_code_root" THIRD_PARTY_NOTICES.txt
        printf '%s/%s\n' "$core_code_root" SBOM.spdx.json
        printf '%s/%s\n' "$core_code_root" BUILD-INFO.json
    } > "$core_code_expected"

    core_code_member_count=$(wc -l < "$core_code_members" | tr -d '[:space:]')
    [ "$core_code_member_count" = 8 ] \
        || core_code_die 'release archive has an unexpected member count'

    LC_ALL=C sort "$core_code_members" > "$core_code_sorted_members"
    LC_ALL=C sort "$core_code_expected" > "$core_code_sorted_expected"
    cmp -s "$core_code_sorted_members" "$core_code_sorted_expected" \
        || core_code_die 'release archive contains an unexpected path'

    # GNU tar and BSD tar both put the entry type at the first character of
    # their verbose mode column. Only directories and regular files are valid.
    awk '
        substr($1, 1, 1) != "d" && substr($1, 1, 1) != "-" { exit 1 }
    ' "$core_code_verbose" \
        || core_code_die 'release archive contains a link or special file'
}

core_code_main() {
    set -eu

    core_code_version=$CORE_CODE_EMBEDDED_VERSION
    core_code_bin_dir=${CORE_CODE_INSTALL_DIR:-}

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || core_code_die '--version requires a value'
                core_code_version=$2
                shift 2
                ;;
            --bin-dir)
                [ "$#" -ge 2 ] || core_code_die '--bin-dir requires a value'
                core_code_bin_dir=$2
                shift 2
                ;;
            -h|--help)
                core_code_usage
                exit 0
                ;;
            --)
                shift
                [ "$#" -eq 0 ] || core_code_die 'positional arguments are not supported'
                ;;
            *)
                core_code_die "unknown option: $1"
                ;;
        esac
    done

    printf '%s\n' "$core_code_version" \
        | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
        || core_code_die 'version must be an exact stable tag such as v0.0.1'

    if [ -z "$core_code_bin_dir" ]; then
        if [ -n "${XDG_BIN_HOME:-}" ]; then
            core_code_bin_dir=$XDG_BIN_HOME
        else
            [ -n "${HOME:-}" ] || core_code_die 'HOME is not set; pass --bin-dir'
            core_code_bin_dir=$HOME/.local/bin
        fi
    fi
    [ -n "$core_code_bin_dir" ] || core_code_die 'installation directory is empty'

    core_code_require curl
    core_code_require tar
    core_code_require awk
    core_code_require cmp
    core_code_require chmod
    core_code_require grep
    core_code_require gzip
    core_code_require install
    core_code_require mkdir
    core_code_require mktemp
    core_code_require mv
    core_code_require rm
    core_code_require sort
    core_code_require tr
    core_code_require uname
    core_code_require wc

    core_code_os=$(uname -s)
    core_code_arch=$(uname -m)
    case "$core_code_os:$core_code_arch" in
        Darwin:arm64|Darwin:aarch64)
            core_code_target=aarch64-apple-darwin
            ;;
        Darwin:x86_64|Darwin:amd64)
            core_code_target=x86_64-apple-darwin
            ;;
        Linux:aarch64|Linux:arm64)
            core_code_target=aarch64-unknown-linux-musl
            ;;
        Linux:x86_64|Linux:amd64)
            core_code_target=x86_64-unknown-linux-musl
            ;;
        *)
            core_code_die "unsupported platform: $core_code_os $core_code_arch"
            ;;
    esac

    core_code_version_number=${core_code_version#v}
    core_code_archive_root="core-code-${core_code_version}-${core_code_target}"
    core_code_archive_name="${core_code_archive_root}.tar.gz"
    core_code_base_url="${CORE_CODE_RELEASE_ROOT}/${core_code_version}"

    core_code_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/core-code.XXXXXXXX") \
        || core_code_die 'could not create a temporary directory'
    core_code_install_tmp=
    core_code_cleanup() {
        if [ -n "${core_code_install_tmp:-}" ]; then
            rm -f -- "$core_code_install_tmp"
        fi
        rm -rf -- "$core_code_work_dir"
    }
    trap core_code_cleanup 0
    trap 'exit 1' HUP INT TERM
    umask 077

    core_code_checksums="$core_code_work_dir/SHA256SUMS"
    core_code_archive="$core_code_work_dir/$core_code_archive_name"
    core_code_download \
        "$core_code_base_url/SHA256SUMS" \
        "$core_code_checksums" \
        "$CORE_CODE_MAX_MANIFEST_BYTES" \
        || core_code_die 'could not download SHA256SUMS'
    core_code_manifest_size=$(core_code_file_size "$core_code_checksums")
    if [ "$core_code_manifest_size" -le 0 ] \
        || [ "$core_code_manifest_size" -gt "$CORE_CODE_MAX_MANIFEST_BYTES" ]; then
        core_code_die 'SHA256SUMS is empty or unexpectedly large'
    fi

    core_code_download \
        "$core_code_base_url/$core_code_archive_name" \
        "$core_code_archive" \
        "$CORE_CODE_MAX_ARCHIVE_BYTES" \
        || core_code_die "could not download $core_code_archive_name"
    core_code_archive_size=$(core_code_file_size "$core_code_archive")
    if [ "$core_code_archive_size" -le 0 ] \
        || [ "$core_code_archive_size" -gt "$CORE_CODE_MAX_ARCHIVE_BYTES" ]; then
        core_code_die 'release archive is empty or unexpectedly large'
    fi

    core_code_checksum_rows=$(awk -v name="$core_code_archive_name" '
        $2 == name || $2 == "*" name { print $1 }
    ' "$core_code_checksums")
    core_code_checksum_count=$(printf '%s\n' "$core_code_checksum_rows" \
        | awk 'NF { count += 1 } END { print count + 0 }')
    [ "$core_code_checksum_count" -eq 1 ] \
        || core_code_die 'SHA256SUMS must contain exactly one archive digest'
    core_code_expected_digest=$(printf '%s\n' "$core_code_checksum_rows" | awk 'NF { print; exit }')
    printf '%s\n' "$core_code_expected_digest" | grep -Eq '^[0-9a-f]{64}$' \
        || core_code_die 'archive digest is malformed'
    core_code_actual_digest=$(core_code_sha256 "$core_code_archive")
    [ "$core_code_actual_digest" = "$core_code_expected_digest" ] \
        || core_code_die 'archive checksum verification failed'

    core_code_unpacked="$core_code_work_dir/archive.tar"
    core_code_unpack_archive "$core_code_archive" "$core_code_unpacked"
    core_code_validate_archive \
        "$core_code_unpacked" \
        "$core_code_archive_root" \
        "$core_code_work_dir/members" \
        "$core_code_work_dir/verbose" \
        "$core_code_work_dir/expected" \
        "$core_code_work_dir/members.sorted" \
        "$core_code_work_dir/expected.sorted"

    mkdir "$core_code_work_dir/extract"
    tar -xf "$core_code_unpacked" -C "$core_code_work_dir/extract" \
        || core_code_die 'release archive extraction failed'
    core_code_binary="$core_code_work_dir/extract/$core_code_archive_root/core"
    if [ ! -f "$core_code_binary" ] || [ -L "$core_code_binary" ]; then
        core_code_die 'archive core entry is not a regular file'
    fi
    chmod 0755 "$core_code_binary"

    # `-V` is the bare `core <semver>`; `--version` additionally carries the commit and build date,
    # so the exact-match smoke tests below deliberately use the short form.
    core_code_reported_version=$("$core_code_binary" -V 2>&1) \
        || core_code_die 'downloaded binary failed its version smoke test'
    [ "$core_code_reported_version" = "core $core_code_version_number" ] \
        || core_code_die "downloaded binary reported an unexpected version: $core_code_reported_version"

    mkdir -p -- "$core_code_bin_dir" \
        || core_code_die "could not create installation directory: $core_code_bin_dir"
    [ -d "$core_code_bin_dir" ] \
        || core_code_die "installation path is not a directory: $core_code_bin_dir"
    [ ! -d "$core_code_bin_dir/core" ] \
        || core_code_die 'installation destination is a directory'
    core_code_install_tmp=$(mktemp "$core_code_bin_dir/.core.new.XXXXXXXX") \
        || core_code_die 'could not create an atomic installation staging file'
    install -m 0755 "$core_code_binary" "$core_code_install_tmp" \
        || core_code_die 'could not stage the installed binary'
    if [ ! -f "$core_code_install_tmp" ] || [ -L "$core_code_install_tmp" ]; then
        core_code_die 'staged installation is not a regular file'
    fi
    core_code_staged_version=$("$core_code_install_tmp" -V 2>&1) \
        || core_code_die 'staged binary failed its version smoke test'
    [ "$core_code_staged_version" = "core $core_code_version_number" ] \
        || core_code_die 'staged binary reported an unexpected version'
    mv -f -- "$core_code_install_tmp" "$core_code_bin_dir/core" \
        || core_code_die 'could not atomically install core'
    if [ ! -f "$core_code_bin_dir/core" ] || [ -L "$core_code_bin_dir/core" ]; then
        core_code_die 'atomic install did not produce a regular destination file'
    fi
    core_code_installed_version=$("$core_code_bin_dir/core" -V 2>&1) \
        || core_code_die 'installed binary failed its final version smoke test'
    [ "$core_code_installed_version" = "core $core_code_version_number" ] \
        || core_code_die 'installed binary reported an unexpected final version'
    core_code_install_tmp=

    printf 'Core Code %s installed at %s/core\n' "$core_code_version_number" "$core_code_bin_dir"
    case ":${PATH:-}:" in
        *:"$core_code_bin_dir":*) ;;
        *) printf 'Add %s to PATH to run the core command.\n' "$core_code_bin_dir" ;;
    esac
    core_code_linux_preflight "$core_code_os"
}

core_code_main "$@"

#!/bin/sh
# Iteron release installer. Release packaging replaces the marker below with
# an immutable tag such as v0.0.1. Keep the entire mutating path behind main so
# a truncated `curl | sh` stream cannot perform a partial installation.

ITERON_EMBEDDED_VERSION='@ITERON_VERSION@'
ITERON_RELEASE_ROOT='https://github.com/Plantcore-AI/Iteron/releases/download'
ITERON_MAX_MANIFEST_BYTES=1048576
ITERON_MAX_ARCHIVE_BYTES=268435456
ITERON_MAX_UNPACKED_BYTES=134217728

iteron_usage() {
    cat <<'EOF'
Install Iteron from an immutable GitHub release.

Usage:
  install.sh [--version vX.Y.Z] [--bin-dir PATH]

Options:
  --version VERSION  Install an exact release tag. The release asset embeds its
                     own version, so this is optional for normal curl installs.
  --bin-dir PATH     Install the `iteron` command into PATH. Defaults to
                     $ITERON_INSTALL_DIR, legacy $ITERON_CODE_INSTALL_DIR,
                     $XDG_BIN_HOME, or ~/.local/bin.
  -h, --help         Show this help.

The installer never invokes sudo and never edits shell startup files.
EOF
}

iteron_die() {
    printf 'iteron: error: %s\n' "$*" >&2
    exit 1
}

iteron_warn() {
    printf 'iteron: warning: %s\n' "$*" >&2
}

iteron_note() {
    printf 'iteron: %s\n' "$*" >&2
}

# The shipped default is unconfined. When the operator selects `--confine` on Linux, the bubblewrap
# backend fails CLOSED: no usable `bwrap`, no bash/build/test tool at all. The package may be absent,
# and Ubuntu 24.04 restricts unprivileged user namespaces unless the invoking binary has an AppArmor
# profile. Run the same probe the backend runs and print the exact remedy. A WARNING, never a hard
# failure: installation and an explicitly unconfined run do not depend on bubblewrap.
iteron_linux_preflight() {
    [ "$1" = Linux ] || return 0

    iteron_bwrap=
    for iteron_candidate in /usr/bin/bwrap /bin/bwrap /usr/local/bin/bwrap; do
        if [ -f "$iteron_candidate" ] && [ ! -L "$iteron_candidate" ]; then
            iteron_bwrap=$iteron_candidate
            break
        fi
    done

    if [ -z "$iteron_bwrap" ]; then
        iteron_warn 'code execution (bash/build/test) will refuse to run: bubblewrap is not installed'
        cat <<'EOF' >&2
Install it, then re-run `iteron`:
  Debian/Ubuntu:  sudo apt-get install -y bubblewrap
  Fedora/RHEL:    sudo dnf install -y bubblewrap
  Alpine:         sudo apk add bubblewrap
  Arch:           sudo pacman -S bubblewrap
EOF
        return 0
    fi

    if "$iteron_bwrap" --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
        --die-with-parent --new-session --unshare-pid --unshare-ipc --unshare-uts \
        --unshare-net /bin/true >/dev/null 2>&1; then
        return 0
    fi

    iteron_warn "code execution (bash/build/test) will refuse to run: $iteron_bwrap cannot create the required namespaces"
    cat <<EOF >&2
This is the Ubuntu 24.04 unprivileged-user-namespace restriction. Grant it to this
one binary rather than disabling the system-wide control:
  sudo apt-get install -y apparmor apparmor-utils
  printf 'abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile iteron-bwrap $iteron_bwrap flags=(unconfined) {\n  userns,\n}\n' | sudo tee /etc/apparmor.d/iteron-bwrap >/dev/null
  sudo apparmor_parser --replace /etc/apparmor.d/iteron-bwrap
See https://plantcore-ai.github.io/Iteron/reference/platforms/ for the full contract.
EOF
}

iteron_require() {
    command -v "$1" >/dev/null 2>&1 || iteron_die "required command not found: $1"
}

iteron_download() {
    iteron_url=$1
    iteron_destination=$2
    iteron_max_bytes=$3

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
        --max-filesize "$iteron_max_bytes" \
        --output "$iteron_destination" \
        "$iteron_url"
}

iteron_file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

iteron_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        iteron_die 'neither sha256sum nor shasum is available'
    fi
}

iteron_unpack_archive() {
    iteron_compressed=$1
    iteron_unpacked=$2
    # POSIX ulimit -f uses 512-byte blocks. Bounding the decompressor's output
    # prevents a small, checksum-valid gzip bomb from exhausting the filesystem
    # before tar ever has a chance to inspect member paths and types.
    iteron_file_blocks=$(( (ITERON_MAX_UNPACKED_BYTES + 511) / 512 ))
    (
        ulimit -f "$iteron_file_blocks" || exit 1
        gzip -dc "$iteron_compressed" > "$iteron_unpacked"
    ) || iteron_die 'release archive exceeds the safe unpacked size limit or is corrupt'
    iteron_unpacked_size=$(iteron_file_size "$iteron_unpacked")
    if [ "$iteron_unpacked_size" -le 0 ] \
        || [ "$iteron_unpacked_size" -gt "$ITERON_MAX_UNPACKED_BYTES" ]; then
        iteron_die 'release archive is empty or exceeds the safe unpacked size limit'
    fi
}

iteron_validate_archive() {
    iteron_tar=$1
    iteron_root=$2
    iteron_members=$3
    iteron_verbose=$4
    iteron_expected=$5
    iteron_sorted_members=$6
    iteron_sorted_expected=$7

    tar -tf "$iteron_tar" > "$iteron_members" \
        || iteron_die 'release archive cannot be listed'
    tar -tvf "$iteron_tar" > "$iteron_verbose" \
        || iteron_die 'release archive metadata cannot be inspected'

    # A release archive is deliberately tiny and exact. Matching the complete
    # member set rejects absolute paths, dot-dot traversal, duplicates, hidden
    # payloads, and unexpected files before extraction.
    {
        printf '%s/\n' "$iteron_root"
        printf '%s/%s\n' "$iteron_root" iteron
        printf '%s/%s\n' "$iteron_root" LICENSE
        printf '%s/%s\n' "$iteron_root" README.md
        printf '%s/%s\n' "$iteron_root" THIRD_PARTY_LICENSES.html
        printf '%s/%s\n' "$iteron_root" THIRD_PARTY_NOTICES.txt
        printf '%s/%s\n' "$iteron_root" SBOM.spdx.json
        printf '%s/%s\n' "$iteron_root" BUILD-INFO.json
    } > "$iteron_expected"

    iteron_member_count=$(wc -l < "$iteron_members" | tr -d '[:space:]')
    [ "$iteron_member_count" = 8 ] \
        || iteron_die 'release archive has an unexpected member count'

    LC_ALL=C sort "$iteron_members" > "$iteron_sorted_members"
    LC_ALL=C sort "$iteron_expected" > "$iteron_sorted_expected"
    cmp -s "$iteron_sorted_members" "$iteron_sorted_expected" \
        || iteron_die 'release archive contains an unexpected path'

    # GNU tar and BSD tar both put the entry type at the first character of
    # their verbose mode column. Only directories and regular files are valid.
    awk '
        substr($1, 1, 1) != "d" && substr($1, 1, 1) != "-" { exit 1 }
    ' "$iteron_verbose" \
        || iteron_die 'release archive contains a link or special file'
}

iteron_main() {
    set -eu

    iteron_version=$ITERON_EMBEDDED_VERSION
    iteron_bin_dir=${ITERON_INSTALL_DIR:-${ITERON_CODE_INSTALL_DIR:-}}
    if [ -z "${ITERON_INSTALL_DIR:-}" ] && [ -n "${ITERON_CODE_INSTALL_DIR:-}" ]; then
        iteron_warn 'ITERON_CODE_INSTALL_DIR is deprecated; use ITERON_INSTALL_DIR'
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || iteron_die '--version requires a value'
                iteron_version=$2
                shift 2
                ;;
            --bin-dir)
                [ "$#" -ge 2 ] || iteron_die '--bin-dir requires a value'
                iteron_bin_dir=$2
                shift 2
                ;;
            -h|--help)
                iteron_usage
                exit 0
                ;;
            --)
                shift
                [ "$#" -eq 0 ] || iteron_die 'positional arguments are not supported'
                ;;
            *)
                iteron_die "unknown option: $1"
                ;;
        esac
    done

    printf '%s\n' "$iteron_version" \
        | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
        || iteron_die 'version must be an exact stable tag such as v0.0.1'

    if [ -z "$iteron_bin_dir" ]; then
        if [ -n "${XDG_BIN_HOME:-}" ]; then
            iteron_bin_dir=$XDG_BIN_HOME
        else
            [ -n "${HOME:-}" ] || iteron_die 'HOME is not set; pass --bin-dir'
            iteron_bin_dir=$HOME/.local/bin
        fi
    fi
    [ -n "$iteron_bin_dir" ] || iteron_die 'installation directory is empty'

    iteron_require curl
    iteron_require tar
    iteron_require awk
    iteron_require cmp
    iteron_require chmod
    iteron_require grep
    iteron_require gzip
    iteron_require install
    iteron_require mkdir
    iteron_require mktemp
    iteron_require mv
    iteron_require rm
    iteron_require sort
    iteron_require tr
    iteron_require uname
    iteron_require wc

    iteron_os=$(uname -s)
    iteron_arch=$(uname -m)
    case "$iteron_os:$iteron_arch" in
        Darwin:arm64|Darwin:aarch64)
            iteron_target=aarch64-apple-darwin
            ;;
        Linux:aarch64|Linux:arm64)
            iteron_target=aarch64-unknown-linux-musl
            ;;
        Linux:x86_64|Linux:amd64)
            iteron_target=x86_64-unknown-linux-musl
            ;;
        *)
            iteron_die "unsupported platform: $iteron_os $iteron_arch"
            ;;
    esac

    iteron_version_number=${iteron_version#v}
    iteron_archive_root="iteron-${iteron_version}-${iteron_target}"
    iteron_archive_name="${iteron_archive_root}.tar.gz"
    iteron_base_url="${ITERON_RELEASE_ROOT}/${iteron_version}"

    iteron_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/iteron.XXXXXXXX") \
        || iteron_die 'could not create a temporary directory'
    iteron_install_tmp=
    iteron_cleanup() {
        if [ -n "${iteron_install_tmp:-}" ]; then
            rm -f -- "$iteron_install_tmp"
        fi
        rm -rf -- "$iteron_work_dir"
    }
    trap iteron_cleanup 0
    trap 'exit 1' HUP INT TERM
    umask 077

    iteron_checksums="$iteron_work_dir/SHA256SUMS"
    iteron_archive="$iteron_work_dir/$iteron_archive_name"
    iteron_note "downloading Iteron $iteron_version_number for $iteron_target"
    iteron_download \
        "$iteron_base_url/SHA256SUMS" \
        "$iteron_checksums" \
        "$ITERON_MAX_MANIFEST_BYTES" \
        || iteron_die 'could not download SHA256SUMS'
    iteron_manifest_size=$(iteron_file_size "$iteron_checksums")
    if [ "$iteron_manifest_size" -le 0 ] \
        || [ "$iteron_manifest_size" -gt "$ITERON_MAX_MANIFEST_BYTES" ]; then
        iteron_die 'SHA256SUMS is empty or unexpectedly large'
    fi

    iteron_download \
        "$iteron_base_url/$iteron_archive_name" \
        "$iteron_archive" \
        "$ITERON_MAX_ARCHIVE_BYTES" \
        || iteron_die "could not download $iteron_archive_name"
    iteron_archive_size=$(iteron_file_size "$iteron_archive")
    if [ "$iteron_archive_size" -le 0 ] \
        || [ "$iteron_archive_size" -gt "$ITERON_MAX_ARCHIVE_BYTES" ]; then
        iteron_die 'release archive is empty or unexpectedly large'
    fi

    iteron_note 'verifying release archive'
    iteron_checksum_rows=$(awk -v name="$iteron_archive_name" '
        $2 == name || $2 == "*" name { print $1 }
    ' "$iteron_checksums")
    iteron_checksum_count=$(printf '%s\n' "$iteron_checksum_rows" \
        | awk 'NF { count += 1 } END { print count + 0 }')
    [ "$iteron_checksum_count" -eq 1 ] \
        || iteron_die 'SHA256SUMS must contain exactly one archive digest'
    iteron_expected_digest=$(printf '%s\n' "$iteron_checksum_rows" | awk 'NF { print; exit }')
    printf '%s\n' "$iteron_expected_digest" | grep -Eq '^[0-9a-f]{64}$' \
        || iteron_die 'archive digest is malformed'
    iteron_actual_digest=$(iteron_sha256 "$iteron_archive")
    [ "$iteron_actual_digest" = "$iteron_expected_digest" ] \
        || iteron_die 'archive checksum verification failed'

    iteron_unpacked="$iteron_work_dir/archive.tar"
    iteron_unpack_archive "$iteron_archive" "$iteron_unpacked"
    iteron_validate_archive \
        "$iteron_unpacked" \
        "$iteron_archive_root" \
        "$iteron_work_dir/members" \
        "$iteron_work_dir/verbose" \
        "$iteron_work_dir/expected" \
        "$iteron_work_dir/members.sorted" \
        "$iteron_work_dir/expected.sorted"

    mkdir "$iteron_work_dir/extract"
    tar -xf "$iteron_unpacked" -C "$iteron_work_dir/extract" \
        || iteron_die 'release archive extraction failed'
    iteron_binary="$iteron_work_dir/extract/$iteron_archive_root/iteron"
    if [ ! -f "$iteron_binary" ] || [ -L "$iteron_binary" ]; then
        iteron_die 'archive iteron entry is not a regular file'
    fi
    chmod 0755 "$iteron_binary"

    # `-V` is the bare `iteron <semver>`; `--version` additionally carries the commit and build date,
    # so the exact-match smoke tests below deliberately use the short form.
    iteron_reported_version=$("$iteron_binary" -V 2>&1) \
        || iteron_die 'downloaded binary failed its version smoke test'
    [ "$iteron_reported_version" = "iteron $iteron_version_number" ] \
        || iteron_die "downloaded binary reported an unexpected version: $iteron_reported_version"

    mkdir -p -- "$iteron_bin_dir" \
        || iteron_die "could not create installation directory: $iteron_bin_dir"
    [ -d "$iteron_bin_dir" ] \
        || iteron_die "installation path is not a directory: $iteron_bin_dir"
    [ ! -d "$iteron_bin_dir/iteron" ] \
        || iteron_die 'installation destination is a directory'
    iteron_note 'installing verified binary'
    iteron_install_tmp=$(mktemp "$iteron_bin_dir/.iteron.new.XXXXXXXX") \
        || iteron_die 'could not create an atomic installation staging file'
    install -m 0755 "$iteron_binary" "$iteron_install_tmp" \
        || iteron_die 'could not stage the installed binary'
    if [ ! -f "$iteron_install_tmp" ] || [ -L "$iteron_install_tmp" ]; then
        iteron_die 'staged installation is not a regular file'
    fi
    iteron_staged_version=$("$iteron_install_tmp" -V 2>&1) \
        || iteron_die 'staged binary failed its version smoke test'
    [ "$iteron_staged_version" = "iteron $iteron_version_number" ] \
        || iteron_die 'staged binary reported an unexpected version'
    mv -f -- "$iteron_install_tmp" "$iteron_bin_dir/iteron" \
        || iteron_die 'could not atomically install iteron'
    if [ ! -f "$iteron_bin_dir/iteron" ] || [ -L "$iteron_bin_dir/iteron" ]; then
        iteron_die 'atomic install did not produce a regular destination file'
    fi
    iteron_installed_version=$("$iteron_bin_dir/iteron" -V 2>&1) \
        || iteron_die 'installed binary failed its final version smoke test'
    [ "$iteron_installed_version" = "iteron $iteron_version_number" ] \
        || iteron_die 'installed binary reported an unexpected final version'
    iteron_install_tmp=

    printf 'Iteron %s installed at %s/iteron\n' "$iteron_version_number" "$iteron_bin_dir"
    case ":${PATH:-}:" in
        *:"$iteron_bin_dir":*) ;;
        *) printf 'Add %s to PATH to run the iteron command.\n' "$iteron_bin_dir" ;;
    esac
    iteron_linux_preflight "$iteron_os"
}

iteron_main "$@"

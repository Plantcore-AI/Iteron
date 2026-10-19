#!/bin/sh
# Iteron release installer. Release packaging replaces the marker below with
# an immutable tag such as v0.0.1. Keep the entire mutating path behind main so
# a truncated `curl | sh` stream cannot perform a partial installation.

ITERON_EMBEDDED_VERSION='@ITERON_VERSION@'
ITERON_RELEASE_ROOT='https://github.com/Plantcore-AI/Iteron/releases/download'
ITERON_MAX_MANIFEST_BYTES=1048576
ITERON_MAX_ARCHIVE_BYTES=268435456
ITERON_MAX_UNPACKED_BYTES=268435456

iteron_usage() {
    cat <<'EOF'
Install Iteron from an immutable GitHub release.

Usage:
  install.sh [--version vX.Y.Z] [--bin-dir PATH]
  install.sh --rollback [--bin-dir PATH]

Options:
  --version VERSION  Install an exact release tag. The release asset embeds its
                     own version, so this is optional for normal curl installs.
  --bin-dir PATH     Install the `iteron` command into PATH. Defaults to
                     $ITERON_INSTALL_DIR, legacy $ITERON_CODE_INSTALL_DIR,
                     $XDG_BIN_HOME, or ~/.local/bin.
  --rollback         Restore the previous executables without downloading.
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
        iteron_warn 'Linux --confine code execution (bash/build/test) is unavailable: bubblewrap is not installed'
        cat <<'EOF' >&2
The default unconfined mode does not require bubblewrap. To use `iteron --confine`,
install bubblewrap with the appropriate package manager:
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

    iteron_warn "Linux --confine code execution (bash/build/test) is unavailable: $iteron_bwrap cannot create the required namespaces"
    cat <<EOF >&2
The default unconfined mode is unaffected. To use --confine, check the namespace
failure first. On Ubuntu 24.04, an AppArmor user-namespace restriction can cause
this failure; if that restriction is confirmed, grant access to this one binary:
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

iteron_expected_members() {
    iteron_root=$1
    iteron_expected=$2
    # A release archive is deliberately tiny and exact. Matching the complete
    # member set rejects absolute paths, dot-dot traversal, duplicates, hidden
    # payloads, and unexpected files before extraction.
    {
        printf '%s/\n' "$iteron_root"
        printf '%s/%s\n' "$iteron_root" iteron
        printf '%s/%s\n' "$iteron_root" iteron-workspace-hook
        printf '%s/%s\n' "$iteron_root" LICENSE
        printf '%s/%s\n' "$iteron_root" README.md
        printf '%s/%s\n' "$iteron_root" THIRD_PARTY_LICENSES.html
        printf '%s/%s\n' "$iteron_root" THIRD_PARTY_NOTICES.txt
        printf '%s/%s\n' "$iteron_root" SBOM.spdx.json
        printf '%s/%s\n' "$iteron_root" BUILD-INFO.json
        for iteron_contract in \
            README.md \
            app-server-v5.schema.json \
            check-app-server-v5.py \
            check-workspace-hook.py \
            check_machine_contract.py \
            examples/app-server-v5-bootstrap-reply.json \
            examples/app-server-v5-bootstrap.json \
            examples/app-server-v5-command-reply.json \
            examples/app-server-v5-command.json \
            examples/app-server-v5-invalid-bootstrap.json \
            examples/app-server-v5-invalid-session.json \
            examples/app-server-v5-listening.json \
            examples/app-server-v5-pause-command-reply.json \
            examples/app-server-v5-pause-command.json \
            examples/app-server-v5-resume-command-reply.json \
            examples/app-server-v5-resume-command.json \
            examples/app-server-v5-resume-terminal-command-reply.json \
            examples/app-server-v5-resume-terminal-command.json \
            examples/machine-contract-v1.json \
            examples/workspace-hook-allow.json \
            examples/workspace-hook-deny.json \
            iteron-output-v7.schema.json \
            machine-contract.schema.json \
            test-vectors/portable-canonical-json-v1.json \
            workspace-hook-v1.schema.json \
            workspace-tools-v1.json
        do
            printf '%s/contracts/plantcore/%s\n' "$iteron_root" "$iteron_contract"
        done
    } > "$iteron_expected"

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

    iteron_expected_members "$iteron_root" "$iteron_expected"
    if [ "$iteron_manual" = 1 ]; then
        printf '%s/STANDALONE-PERSISTENCE.md\n%s/machine-contract.json\n' "$iteron_root" "$iteron_root" >> "$iteron_expected"
    fi
    iteron_has_server=0
    if grep -Fxq "$iteron_root/iteron-app-server" "$iteron_members"; then
        iteron_has_server=1
        printf '%s/iteron-app-server\n' "$iteron_root" >> "$iteron_expected"
    fi
    if printf '%s\n' "$iteron_version_number" | awk -F. '{ exit !($1 > 0 || $2 > 0 || $3 >= 30) }'; then
        [ "$iteron_has_server" = 1 ] \
            || iteron_die 'release v0.0.30 and later must include iteron-app-server'
    fi

    iteron_member_count=$(wc -l < "$iteron_members" | tr -d '[:space:]')
    iteron_expected_count=$(wc -l < "$iteron_expected" | tr -d '[:space:]')
    [ "$iteron_member_count" = "$iteron_expected_count" ] \
        || iteron_die 'release archive has an unexpected member count'

    LC_ALL=C sort "$iteron_members" > "$iteron_sorted_members"
    LC_ALL=C sort "$iteron_expected" > "$iteron_sorted_expected"
    cmp -s "$iteron_sorted_members" "$iteron_sorted_expected" \
        || iteron_die 'release archive contains an unexpected path'

    # Only the root directory and regular files are accepted, except the
    # manual package's one fixed Hook -> iteron hardlink. Both GNU and BSD tar
    # print that link as "<path> link to <target>". No symlink is accepted.
    awk -v root="$iteron_root" -v manual="$iteron_manual" '
        substr($1, 1, 1) == "d" { if ($NF != root "/") exit 1; next }
        substr($1, 1, 1) == "-" { next }
        manual == 1 && substr($1, 1, 1) == "h" &&
            $(NF-3) == root "/iteron-workspace-hook" && $(NF-2) == "link" &&
            $(NF-1) == "to" && $NF == root "/iteron" { next }
        { exit 1 }
    ' "$iteron_verbose" \
        || iteron_die 'release archive contains an unsupported link or special file'

}

iteron_verify_checksum() {
    iteron_sum=$(awk -v name="$2" '$2 == name || $2 == "*" name { print $1; count++ } END { if (count != 1) exit 1 }' "$1") \
        || iteron_die 'SHA256SUMS must contain exactly one digest for each selected asset'
    printf '%s\n' "$iteron_sum" | grep -Eq '^[0-9a-f]{64}$' \
        || iteron_die 'asset digest is malformed'
    [ "$(iteron_sha256 "$3")" = "$iteron_sum" ] || iteron_die 'asset checksum verification failed'
}

iteron_assert_destination() {
    if [ ! -f "$1" ] || [ -L "$1" ]; then iteron_die "destination is not a regular file: $1"; fi
}

iteron_check_backup() {
    if [ ! -d "$1" ] || [ -L "$1" ]; then iteron_die 'previous installation is not a plain directory'; fi
    if [ ! -f "$1/format" ] || [ -L "$1/format" ] || [ "$(cat "$1/format")" != iteron-installer-v1 ]; then
        iteron_die 'previous installation has an invalid format marker'
    fi
    for iteron_saved in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        [ -e "$iteron_saved" ] || [ -L "$iteron_saved" ] || continue
        case "${iteron_saved##*/}" in
            format|iteron|iteron-workspace-hook|iteron-app-server) iteron_assert_destination "$iteron_saved" ;;
            *) iteron_die 'previous installation contains an unexpected file' ;;
        esac
    done
}

# Every executable is copied before mutation. Recovery restores missing members
# as missing, including AppServer when rolling back to an older release.
iteron_restore_pair() {
    [ -d "$1" ] && [ -f "$1/format" ] || return 1
    for iteron_restore_name in iteron iteron-workspace-hook iteron-app-server; do
        iteron_restore_target="$2/$iteron_restore_name"
        if [ -d "$iteron_restore_target" ] || [ -L "$iteron_restore_target" ]; then return 1; fi
        if [ -f "$1/$iteron_restore_name" ]; then
            iteron_restore_tmp=$(mktemp "$2/.iteron.restore.XXXXXXXX") || return 1
            cp -p -- "$1/$iteron_restore_name" "$iteron_restore_tmp" || return 1
            mv -f -- "$iteron_restore_tmp" "$iteron_restore_target" || return 1
            [ -f "$iteron_restore_target" ] && [ ! -L "$iteron_restore_target" ] || return 1
        else
            rm -f -- "$iteron_restore_target" || return 1
        fi
    done
}

iteron_begin_transaction() {
    mkdir -p -- "$1" || iteron_die 'could not create installation directory'
    mkdir -- "$1/.iteron-install.lock" 2>/dev/null \
        || iteron_die 'another installation is active, or .iteron-install.lock needs recovery'
    iteron_lock="$1/.iteron-install.lock"
    if [ -e "$1/.iteron-previous" ] || [ -L "$1/.iteron-previous" ]; then
        iteron_check_backup "$1/.iteron-previous"
    fi
    iteron_transaction=$(mktemp -d "$1/.iteron-transaction.XXXXXXXX")
    printf 'iteron-installer-v1\n' > "$iteron_transaction/format"
    for iteron_backup_name in iteron iteron-workspace-hook iteron-app-server; do
        if [ -e "$1/$iteron_backup_name" ] || [ -L "$1/$iteron_backup_name" ]; then
            iteron_assert_destination "$1/$iteron_backup_name"
            cp -p -- "$1/$iteron_backup_name" "$iteron_transaction/$iteron_backup_name"
        fi
    done
}

iteron_finish_transaction() {
    # Keep one previous installation. The private backup is checked before any
    # removal, and concurrent installers share the same directory lock.
    if [ -d "$iteron_bin_dir/.iteron-previous" ]; then
        rm -rf -- "$iteron_bin_dir/.iteron-previous"
    fi
    if [ -f "$iteron_transaction/iteron" ]; then
        mv -- "$iteron_transaction" "$iteron_bin_dir/.iteron-previous" \
            || iteron_die 'could not retain the previous installation'
        iteron_changed=0
        iteron_transaction=
    fi
    iteron_changed=0
}

iteron_restore_previous() {
    iteron_bin_dir=$1
    iteron_check_backup "$iteron_bin_dir/.iteron-previous"
    iteron_transaction=
    iteron_lock=
    iteron_changed=0
    # shellcheck disable=SC2317 # Invoked through the EXIT trap below.
    iteron_rollback_cleanup() {
        if [ "$iteron_changed" = 1 ]; then
            if ! iteron_restore_pair "$iteron_transaction" "$iteron_bin_dir"; then
                iteron_warn "rollback recovery failed; files retained at $iteron_transaction"
                iteron_transaction=
            fi
        fi
        if [ -n "$iteron_transaction" ]; then rm -rf -- "$iteron_transaction"; fi
        if [ -n "$iteron_lock" ]; then rmdir -- "$iteron_lock"; fi
    }
    trap iteron_rollback_cleanup 0
    trap 'exit 1' HUP INT TERM
    umask 077
    iteron_begin_transaction "$iteron_bin_dir"
    iteron_changed=1
    iteron_restore_pair "$iteron_bin_dir/.iteron-previous" "$iteron_bin_dir" \
        || iteron_die 'could not restore the previous installation'
    iteron_restored_version=$("$iteron_bin_dir/iteron" -V 2>&1) \
        || iteron_die 'restored executable failed its version smoke test'
    if [ -f "$iteron_bin_dir/iteron-app-server" ]; then
        iteron_restored_server_version=$("$iteron_bin_dir/iteron-app-server" -V 2>&1) \
            || iteron_die 'restored AppServer failed its version smoke test'
        [ "$iteron_restored_server_version" = "iteron-app-server ${iteron_restored_version#iteron }" ] \
            || iteron_die 'restored AppServer reported a mismatched version'
    fi
    printf '%s\n' "$iteron_restored_version"
    iteron_finish_transaction
    printf 'Previous Iteron installation restored at %s\n' "$iteron_bin_dir"
}

iteron_main() {
    set -eu

    iteron_version=$ITERON_EMBEDDED_VERSION
    iteron_rollback=0
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
            --rollback)
                iteron_rollback=1
                shift
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

    if [ "$iteron_rollback" = 0 ]; then
    printf '%s\n' "$iteron_version" \
        | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
        || iteron_die 'version must be an exact stable tag such as v0.0.1'
    fi

    if [ -z "$iteron_bin_dir" ]; then
        if [ -n "${XDG_BIN_HOME:-}" ]; then
            iteron_bin_dir=$XDG_BIN_HOME
        else
            [ -n "${HOME:-}" ] || iteron_die 'HOME is not set; pass --bin-dir'
            iteron_bin_dir=$HOME/.local/bin
        fi
    fi
    [ -n "$iteron_bin_dir" ] || iteron_die 'installation directory is empty'

    if [ "$iteron_rollback" = 1 ]; then
        iteron_restore_previous "$iteron_bin_dir"
        exit 0
    fi

    iteron_require curl
    iteron_require tar
    iteron_require awk
    iteron_require cmp
    iteron_require cp
    iteron_require rmdir
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
    iteron_hook_install_tmp=
    iteron_transaction=
    iteron_changed=0
    iteron_lock=
    iteron_cleanup() {
        if [ "$iteron_changed" = 1 ]; then
            if ! iteron_restore_pair "$iteron_transaction" "$iteron_bin_dir"; then
                iteron_warn "automatic recovery failed; previous files retained at $iteron_transaction"
                iteron_transaction=
            fi
        fi
        if [ -n "$iteron_transaction" ]; then rm -rf -- "$iteron_transaction"; fi
        if [ -n "$iteron_lock" ]; then rmdir -- "$iteron_lock"; fi
        if [ -n "${iteron_server_install_tmp:-}" ]; then
            rm -f -- "$iteron_server_install_tmp"
        fi
        if [ -n "${iteron_install_tmp:-}" ]; then
            rm -f -- "$iteron_install_tmp"
        fi
        if [ -n "${iteron_hook_install_tmp:-}" ]; then
            rm -f -- "$iteron_hook_install_tmp"
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

    # A checksum-listed manual manifest explicitly selects the documented
    # manual package family. Archive identity is bound by the selected tag,
    # target, full SHA256SUMS row and exact complete member set below.
    iteron_manual=0
    if awk '$2 == "manual-release-manifest.json" || $2 == "*manual-release-manifest.json" { found=1 } END { exit !found }' "$iteron_checksums"; then
        iteron_manual=1
        iteron_download "$iteron_base_url/manual-release-manifest.json" \
            "$iteron_work_dir/manual-release-manifest.json" "$ITERON_MAX_MANIFEST_BYTES" \
            || iteron_die 'could not download the declared manual release manifest'
        iteron_verify_checksum "$iteron_checksums" manual-release-manifest.json "$iteron_work_dir/manual-release-manifest.json"
    fi
    iteron_unpacked="$iteron_work_dir/archive.tar"
    iteron_unpack_archive "$iteron_archive" "$iteron_unpacked"
    iteron_validate_archive "$iteron_unpacked" "$iteron_archive_root" \
        "$iteron_work_dir/members" "$iteron_work_dir/verbose" "$iteron_work_dir/expected" \
        "$iteron_work_dir/members.sorted" "$iteron_work_dir/expected.sorted"
    mkdir "$iteron_work_dir/extract"
    tar -xf "$iteron_unpacked" -C "$iteron_work_dir/extract" \
        || iteron_die 'release archive extraction failed'
    iteron_binary="$iteron_work_dir/extract/$iteron_archive_root/iteron"
    iteron_workspace_hook="$iteron_work_dir/extract/$iteron_archive_root/iteron-workspace-hook"
    if [ ! -f "$iteron_binary" ] || [ -L "$iteron_binary" ]; then
        iteron_die 'archive iteron entry is not a regular file'
    fi
    if [ ! -f "$iteron_workspace_hook" ] || [ -L "$iteron_workspace_hook" ]; then
        iteron_die 'archive iteron-workspace-hook entry is not a regular file'
    fi
    chmod 0755 "$iteron_binary"
    chmod 0755 "$iteron_workspace_hook"

    # `-V` is the bare `iteron <semver>`; `--version` additionally carries the commit and build date,
    # so the exact-match smoke tests below deliberately use the short form.
    iteron_reported_version=$("$iteron_binary" -V 2>&1) \
        || iteron_die 'downloaded binary failed its version smoke test'
    [ "$iteron_reported_version" = "iteron $iteron_version_number" ] \
        || iteron_die "downloaded binary reported an unexpected version: $iteron_reported_version"

    iteron_begin_transaction "$iteron_bin_dir"
    iteron_server_install_tmp=
    iteron_note 'installing verified executables'
    if [ "$iteron_has_server" = 1 ]; then
        iteron_server="$iteron_work_dir/extract/$iteron_archive_root/iteron-app-server"
        iteron_assert_destination "$iteron_server"
        chmod 0755 "$iteron_server"
        iteron_server_version=$("$iteron_server" -V 2>&1) \
            || iteron_die 'AppServer binary failed its version smoke test'
        [ "$iteron_server_version" = "iteron-app-server $iteron_version_number" ] \
            || iteron_die 'AppServer binary reported an unexpected version'
        iteron_server_install_tmp=$(mktemp "$iteron_bin_dir/.iteron-app-server.new.XXXXXXXX")
        install -m 0755 "$iteron_server" "$iteron_server_install_tmp"
    fi
    iteron_install_tmp=$(mktemp "$iteron_bin_dir/.iteron.new.XXXXXXXX")
    iteron_hook_install_tmp=$(mktemp "$iteron_bin_dir/.iteron-workspace-hook.new.XXXXXXXX")
    install -m 0755 "$iteron_binary" "$iteron_install_tmp"
    install -m 0755 "$iteron_workspace_hook" "$iteron_hook_install_tmp"
    iteron_staged_version=$("$iteron_install_tmp" -V 2>&1) \
        || iteron_die 'staged binary failed its version smoke test'
    [ "$iteron_staged_version" = "iteron $iteron_version_number" ] \
        || iteron_die 'staged binary reported an unexpected version'
    iteron_changed=1
    if [ "$iteron_has_server" = 1 ]; then
        mv -f -- "$iteron_server_install_tmp" "$iteron_bin_dir/iteron-app-server" \
            || iteron_die 'could not install iteron-app-server'
        iteron_assert_destination "$iteron_bin_dir/iteron-app-server"
        iteron_server_install_tmp=
    elif [ -e "$iteron_bin_dir/iteron-app-server" ]; then
        rm -f -- "$iteron_bin_dir/iteron-app-server"
    fi
    mv -f -- "$iteron_hook_install_tmp" "$iteron_bin_dir/iteron-workspace-hook" \
        || iteron_die 'could not install iteron-workspace-hook'
    iteron_assert_destination "$iteron_bin_dir/iteron-workspace-hook"
    iteron_hook_install_tmp=
    mv -f -- "$iteron_install_tmp" "$iteron_bin_dir/iteron" \
        || iteron_die 'could not install iteron'
    iteron_assert_destination "$iteron_bin_dir/iteron"
    iteron_install_tmp=
    iteron_installed_version=$("$iteron_bin_dir/iteron" -V 2>&1) \
        || iteron_die 'installed binary failed its final version smoke test'
    [ "$iteron_installed_version" = "iteron $iteron_version_number" ] \
        || iteron_die 'installed binary reported an unexpected final version'
    if [ "$iteron_has_server" = 1 ]; then
        iteron_installed_server_version=$("$iteron_bin_dir/iteron-app-server" -V 2>&1) \
            || iteron_die 'installed AppServer failed its final version smoke test'
        [ "$iteron_installed_server_version" = "iteron-app-server $iteron_version_number" ] \
            || iteron_die 'installed AppServer reported an unexpected final version'
    fi
    iteron_finish_transaction

    printf 'Iteron %s installed at %s/iteron\n' "$iteron_version_number" "$iteron_bin_dir"
    case ":${PATH:-}:" in
        *:"$iteron_bin_dir":*) ;;
        *) printf 'Add %s to PATH to run the iteron command.\n' "$iteron_bin_dir" ;;
    esac
    iteron_linux_preflight "$iteron_os"
}

iteron_main "$@"

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/core-install-test.XXXXXXXX")
trap 'rm -rf "$temporary"' EXIT

case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
  Darwin:x86_64|Darwin:amd64) target=x86_64-apple-darwin ;;
  Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl ;;
  Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-musl ;;
  *) printf 'unsupported test host\n' >&2; exit 1 ;;
esac

fixture=$temporary/fixture
mkdir -p "$fixture" "$temporary/fakebin"

# `-V` is the bare `iteron <semver>` the installer's smoke tests match exactly; `--version` adds the
# commit and build date, so a real binary's long form is deliberately not an exact-match target.
cat > "$temporary/fake-core" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -V) printf 'iteron 0.0.1\n' ;;
  --version) printf 'iteron 0.0.1 (0123456789abcdef0123456789abcdef01234567 2026-08-03)\n' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$temporary/fake-core"

printf 'Apache License 2.0\n' > "$temporary/LICENSE"
printf '# Iteron\n' > "$temporary/README.md"
printf '<html><body>%0300d</body></html>\n' 0 > "$temporary/THIRD_PARTY_LICENSES.html"
printf 'Iteron third-party notices\n' > "$temporary/THIRD_PARTY_NOTICES.txt"
printf '{}\n' > "$temporary/SBOM.spdx.json"
printf '{}\n' > "$temporary/BUILD-INFO.json"

python3 "$repo_root/release-tools/package.py" \
  --binary "$temporary/fake-core" \
  --license "$temporary/LICENSE" \
  --readme "$temporary/README.md" \
  --licenses "$temporary/THIRD_PARTY_LICENSES.html" \
  --notices "$temporary/THIRD_PARTY_NOTICES.txt" \
  --sbom "$temporary/SBOM.spdx.json" \
  --build-info "$temporary/BUILD-INFO.json" \
  --version 0.0.1 \
  --target "$target" \
  --source-date-epoch 1700000000 \
  --output-dir "$fixture" >/dev/null

archive="iteron-v0.0.1-${target}.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$fixture/$archive" | sed "s#  .*/#  #" > "$fixture/SHA256SUMS"
else
  shasum -a 256 "$fixture/$archive" | sed "s#  .*/#  #" > "$fixture/SHA256SUMS"
fi

cat > "$temporary/fakebin/curl" <<'EOF'
#!/bin/sh
set -eu
destination=
max_filesize=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) destination=$2; shift 2 ;;
    --max-filesize) max_filesize=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
[ -n "$destination" ] && [ -n "$url" ]
name=${url##*/}
case "$name" in
  SHA256SUMS) [ "$max_filesize" = 1048576 ] ;;
  *.tar.gz) [ "$max_filesize" = 268435456 ] ;;
  *) exit 3 ;;
esac
cp "$ITERON_CODE_TEST_FIXTURE/$name" "$destination"
if [ "${ITERON_CODE_TEST_TAMPER:-0}" = 1 ] && [ "$name" != SHA256SUMS ]; then
  printf 'tamper\n' >> "$destination"
fi
EOF
chmod +x "$temporary/fakebin/curl"

cat > "$temporary/fakebin/mv" <<'EOF'
#!/bin/sh
set -eu
if [ "${ITERON_CODE_TEST_MV_RACE:-0}" = 1 ]; then
  for iteron_argument do
    iteron_source=${iteron_destination:-}
    iteron_destination=$iteron_argument
  done
  [ -n "${iteron_source:-}" ] && [ -n "${iteron_destination:-}" ]
  rm -f -- "$iteron_destination"
  mkdir "$iteron_destination"
fi
exec /bin/mv "$@"
EOF
chmod +x "$temporary/fakebin/mv"

install_dir="$temporary/install with spaces"
mkdir "$temporary/tmp with spaces"
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$fixture ITERON_CODE_VERSION=v0.0.1 \
  sh "$repo_root/install.sh" --bin-dir "$install_dir" >/dev/null 2>&1; then
  printf 'environment unexpectedly overrode the embedded installer version\n' >&2
  exit 1
fi
test ! -e "$install_dir/core"
PATH="$temporary/fakebin:$PATH" TMPDIR="$temporary/tmp with spaces" ITERON_CODE_TEST_FIXTURE=$fixture \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$install_dir" >/dev/null
test -x "$install_dir/core"
test "$("$install_dir/core" -V)" = 'iteron 0.0.1'
grep -q '0123456789abcdef' <<<"$("$install_dir/core" --version)"

printf 'existing\n' > "$install_dir/core"
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$fixture ITERON_CODE_TEST_TAMPER=1 \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$install_dir" >/dev/null 2>&1; then
  printf 'tampered archive unexpectedly installed\n' >&2
  exit 1
fi
test "$(cat "$install_dir/core")" = existing

malicious=$temporary/malicious
mkdir "$malicious"
ITERON_CODE_TEST_ARCHIVE="$malicious/$archive" ITERON_CODE_TEST_ROOT="iteron-v0.0.1-${target}" \
python3 - <<'PY'
import io
import os
import tarfile

archive = os.environ["ITERON_CODE_TEST_ARCHIVE"]
root = os.environ["ITERON_CODE_TEST_ROOT"]
with tarfile.open(archive, "w:gz") as output:
    directory = tarfile.TarInfo(root + "/")
    directory.type = tarfile.DIRTYPE
    output.addfile(directory)
    link = tarfile.TarInfo(root + "/core")
    link.type = tarfile.SYMTYPE
    link.linkname = "/bin/sh"
    output.addfile(link)
    for name in (
        "LICENSE",
        "README.md",
        "THIRD_PARTY_LICENSES.html",
        "THIRD_PARTY_NOTICES.txt",
        "SBOM.spdx.json",
        "BUILD-INFO.json",
    ):
        content = b"fixture\n"
        info = tarfile.TarInfo(root + "/" + name)
        info.size = len(content)
        output.addfile(info, io.BytesIO(content))
PY
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$malicious/$archive" | sed "s#  .*/#  #" > "$malicious/SHA256SUMS"
else
  shasum -a 256 "$malicious/$archive" | sed "s#  .*/#  #" > "$malicious/SHA256SUMS"
fi
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$malicious \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$install_dir" >/dev/null 2>&1; then
  printf 'symlink archive unexpectedly installed\n' >&2
  exit 1
fi
test "$(cat "$install_dir/core")" = existing

traversal=$temporary/traversal
mkdir "$traversal"
ITERON_CODE_TEST_ARCHIVE="$traversal/$archive" ITERON_CODE_TEST_ROOT="iteron-v0.0.1-${target}" \
python3 - <<'PY'
import io
import os
import tarfile

archive = os.environ["ITERON_CODE_TEST_ARCHIVE"]
root = os.environ["ITERON_CODE_TEST_ROOT"]
with tarfile.open(archive, "w:gz") as output:
    directory = tarfile.TarInfo(root + "/")
    directory.type = tarfile.DIRTYPE
    output.addfile(directory)
    for name in (
        "iteron",
        "LICENSE",
        "README.md",
        "THIRD_PARTY_LICENSES.html",
        "THIRD_PARTY_NOTICES.txt",
        "SBOM.spdx.json",
    ):
        content = b"fixture\n"
        info = tarfile.TarInfo(root + "/" + name)
        info.size = len(content)
        output.addfile(info, io.BytesIO(content))
    content = b"escape\n"
    traversal = tarfile.TarInfo(root + "/../BUILD-INFO.json")
    traversal.size = len(content)
    output.addfile(traversal, io.BytesIO(content))
PY
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$traversal/$archive" | sed "s#  .*/#  #" > "$traversal/SHA256SUMS"
else
  shasum -a 256 "$traversal/$archive" | sed "s#  .*/#  #" > "$traversal/SHA256SUMS"
fi
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$traversal \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$install_dir" >/dev/null 2>&1; then
  printf 'path traversal archive unexpectedly installed\n' >&2
  exit 1
fi
test "$(cat "$install_dir/core")" = existing

oversized=$temporary/oversized
mkdir "$oversized"
ITERON_CODE_TEST_ARCHIVE="$oversized/$archive" ITERON_CODE_TEST_ROOT="iteron-v0.0.1-${target}" \
python3 - <<'PY'
import io
import os
import tarfile


class ZeroReader:
    def __init__(self, remaining: int) -> None:
        self.remaining = remaining

    def read(self, size: int = -1) -> bytes:
        if self.remaining == 0:
            return b""
        amount = self.remaining if size < 0 else min(size, self.remaining)
        self.remaining -= amount
        return b"\0" * amount


archive = os.environ["ITERON_CODE_TEST_ARCHIVE"]
root = os.environ["ITERON_CODE_TEST_ROOT"]
with tarfile.open(archive, "w:gz", compresslevel=9) as output:
    directory = tarfile.TarInfo(root + "/")
    directory.type = tarfile.DIRTYPE
    output.addfile(directory)
    iteron = tarfile.TarInfo(root + "/core")
    iteron.size = 134_217_729
    output.addfile(iteron, ZeroReader(iteron.size))
    for name in (
        "LICENSE",
        "README.md",
        "THIRD_PARTY_LICENSES.html",
        "THIRD_PARTY_NOTICES.txt",
        "SBOM.spdx.json",
        "BUILD-INFO.json",
    ):
        content = b"fixture\n"
        info = tarfile.TarInfo(root + "/" + name)
        info.size = len(content)
        output.addfile(info, io.BytesIO(content))
PY
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$oversized/$archive" | sed "s#  .*/#  #" > "$oversized/SHA256SUMS"
else
  shasum -a 256 "$oversized/$archive" | sed "s#  .*/#  #" > "$oversized/SHA256SUMS"
fi
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$oversized \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$install_dir" >/dev/null 2>&1; then
  printf 'oversized unpacked archive unexpectedly installed\n' >&2
  exit 1
fi
test "$(cat "$install_dir/core")" = existing

directory_install=$temporary/directory-install
mkdir -p "$directory_install/core"
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$fixture \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$directory_install" >/dev/null 2>&1; then
  printf 'directory destination unexpectedly accepted\n' >&2
  exit 1
fi
test -d "$directory_install/core"

symlink_install=$temporary/symlink-install
mkdir -p "$symlink_install" "$temporary/directory-target"
ln -s "$temporary/directory-target" "$symlink_install/core"
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$fixture \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$symlink_install" >/dev/null 2>&1; then
  printf 'directory symlink destination unexpectedly accepted\n' >&2
  exit 1
fi
test -L "$symlink_install/core"

race_install=$temporary/race-install
mkdir "$race_install"
if PATH="$temporary/fakebin:$PATH" ITERON_CODE_TEST_FIXTURE=$fixture ITERON_CODE_TEST_MV_RACE=1 \
  sh "$repo_root/install.sh" --version v0.0.1 --bin-dir "$race_install" >/dev/null 2>&1; then
  printf 'destination directory race unexpectedly reported success\n' >&2
  exit 1
fi
test -d "$race_install/core"

printf 'installer integration tests passed\n'

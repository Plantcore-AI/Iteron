#!/usr/bin/env python3
"""Bounded installer integration checks with local downloads and synthetic payloads."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[2]
TARGETS = {('Linux', 'aarch64'): 'aarch64-unknown-linux-musl',
           ('Linux', 'x86_64'): 'x86_64-unknown-linux-musl',
           ('Darwin', 'arm64'): 'aarch64-apple-darwin'}
TARGET = TARGETS.get((platform.system(), platform.machine()))
NAMES = ('iteron', 'iteron-workspace-hook', 'iteron-app-server')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture(directory: Path, version='0.0.30', *, windows=False, mutate=None, omit_server=False):
    directory.mkdir(parents=True)
    target = 'x86_64-pc-windows-msvc' if windows else TARGET
    root = f'iteron-v{version}-{target}'
    extension = '.exe' if windows else ''
    members = {name: b'fixture\n' for name in ('LICENSE', 'README.md',
        'THIRD_PARTY_LICENSES.html', 'THIRD_PARTY_NOTICES.txt', 'SBOM.spdx.json',
        'BUILD-INFO.json', 'STANDALONE-PERSISTENCE.md', 'machine-contract.json')}
    contracts = REPO / 'contracts/plantcore'
    for source in contracts.rglob('*'):
        if source.is_file() and source.suffix in ('.json', '.py', '.md'):
            members[f'contracts/plantcore/{source.relative_to(contracts)}'] = source.read_bytes()
    for name in NAMES:
        if name == 'iteron-app-server' and (version == '0.0.29' or omit_server):
            continue
        reported = 'iteron-app-server' if name == 'iteron-app-server' else 'iteron'
        members[name + extension] = (f'#!/bin/sh\n'
            'if [ "${ITERON_TEST_FAIL_INSTALLED:-}" = "$0" ]; then exit 9; fi\n'
            f"printf '{reported} {version}\\n'\n").encode()
    metadata = {}
    for name, data in members.items():
        metadata[name] = {'type': 'file', 'sha256': digest(data), 'bytes': len(data)}
    archive = directory / (root + ('.zip' if windows else '.tar.gz'))
    if windows:
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out:
            for name, data in members.items():
                out.writestr(f'{root}/{name}', data)
    else:
        with tarfile.open(archive, 'w:gz') as out:
            info = tarfile.TarInfo(root + '/')
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            out.addfile(info)
            for name, data in members.items():
                info = tarfile.TarInfo(f'{root}/{name}')
                info.mode = 0o755 if name in NAMES else 0o644
                if name == 'iteron-workspace-hook':
                    info.type = tarfile.LNKTYPE
                    info.linkname = root + '/iteron'
                else:
                    info.size = len(data)
                if mutate:
                    mutate(info, name, root)
                out.addfile(info, io.BytesIO(data) if info.isfile() else None)
    manifest = {'type': 'iteron_manual_release_manifest', 'schema_version': 3,
                'tag': f'v{version}', 'source_commit': 'a' * 40,
                'targets': {target: {'archive': {'name': archive.name,
                    'bytes': archive.stat().st_size, 'sha256': digest(archive.read_bytes())},
                    'files': metadata}}}
    (directory / 'manual-release-manifest.json').write_text(json.dumps(manifest))
    sums(directory)
    return archive


def sums(directory):
    (directory / 'SHA256SUMS').write_text(''.join(
        f'{digest(path.read_bytes())}  {path.name}\n' for path in sorted(directory.iterdir())
        if path.is_file() and path.name != 'SHA256SUMS'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, help='also install an actual native release archive')
    parser.add_argument('--release-version', default='0.0.29', help='version number for --release-dir')
    parser.add_argument('--windows-fixtures', type=Path, help='only write mocked Windows fixtures')
    args = parser.parse_args()
    if args.windows_fixtures:
        fixture(args.windows_fixtures / 'v0.0.29', '0.0.29', windows=True)
        fixture(args.windows_fixtures / 'v0.0.30', windows=True)
        return
    if TARGET is None:
        raise SystemExit('unsupported native test host')
    with tempfile.TemporaryDirectory(prefix='iteron-installer-') as temporary:
        work = Path(temporary)
        fakebin = work / 'mock bin'
        fakebin.mkdir()
        (fakebin / 'curl').write_text('''#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
 case "$1" in
 --output) output=$2; shift 2 ;;
 https://github.com/Plantcore-AI/Iteron/releases/download/*) url=$1; shift ;;
 *) shift ;;
 esac
done
cp "$ITERON_TEST_FIXTURE/${url##*/}" "$output"
''')
        (fakebin / 'mv').write_text('''#!/bin/sh
set -eu
if [ -n "${ITERON_TEST_FAIL_MOVE:-}" ]; then
 case "$*" in *'.iteron.new.'*)
  if [ ! -e "$ITERON_TEST_FAIL_MOVE" ]; then touch "$ITERON_TEST_FAIL_MOVE"; exit 1; fi ;;
 esac
fi
exec /bin/mv "$@"
''')
        for path in fakebin.iterdir():
            path.chmod(0o755)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'])
        old = work / 'old'
        new = work / 'new'
        fixture(old, '0.0.29')
        archive = fixture(new)
        destination = work / 'install with spaces'
        count = 0

        def run(source, version='0.0.30', *, succeeds=True, rollback=False, extra=None):
            nonlocal count
            command = ['sh', str(REPO / 'install.sh'), '--bin-dir', str(destination)]
            command += ['--rollback'] if rollback else ['--version', 'v' + version]
            result = subprocess.run(command, env=dict(env, ITERON_TEST_FIXTURE=str(source), **(extra or {})),
                                    text=True, capture_output=True, timeout=30)
            assert (result.returncode == 0) == succeeds, result.stderr + result.stdout
            count += 1
            return result

        def snapshot():
            return {name: (destination / name).read_bytes() if (destination / name).exists() else None
                    for name in NAMES}

        run(old, '0.0.29')
        before = snapshot()
        assert before['iteron-app-server'] is None
        run(new)
        after = snapshot()
        assert after['iteron-app-server'] is not None
        run(new, rollback=True)
        assert snapshot() == before
        run(new, rollback=True)
        assert snapshot() == after
        # Downgrade removes the newer standalone executable; rollback restores it.
        run(old, '0.0.29')
        assert snapshot() == before
        run(new, rollback=True, succeeds=False,
            extra={'ITERON_TEST_FAIL_INSTALLED': str(destination / 'iteron-app-server')})
        assert snapshot() == before
        run(new, rollback=True)
        assert snapshot() == after
        run(old, '0.0.29', succeeds=False, extra={'ITERON_TEST_FAIL_MOVE': str(work / 'fail-once')})
        assert snapshot() == after
        run(new, succeeds=False, extra={'ITERON_TEST_FAIL_INSTALLED': str(destination / 'iteron')})
        assert snapshot() == after
        run(new, succeeds=False, extra={'ITERON_TEST_FAIL_INSTALLED': str(destination / 'iteron-app-server')})
        assert snapshot() == after

        incomplete = work / 'missing-server'
        fixture(incomplete, omit_server=True)
        run(incomplete, succeeds=False)
        assert snapshot() == after

        for name, mutator in {
            'bad-hardlink': lambda member, name, root: setattr(member, 'linkname', '../../escape')
                if name == 'iteron-workspace-hook' else None,
            'metadata-symlink': lambda member, name, root: (setattr(member, 'type', tarfile.SYMTYPE),
                setattr(member, 'linkname', '/etc/passwd')) if name == 'README.md' else None,
            'traversal': lambda member, name, root: setattr(member, 'name', root + '/../escape')
                if name == 'README.md' else None,
            'duplicate': lambda member, name, root: setattr(member, 'name', root + '/LICENSE')
                if name == 'README.md' else None,
            'directory-file': lambda member, name, root: setattr(member, 'type', tarfile.DIRTYPE)
                if name == 'README.md' else None,
        }.items():
            malicious = work / name
            fixture(malicious, mutate=mutator)
            run(malicious, succeeds=False)
            assert snapshot() == after
        # The archive still matches its checksum but the manifest declaration is absent.
        no_declaration = work / 'no-declaration'
        shutil.copytree(new, no_declaration)
        (no_declaration / 'manual-release-manifest.json').unlink()
        sums(no_declaration)
        run(no_declaration, succeeds=False)
        assert snapshot() == after
        # A corrupted archive and duplicate checksum row must both preserve all executables.
        with archive.open('ab') as output:
            output.write(b'corruption')
        run(new, succeeds=False)
        assert snapshot() == after
        sums(new)
        with (new / 'SHA256SUMS').open('a') as output:
            output.write(f'{digest(archive.read_bytes())}  {archive.name}\n')
        run(new, succeeds=False)
        assert snapshot() == after
        if args.release_dir:
            run(args.release_dir, args.release_version)
            assert subprocess.check_output([destination / 'iteron', '-V'], text=True).strip() == 'iteron ' + args.release_version
        print(f'{count} manual installer journeys passed (synthetic downloads' +
              (f' plus actual native v{args.release_version} payload)' if args.release_dir else ')'))


if __name__ == '__main__':
    main()

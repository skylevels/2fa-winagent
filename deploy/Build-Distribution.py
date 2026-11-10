#!/usr/bin/env python3
"""Package text sources and hash-pinned official Windows runtime; no compiler."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

TOP = ('README.md', 'composer.json', 'composer.lock', 'config.example.json',
       'config.dosifey.example.json', 'config.pimen.example.json')
DIRECTORIES = ('bin', 'src', 'powershell', 'deploy', 'docs', 'tests')
DOCS = ('instruction.txt', 'api.txt', 'API.md', 'support-api.md', 'BUILD.md',
        'hmac-test-vector.json', 'WINDOWS-VALIDATION.md', 'VALIDATION-RESULTS.md', 'SECURITY-REVIEW.md')
BLOCKED = {'.git', '.build', '__pycache__', 'tls', 'logs', 'dist', 'distrib', 'distib', '.codex', '.agents'}
PRIVATE_SUFFIXES = {'.pem', '.key', '.pfx', '.p12', '.cer', '.crt', '.der', '.csr', '.req',
                    '.p7b', '.p7c', '.log', '.jsonl', '.sqlite', '.sqlite3', '.db', '.pyc'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plain(path):
    for item in (path, *path.parents):
        if item.is_symlink() or (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('Links and reparse points are not permitted: ' + str(item))


def read(path, maximum=16 * 1024 * 1024):
    plain(path)
    before = path.stat()
    if not path.is_file() or before.st_size > maximum:
        raise ValueError('Expected a bounded plain file: ' + str(path))
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError('Input changed while reading: ' + str(path))
    return data


def member(name):
    path = PurePosixPath(name)
    if ('\\' in name or ':' in name or '\0' in name or path.is_absolute()
            or '..' in path.parts or not path.parts):
        raise ValueError('Unsafe archive member: ' + repr(name))
    return path.as_posix()


def files(root):
    plain(root)
    if not root.is_dir():
        raise ValueError('Missing source directory: ' + str(root))
    for path in sorted(root.iterdir()):
        plain(path)
        if path.name.lower() in BLOCKED:
            continue
        if path.is_dir():
            yield from files(path)
        elif path.is_file():
            if (path.name.lower() == 'config.json' or path.name.lower().startswith('.env')
                    or '.local.' in path.name.lower() or path.suffix.lower() in PRIVATE_SUFFIXES):
                continue
            yield path
        else:
            raise ValueError('Special file in source tree: ' + str(path))


def verified_input(inputs, component):
    name = member(component['filename'])
    if '/' in name or not component['url'].startswith('https://'):
        raise ValueError('Unsafe component declaration')
    data = read(inputs / name, component['maximum_bytes'])
    if digest(data) != component['sha256']:
        raise ValueError('SHA-256 mismatch: ' + name)
    return data


def vendor_matches_lock(source, vendor):
    lock = json.loads(read(source / 'composer.lock'))
    installed = json.loads(read(vendor / 'composer' / 'installed.json'))
    installed = installed['packages'] if isinstance(installed, dict) else installed
    expected = {p['name']: (p['version'], p['source']['reference']) for p in lock['packages']}
    actual = {p['name']: (p['version'], p['source']['reference']) for p in installed}
    if actual != expected or len(actual) != len(installed):
        raise ValueError('vendor package versions/references differ from composer.lock')
    read(vendor / 'autoload.php')
    return digest(read(source / 'composer.lock'))


def make_plan(source, inputs, vendor):
    pin_raw = read(source / 'deploy' / 'download-inputs.json')
    pins = json.loads(pin_raw)['components']
    lock_sha = vendor_matches_lock(source, vendor)
    plan, names = {}, set()

    def add(name, data, text=False):
        name = member(name)
        if name.casefold() in names:
            raise ValueError('Duplicate archive member: ' + name)
        if text:
            data.decode('utf-8-sig')
            if b'\0' in data:
                raise ValueError('Binary file in source package: ' + name)
        names.add(name.casefold())
        plan[name] = data

    for name in TOP:
        data = read(source / name)
        if name.startswith('config.') and json.loads(data)['apiSecretHex'] != 'GENERATED_BY_INSTALLER':
            raise ValueError('Example configuration must not contain an installed API secret')
        add('agent/' + name, data, text=True)
    for directory in DIRECTORIES:
        for path in files(source / directory):
            add('agent/' + path.relative_to(source).as_posix(), read(path), text=True)
    for path in files(vendor):
        add('agent/vendor/' + path.relative_to(vendor).as_posix(), read(path), text=True)
    for name in DOCS:
        add('docs/' + name, read(source / 'docs' / name), text=True)
    source_plan = dict(plan)
    add('START-HERE.txt', read(source / 'deploy' / 'START-HERE.txt'), text=True)
    php_raw = verified_input(inputs, pins['php'])
    with zipfile.ZipFile(io.BytesIO(php_raw)) as archive:
        if len(archive.infolist()) > 1000 or sum(x.file_size for x in archive.infolist()) > 400 * 1024 * 1024:
            raise ValueError('PHP archive exceeds size/count limits')
        for info in archive.infolist():
            name = member(info.filename.rstrip('/'))
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('PHP archive contains a link')
            if info.is_dir():
                continue
            if info.file_size > 150 * 1024 * 1024 or info.file_size > max(1024 * 1024, info.compress_size * 200):
                raise ValueError('PHP archive member exceeds size/ratio limits')
            add('php/' + name, archive.read(info))
    production = plan['php/php.ini-production'].decode('utf-8-sig')
    production, directory_count = re.subn(r'(?m)^;\s*extension_dir\s*=\s*"ext"\s*$', 'extension_dir = "C:/2fa/php/ext"', production)
    production, ssl_count = re.subn(r'(?m)^;\s*extension\s*=\s*openssl\s*$', 'extension=openssl', production)
    if directory_count != 1 or ssl_count != 1:
        raise ValueError('Unexpected official php.ini-production template')
    add('php/php.ini', production.replace('\r\n', '\n').replace('\n', '\r\n').encode())
    vc = verified_input(inputs, pins['visual_cpp'])
    if vc[:2] != b'MZ':
        raise ValueError('VC++ redistributable is not a PE file')
    add('prerequisites/VC_redist.x64.exe', vc)
    add('sources/download-inputs.json', pin_raw, text=True)
    provenance = {
        'format_version': 1, 'builder': 'deploy/Build-Distribution.py',
        'composer_lock_sha256': lock_sha,
        'vendor_check': 'Installed package versions and source commits match composer.lock; source files are UTF-8.',
        'php': pins['php'], 'visual_cpp_runtime': pins['visual_cpp'],
        'dependency_installer': pins['composer'],
        'authenticode': 'Prepare-Distribution.ps1 checks Microsoft Authenticode on Windows; Python packaging only checks pinned SHA-256.',
        'custom_compiled_executables': False,
    }
    add('sources/manifest.json', (json.dumps(provenance, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode(), text=True)
    add('sources/SOURCES.txt', ('Official runtime inputs are pinned in download-inputs.json.\n'
        'Agent code and dependencies are PHP/PowerShell text. No custom binary compilation is performed.\n'
        'Rebuild instructions: docs/BUILD.md. Verify Microsoft Authenticode before running its redistributable.\n').encode(), text=True)
    add('sources/manifest.sha256', ''.join(f'{digest(plan[name])}  {name}\n' for name in sorted(plan)).encode(), text=True)
    return source_plan, plan


def build(plan, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    plain(destination.parent)
    plain(destination)
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1577836800'))
    stamp = dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
    if not 1980 <= stamp.year <= 2107:
        raise ValueError('SOURCE_DATE_EPOCH is outside the ZIP timestamp range')
    handle, name = tempfile.mkstemp(prefix='.distribution-', suffix='.zip.tmp', dir=destination.parent)
    os.close(handle)
    temporary = Path(name)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name in sorted(plan):
                info = zipfile.ZipInfo(name, stamp.timetuple()[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, plan[name])
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None or set(archive.namelist()) != set(plan):
                raise ValueError('Output archive membership/CRC verification failed')
            for name, data in plan.items():
                if digest(archive.read(name)) != digest(data):
                    raise ValueError('Output archive bytes differ: ' + name)
        checksum = digest(read(temporary, 200 * 1024 * 1024))
        os.replace(temporary, destination)
        checksum_file = destination.with_suffix(destination.suffix + '.sha256')
        plain(checksum_file)
        checksum_file.write_text(f'{checksum}  {destination.name}\n', encoding='ascii')
        return {'file': str(destination), 'sha256': checksum, 'entries': len(plan)}
    finally:
        temporary.unlink(missing_ok=True)


def main():
    agent = Path(__file__).absolute().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=agent)
    parser.add_argument('--inputs-dir', type=Path, default=agent / '.build' / 'inputs')
    parser.add_argument('--vendor-dir', type=Path, default=agent / '.build' / 'vendor')
    parser.add_argument('--output-dir', type=Path, default=agent / 'dist')
    parser.add_argument('--build', action='store_true', help='Write ZIPs; otherwise verify inputs without writing.')
    args = parser.parse_args()
    source_plan, full_plan = make_plan(args.source_dir.absolute(), args.inputs_dir.absolute(), args.vendor_dir.absolute())
    if args.build:
        result = [build(source_plan, args.output_dir.absolute() / 'windows-agent.zip'),
                  build(full_plan, args.output_dir.absolute() / 'windows-agent-all-in-one.zip')]
        print(json.dumps(result, ensure_ascii=False))
    else:
        print(json.dumps({'verified': True, 'source_entries': len(source_plan), 'full_entries': len(full_plan)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit('Build refused: ' + str(error)) from None

#!/usr/bin/env python3
"""Build the pinned Rust unwind provider without bundling a Rust panic owner."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent
TARGET = 'x86_64-unknown-linux-musl'
PINS = {
    'unwinding': ('0.2.10', '4b134ada16dda9e435abe2a6d76a01d497bc60707357845a15f9b0ed42dc88ce'),
    'gimli': ('0.34.0', '1033caf0b349c518623b5396bfb2cf0bddf44f0306d543a250e5743297aafd10'),
    'libc': ('0.2.186', '68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66'),
}
FEATURES = {
    'crabc-unwinder': set(),
    'unwinding': {'unwinder', 'fde-phdr-dl', 'fde-phdr', 'libc', 'dwarf-expr'},
    'gimli': {'read-core'},
    'libc': {'default', 'std'},
}
UNWIND_ABI = {
    '_Unwind_GetGR', '_Unwind_GetCFA', '_Unwind_SetGR', '_Unwind_GetIP',
    '_Unwind_GetIPInfo', '_Unwind_SetIP', '_Unwind_GetLanguageSpecificData',
    '_Unwind_GetRegionStart', '_Unwind_GetTextRelBase', '_Unwind_GetDataRelBase',
    '_Unwind_FindEnclosingFunction', '_Unwind_RaiseException', '_Unwind_ForcedUnwind',
    '_Unwind_Resume', '_Unwind_Resume_or_Rethrow', '_Unwind_DeleteException', '_Unwind_Backtrace',
}

def run(args, **kwargs):
    return subprocess.check_output([str(a) for a in args], text=True, **kwargs)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def audit_graph(metadata, lock):
    package_records = metadata['packages']
    package_names = [p['name'] for p in package_records]
    if len(package_names) != len(set(package_names)):
        raise ValueError('duplicate package name in resolved dependency graph')
    packages = {p['name']: p for p in package_records}
    if set(packages) != set(FEATURES):
        raise ValueError('unapproved dependency graph')
    locked = {p['name']: p for p in lock['package']}
    for name, (version, checksum) in PINS.items():
        if (locked[name]['version'], locked[name]['checksum']) != (version, checksum):
            raise ValueError(f'unapproved source pin: {name}')
        if packages[name]['version'] != version:
            raise ValueError(f'unapproved resolved version: {name}')
    for node in metadata['resolve']['nodes']:
        package = next(p for p in packages.values() if p['id'] == node['id'])
        name = package['name']
        if set(node['features']) != FEATURES[name]:
            raise ValueError(f'unapproved features for {name}: {node["features"]}')
        for target in package['targets']:
            if 'proc-macro' in target['kind'] or ('custom-build' in target['kind'] and name != 'libc'):
                raise ValueError(f'unapproved build executable in {name}')
    return packages

def build(output):
    if (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        raise ValueError('native Linux/x86-64 required')
    output = output.resolve()
    if not output.is_relative_to(ROOT.parent / '.work'):
        raise ValueError('build output must remain inside checkout .work')
    output.mkdir(parents=True, exist_ok=True)
    temporary = output / 'tmp'
    temporary.mkdir(exist_ok=True)
    channel = tomllib.loads((ROOT.parent / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    cargo = ['rustup', 'run', channel, 'cargo']
    rustc = ['rustup', 'run', channel, 'rustc']
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN'))}
    environment.update(CARGO_HOME=str(ROOT.parent / '.work/x86_64/cargo'),
        CARGO_TARGET_DIR=str(output / 'target'), TMPDIR=str(temporary),
        CARGO_ENCODED_RUSTFLAGS='\x1f'.join(['-Crelocation-model=pic', '-Cembed-bitcode=yes',
            '-Cforce-unwind-tables=yes', '--remap-path-prefix', f'{ROOT.parent}=/crabc']),
        SOURCE_DATE_EPOCH='0', CARGO_INCREMENTAL='0')
    kwargs = {'cwd': ROOT, 'env': environment}
    manifest = ['--manifest-path', str(ROOT / 'Cargo.toml'), '--locked']
    metadata = json.loads(run([*cargo, 'metadata', *manifest, '--format-version=1', '--filter-platform', TARGET], **kwargs))
    packages = audit_graph(metadata, tomllib.loads((ROOT / 'Cargo.lock').read_text()))
    log = run([*cargo, 'build', *manifest, '--release', '--target', TARGET, '--message-format=json'], **kwargs)
    (output / 'cargo.jsonl').write_text(log)
    sysroot = Path(run([*rustc, '--print', 'sysroot'], **kwargs).strip())
    llvm = sysroot / 'lib/rustlib/x86_64-unknown-linux-musl/bin'
    # llvm-tools reside under the host triple, which this image pins to musl.
    ar = llvm / 'llvm-ar'
    nm = llvm / 'llvm-nm'
    if not ar.exists():
        raise ValueError('pinned llvm-tools are unavailable')
    members = []
    sources = []
    for name in sorted(PINS):
        package = packages[name]
        source = Path(package['manifest_path']).parent
        source_files = sorted(p for p in source.rglob('*') if p.is_file())
        sources.append({'name': name, 'version': package['version'], 'license': package['license'],
            'features': sorted(FEATURES[name]), 'files': [
                {'path': str(p.relative_to(source)), 'sha256': digest(p)} for p in source_files]})
        artifacts = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
        matching = [a for a in artifacts if a.get('reason') == 'compiler-artifact' and a['package_id'] == package['id'] and 'lib' in a['target']['kind']]
        archives = [Path(f) for a in matching for f in a['filenames'] if f.endswith('.rlib')]
        if len(archives) != 1:
            raise ValueError(f'expected one Rust archive for {name}')
        archive = archives[0]
        directory = output / 'members' / name
        directory.mkdir(parents=True, exist_ok=True)
        names = run([ar, 't', archive]).splitlines()
        for member in names:
            if member in {'lib.rmeta', 'lib.rmeta-link'}:
                continue
            if '/' in member or not member.endswith('.o'):
                raise ValueError(f'unexpected Rust archive member: {member}')
            subprocess.run([str(ar), 'x', str(archive), member], cwd=directory, check=True)
            path = directory / member
            header = path.read_bytes()[:20]
            if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
                raise ValueError('non-native ELF object in provider')
            members.append(path)
    archive = output / 'libcrabc-unwind.a'
    archive.unlink(missing_ok=True)
    subprocess.run([str(ar), 'rcsD', str(archive), *map(str, members)], check=True)
    symbols = run([nm, '--defined-only', '--extern-only', archive])
    (output / 'defined-symbols.txt').write_text(symbols)
    names = {line.split()[-1] for line in symbols.splitlines() if len(line.split()) >= 3}
    if {n for n in names if n.startswith('_Unwind_')} != UNWIND_ABI:
        raise ValueError('unwind ABI inventory changed')
    forbidden = {'rust_eh_personality', 'rust_begin_unwind', '__rust_alloc', 'malloc', '__register_frame', '__deregister_frame'}
    if names & forbidden:
        raise ValueError('provider contains an unapproved runtime owner')
    undefined = run([nm, '--undefined-only', archive])
    (output / 'undefined-symbols.txt').write_text(undefined)
    provenance = {'schema': 1, 'target': TARGET, 'toolchain': run([*rustc, '-Vv'], **kwargs),
        'upstream_commit': '0e2de8fb536b1ca42066024609f58d708cf80e69',
        'archive': {'name': archive.name, 'sha256': digest(archive)}, 'dependencies': sources,
        'unwind_abi': sorted(UNWIND_ABI), 'members': [{'name': p.name, 'sha256': digest(p)} for p in members],
        'native_build_products': False, 'personality_owner': 'consumer Rust std',
        'qualified': False}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(archive)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT.parent / '.work/x86_64/unwinder')
    build(parser.parse_args().output)

#!/usr/bin/env python3
"""Build the pinned Rust unwind provider without bundling a Rust panic owner."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
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
PATCHED_UNWINDING = 'unwinding'
PATCH_TARGET = 'src/unwinder/find_fde/phdr.rs'
PATCH_OVERLAY = ROOT / 'patches/unwinding-0.2.10-phdr-bounds.rs'
PATCHED_UNWINDING_ORIGINAL_SHA256 = '5c462a8ea77cd67c8cd2c248671b74ac3df475ea134f7ff578a79a0ab0398a68'
PATCHED_UNWINDING_UPSTREAM_TREE_SHA256 = '8ce98e8ae23314ff1312aec0c3f6c627df256a61e212923a6cd70fd53a0990d9'
PATCHED_UNWINDING_LICENSE = 'MIT OR Apache-2.0'
CRATES_IO_REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'

def run(args, **kwargs):
    return subprocess.check_output([str(a) for a in args], text=True, **kwargs)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files(root):
    files = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'symlink in audited source tree: {path}')
        if path.is_file():
            files.append(path)
    return files


def tree_digest(root, overlays=None):
    overlays = overlays or {}
    identity = hashlib.sha256()
    paths = source_files(root)
    names = {path.relative_to(root).as_posix() for path in paths}
    if not set(overlays) <= names:
        raise ValueError('source overlay target is absent from the pinned tree')
    for path in paths:
        relative = path.relative_to(root).as_posix()
        identity.update(relative.encode())
        identity.update(b'\0')
        identity.update(digest(overlays.get(relative, path)).encode())
        identity.update(b'\0')
    return identity.hexdigest()


def audit_graph(metadata, lock, patched_unwinding=False):
    package_records = metadata['packages']
    package_names = [p['name'] for p in package_records]
    if len(package_names) != len(set(package_names)):
        raise ValueError('duplicate package name in resolved dependency graph')
    package_ids = [p['id'] for p in package_records]
    if len(package_ids) != len(set(package_ids)):
        raise ValueError('duplicate resolved package identity')
    packages = {p['name']: p for p in package_records}
    if set(packages) != set(FEATURES):
        raise ValueError('unapproved dependency graph')
    packages_by_id = {p['id']: p for p in package_records}

    lock_records = lock['package']
    lock_names = [p['name'] for p in lock_records]
    if len(lock_names) != len(set(lock_names)):
        raise ValueError('duplicate lock package name')
    locked = {p['name']: p for p in lock_records}
    if set(locked) != set(FEATURES):
        raise ValueError('unapproved locked dependency graph')

    root = locked['crabc-unwinder']
    if (root['version'] != packages['crabc-unwinder']['version']
            or 'source' in root or 'checksum' in root):
        raise ValueError('unapproved root lock package')
    for name, (version, checksum) in PINS.items():
        if patched_unwinding and name == PATCHED_UNWINDING:
            if (locked[name]['version'] != version
                    or 'source' in locked[name] or 'checksum' in locked[name]):
                raise ValueError('unapproved patched source pin')
        elif (locked[name]['version'], locked[name]['checksum']) != (version, checksum):
            raise ValueError(f'unapproved source pin: {name}')
        if packages[name]['version'] != version:
            raise ValueError(f'unapproved resolved version: {name}')

    nodes = metadata['resolve']['nodes']
    node_ids = [node['id'] for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError('duplicate resolve node identity')
    unknown_node_ids = set(node_ids) - set(packages_by_id)
    if unknown_node_ids:
        raise ValueError('unknown resolve node identity')
    missing_node_ids = set(packages_by_id) - set(node_ids)
    if missing_node_ids:
        raise ValueError('missing resolve node identity')
    for node in nodes:
        package = packages_by_id[node['id']]
        name = package['name']
        if set(node['features']) != FEATURES[name]:
            raise ValueError(f'unapproved features for {name}: {node["features"]}')
        for target in package['targets']:
            if 'proc-macro' in target['kind'] or ('custom-build' in target['kind'] and name != 'libc'):
                raise ValueError(f'unapproved build executable in {name}')
    return packages


def staged_manifest_text():
    return (
        f'{(ROOT / "Cargo.toml").read_text()}\n'
        f'[patch.crates-io]\n{PATCHED_UNWINDING} = {{ path = "../{PATCHED_UNWINDING}-0.2.10" }}\n'
    )


def stage_patched_unwinding(packages):
    package = packages[PATCHED_UNWINDING]
    if package.get('source') != CRATES_IO_REGISTRY:
        raise ValueError('unwinding source is not the pinned crates.io registry package')
    upstream = Path(package['manifest_path']).parent
    source = upstream / PATCH_TARGET
    if source.is_symlink() or not source.is_file() or digest(source) != PATCHED_UNWINDING_ORIGINAL_SHA256:
        raise ValueError('unwinding patch target differs from the pinned upstream source')
    upstream_tree_sha256 = tree_digest(upstream)
    if upstream_tree_sha256 != PATCHED_UNWINDING_UPSTREAM_TREE_SHA256:
        raise ValueError('unwinding source tree differs from the pinned upstream identity')
    if PATCH_OVERLAY.is_symlink() or not PATCH_OVERLAY.is_file():
        raise ValueError('unwinding bounds overlay is not a regular checked-in source')
    patched_tree_sha256 = tree_digest(upstream, {PATCH_TARGET: PATCH_OVERLAY})
    input_identity = hashlib.sha256()
    for value in (
        upstream_tree_sha256,
        patched_tree_sha256,
        digest(ROOT / 'Cargo.toml'),
        digest(ROOT / 'Cargo.lock'),
        tree_digest(ROOT / 'src'),
    ):
        input_identity.update(value.encode())
        input_identity.update(b'\0')
    source_root = ROOT.parent / '.work/x86_64/unwinder-source-inputs' / input_identity.hexdigest()
    staged_unwinding = source_root / f'{PATCHED_UNWINDING}-0.2.10'
    staged_root = source_root / 'crabc-unwinder'
    if source_root.exists():
        if source_root.is_symlink() or not source_root.is_dir():
            raise ValueError('unwinding source input is not a regular directory')
        if tree_digest(staged_unwinding) != patched_tree_sha256:
            raise ValueError('existing unwinding source input differs from the reviewed overlay')
        if tree_digest(staged_root / 'src') != tree_digest(ROOT / 'src'):
            raise ValueError('existing crabc-unwinder source input is stale')
        if (staged_root / 'Cargo.toml').read_text() != staged_manifest_text():
            raise ValueError('existing crabc-unwinder manifest is stale')
    else:
        source_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(upstream, staged_unwinding)
        shutil.copytree(ROOT / 'src', staged_root / 'src')
        (staged_root / 'Cargo.toml').write_text(staged_manifest_text())
        shutil.copy2(ROOT / 'Cargo.lock', staged_root / 'Cargo.lock')
        patched_target = staged_unwinding / PATCH_TARGET
        shutil.copyfile(PATCH_OVERLAY, patched_target)
        if tree_digest(staged_unwinding) != patched_tree_sha256:
            raise ValueError('unwinding bounds overlay was not staged exactly')
    return {
        'manifest': staged_root / 'Cargo.toml',
        'upstream': upstream,
        'staged': staged_unwinding,
        'source_input': source_root,
        'upstream_tree_sha256': upstream_tree_sha256,
        'patched_tree_sha256': patched_tree_sha256,
        'patch': {
            'path': str(PATCH_OVERLAY.relative_to(ROOT.parent)),
            'sha256': digest(PATCH_OVERLAY),
            'target': PATCH_TARGET,
            'upstream_sha256': PATCHED_UNWINDING_ORIGINAL_SHA256,
            'compiled_sha256': digest(staged_unwinding / PATCH_TARGET),
            'license': PATCHED_UNWINDING_LICENSE,
        },
    }


def verify_staged_patched_unwinding(staged):
    """Reject provenance if the staged source changes before it is recorded."""
    if tree_digest(staged['staged']) != staged['patched_tree_sha256']:
        raise ValueError('compiled unwinding source differs from the reviewed overlay')
    patch = staged['patch']
    if digest(PATCH_OVERLAY) != patch['sha256']:
        raise ValueError('checked-in unwinding overlay differs from the staged patch record')
    if digest(staged['staged'] / patch['target']) != patch['compiled_sha256']:
        raise ValueError('compiled unwinding overlay differs from the staged patch record')

def build(output):
    if (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        raise ValueError('native Linux/x86-64 required')
    output = output.resolve()
    if not output.is_relative_to(ROOT.parent / '.work'):
        raise ValueError('build output must remain inside checkout .work')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('build output is nonempty; preserve its existing evidence')
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
    source_manifest = ['--manifest-path', str(ROOT / 'Cargo.toml'), '--locked']
    metadata = json.loads(run([*cargo, 'metadata', *source_manifest, '--format-version=1', '--filter-platform', TARGET], **kwargs))
    packages = audit_graph(metadata, tomllib.loads((ROOT / 'Cargo.lock').read_text()))
    staged = stage_patched_unwinding(packages)
    staged_kwargs = {'cwd': staged['manifest'].parent, 'env': environment}
    run([*cargo, 'generate-lockfile', '--offline', '--manifest-path', staged['manifest']], **staged_kwargs)
    manifest = ['--manifest-path', str(staged['manifest']), '--locked']
    patched_metadata = json.loads(run([*cargo, 'metadata', *manifest, '--format-version=1', '--filter-platform', TARGET], **staged_kwargs))
    packages = audit_graph(patched_metadata, tomllib.loads((staged['manifest'].parent / 'Cargo.lock').read_text()), patched_unwinding=True)
    if Path(packages[PATCHED_UNWINDING]['manifest_path']).parent != staged['staged']:
        raise ValueError('Cargo did not compile the staged unwinding source')
    log = run([*cargo, 'build', *manifest, '--release', '--target', TARGET, '--message-format=json'], **staged_kwargs)
    verify_staged_patched_unwinding(staged)
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
        package_files = source_files(source)
        sources.append({'name': name, 'version': package['version'], 'license': package['license'],
            'features': sorted(FEATURES[name]), 'files': [
                {'path': str(p.relative_to(source)), 'sha256': digest(p)} for p in package_files]})
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
        'patched_unwinding': {
            'source_input': str(staged['source_input'].relative_to(ROOT.parent)),
            'upstream_tree_sha256': staged['upstream_tree_sha256'],
            'patched_tree_sha256': staged['patched_tree_sha256'],
            'patches': [staged['patch']],
        },
        'unwind_abi': sorted(UNWIND_ABI), 'members': [{'name': p.name, 'sha256': digest(p)} for p in members],
        'native_build_products': False, 'personality_owner': 'consumer Rust std',
        'qualified': False}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(archive)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='fresh or empty checkout-local output directory')
    output = parser.parse_args().output
    if output is None:
        runs = ROOT.parent / '.work/x86_64/unwinder-builds'
        runs.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix='run-', dir=runs))
        # The pinned container builds as root; retain public build evidence
        # readable by the invoking host user, like the installed-product jobs.
        output.chmod(0o755)
    build(output)

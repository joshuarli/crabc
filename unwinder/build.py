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
import stat
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
PATCHES = {
    'src/unwinder/find_fde/phdr.rs': {
        'overlay': ROOT / 'patches/unwinding-0.2.10-phdr-bounds.rs',
        'upstream_sha256': '5c462a8ea77cd67c8cd2c248671b74ac3df475ea134f7ff578a79a0ab0398a68',
    },
    'src/unwinder/frame.rs': {
        'overlay': ROOT / 'patches/unwinding-0.2.10-frame-bounds.rs',
        'upstream_sha256': '26f18f4097b32972b1c7ce95ba31abe31201301dee2bac7f794a9f2da4e7f5d7',
    },
}
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


def private_stage_root(stage_root):
    """Create one explicit fresh physical root for a private provider stage."""

    candidate = Path(os.path.abspath(stage_root))
    if ".." in Path(stage_root).parts:
        raise ValueError('private unwinding stage root has parent traversal')
    if candidate.exists() or candidate.is_symlink():
        raise ValueError('private unwinding stage root must be fresh')
    parent = candidate.parent
    current = Path(candidate.anchor)
    try:
        for part in candidate.parts[1:-1]:
            current /= part
            if current.is_symlink():
                raise ValueError('private unwinding stage root traverses a symlink')
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError('private unwinding stage root parent is not a physical directory')
        if not os.access(parent, os.W_OK | os.X_OK):
            raise ValueError('private unwinding stage root parent is not writable')
        candidate.mkdir(mode=0o755)
    except OSError as error:
        raise ValueError('private unwinding stage root is not writable') from error
    return candidate


def stage_patched_unwinding(packages, *, stage_root=None, registry_source=None):
    package = packages[PATCHED_UNWINDING]
    if package.get('source') != CRATES_IO_REGISTRY:
        raise ValueError('unwinding source is not the pinned crates.io registry package')
    if registry_source is None:
        upstream = Path(package['manifest_path']).parent
    else:
        upstream = Path(registry_source)
        if upstream.is_symlink() or not upstream.is_dir():
            raise ValueError('registry unwinding source must be a physical directory')
        upstream = upstream.resolve(strict=True)
        try:
            source_manifest = tomllib.loads((upstream / 'Cargo.toml').read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ValueError('registry unwinding source manifest is invalid') from error
        source_package = source_manifest.get('package')
        if (not isinstance(source_package, dict)
                or source_package.get('name') != PATCHED_UNWINDING
                or source_package.get('version') != PINS[PATCHED_UNWINDING][0]):
            raise ValueError('registry unwinding source identity differs from its lock')
    overlays = {}
    for target, patch in PATCHES.items():
        source = upstream / target
        overlay = patch['overlay']
        if source.is_symlink() or not source.is_file() or digest(source) != patch['upstream_sha256']:
            raise ValueError(f'unwinding patch target differs from the pinned upstream source: {target}')
        if overlay.is_symlink() or not overlay.is_file():
            raise ValueError(f'unwinding bounds overlay is not a regular checked-in source: {target}')
        overlays[target] = overlay
    upstream_tree_sha256 = tree_digest(upstream)
    if upstream_tree_sha256 != PATCHED_UNWINDING_UPSTREAM_TREE_SHA256:
        raise ValueError('unwinding source tree differs from the pinned upstream identity')
    patched_tree_sha256 = tree_digest(upstream, overlays)
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
    # A direct provider build keeps the historical shared content-addressed
    # checkout input.  Consumers with a read-only checkout supply one fresh
    # evidence-local root so every copied/overlaid source remains writable
    # without relaxing their input mounts.
    if stage_root is None:
        inputs_root = ROOT.parent / '.work/x86_64/unwinder-source-inputs'
    else:
        inputs_root = private_stage_root(stage_root)
    source_root = inputs_root / input_identity.hexdigest()
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
        staged_modes = {}
        try:
            # The registry derivative may preserve the supplied vendor's
            # read-only modes. Only the two checked overlay targets need a
            # temporary owner-write bit, and every original mode is restored
            # whether copying or the post-copy digest check succeeds.
            for target in overlays:
                staged_target = staged_unwinding / target
                staged_mode = stat.S_IMODE(staged_target.stat().st_mode)
                staged_modes[staged_target] = staged_mode
                staged_target.chmod(staged_mode | stat.S_IWUSR)
            for target, overlay in overlays.items():
                shutil.copyfile(overlay, staged_unwinding / target)
            if tree_digest(staged_unwinding) != patched_tree_sha256:
                raise ValueError('unwinding bounds overlay was not staged exactly')
        finally:
            for staged_target, staged_mode in staged_modes.items():
                staged_target.chmod(staged_mode)
    return {
        'manifest': staged_root / 'Cargo.toml',
        'upstream': upstream,
        'staged': staged_unwinding,
        'source_input': source_root,
        'upstream_tree_sha256': upstream_tree_sha256,
        'patched_tree_sha256': patched_tree_sha256,
        'patches': [{
            'path': str(overlay.relative_to(ROOT.parent)),
            'sha256': digest(overlay),
            'target': target,
            'upstream_sha256': PATCHES[target]['upstream_sha256'],
            'compiled_sha256': digest(staged_unwinding / target),
            'license': PATCHED_UNWINDING_LICENSE,
        } for target, overlay in overlays.items()],
    }


def verify_staged_patched_unwinding(staged):
    """Reject provenance if the staged source changes before it is recorded."""
    if tree_digest(staged['staged']) != staged['patched_tree_sha256']:
        raise ValueError('compiled unwinding source differs from the reviewed overlay')
    patches = staged['patches']
    targets = [patch['target'] for patch in patches]
    if len(targets) != len(PATCHES) or set(targets) != set(PATCHES):
        raise ValueError('staged unwinding patch roster differs from the reviewed overlays')
    for patch in patches:
        configured = PATCHES.get(patch['target'])
        if configured is None:
            raise ValueError('staged unwinding patch target is not reviewed')
        overlay = configured['overlay']
        if digest(overlay) != patch['sha256']:
            raise ValueError('checked-in unwinding overlay differs from the staged patch record')
        if digest(staged['staged'] / patch['target']) != patch['compiled_sha256']:
            raise ValueError('compiled unwinding overlay differs from the staged patch record')

def build(output, *, stage_root=None, cargo_home=None, registry_unwinding_source=None):
    if (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        raise ValueError('native Linux/x86-64 required')
    output = output.resolve()
    if not output.is_relative_to(ROOT.parent / '.work'):
        raise ValueError('build output must remain inside checkout .work')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('build output is nonempty; preserve its existing evidence')
    output.mkdir(parents=True, exist_ok=True)
    if stage_root is not None:
        stage_root = Path(os.path.abspath(stage_root))
        if not stage_root.is_relative_to(output):
            raise ValueError('private unwinding stage root must remain below build output')
    if registry_unwinding_source is not None:
        registry_unwinding_source = Path(os.path.abspath(registry_unwinding_source))
        if (registry_unwinding_source.is_symlink() or not registry_unwinding_source.is_dir()
                or not registry_unwinding_source.resolve(strict=True).is_relative_to(output.parent)):
            raise ValueError('registry unwinding source must be a physical input below the build output parent')
    if cargo_home is None:
        cargo_home = ROOT.parent / '.work/x86_64/cargo'
    else:
        cargo_home = Path(os.path.abspath(cargo_home))
        if cargo_home.parent != output.parent:
            raise ValueError('private Cargo home must remain beside build output')
        if cargo_home.is_symlink() or not cargo_home.is_dir():
            raise ValueError('private Cargo home must be a physical directory')
    temporary = output / 'tmp'
    temporary.mkdir(exist_ok=True)
    channel = tomllib.loads((ROOT.parent / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    cargo = ['rustup', 'run', channel, 'cargo']
    rustc = ['rustup', 'run', channel, 'rustc']
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN'))}
    environment.update(CARGO_HOME=str(cargo_home),
        CARGO_TARGET_DIR=str(output / 'target'), TMPDIR=str(temporary),
        CARGO_ENCODED_RUSTFLAGS='\x1f'.join(['-Crelocation-model=pic', '-Cembed-bitcode=yes',
            '-Cforce-unwind-tables=yes', '--remap-path-prefix', f'{ROOT.parent}=/crabc']),
        SOURCE_DATE_EPOCH='0', CARGO_INCREMENTAL='0')
    kwargs = {'cwd': ROOT, 'env': environment}
    source_manifest = ['--manifest-path', str(ROOT / 'Cargo.toml'), '--locked']
    metadata = json.loads(run([*cargo, 'metadata', *source_manifest, '--format-version=1', '--filter-platform', TARGET], **kwargs))
    packages = audit_graph(metadata, tomllib.loads((ROOT / 'Cargo.lock').read_text()))
    staged = stage_patched_unwinding(
        packages, stage_root=stage_root, registry_source=registry_unwinding_source,
    )
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
            'patches': staged['patches'],
        },
        'unwind_abi': sorted(UNWIND_ABI), 'members': [{'name': p.name, 'sha256': digest(p)} for p in members],
        'native_build_products': False, 'personality_owner': 'consumer Rust std',
        'qualified': False}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(archive)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='fresh or empty checkout-local output directory')
    parser.add_argument('--stage-root', type=Path,
                        help='fresh private provider-source root below --output')
    parser.add_argument('--cargo-home', type=Path,
                        help='existing private Cargo home beside --output')
    parser.add_argument('--registry-unwinding-source', type=Path,
                        help='authenticated registry-shaped source derived from the provider Cargo vendor')
    arguments = parser.parse_args()
    output = arguments.output
    if output is None:
        runs = ROOT.parent / '.work/x86_64/unwinder-builds'
        runs.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix='run-', dir=runs))
        # The pinned container builds as root; retain public build evidence
        # readable by the invoking host user, like the installed-product jobs.
        output.chmod(0o755)
    build(output, stage_root=arguments.stage_root, cargo_home=arguments.cargo_home,
          registry_unwinding_source=arguments.registry_unwinding_source)

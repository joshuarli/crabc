#!/usr/bin/env python3
"""Execute and retain the complete installed POSIX workload product matrix.

The static preparation and dynamic qualification owners establish products.
This coordinator adds the finite POSIX workload map, unchanged object identity
across independent products, and retained raw workload observations. A matrix
receipt is a prerequisite for native aggregate qualification, not family closure
or public x86 support.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from typing import Mapping

import owned_posix_static_products as static_products

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'crabc.x86_64-owned-posix-family-execution/v1'
# Each replay consumes one independent static/dynamic pair. Every object role
# must have identical bytes across all three replays, even when a leaf repeats
# the installed-header translation with the corresponding installed driver.
PAIRS = {'primary': 'installed', 'reproduction': 'second', 'extracted': 'extracted'}


class ExecutionError(RuntimeError):
    """A required workload, product cell or retained artifact is incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ExecutionError(message)


def physical(root: Path, path: Path) -> Path:
    try:
        return static_products.physical(root, path)
    except (static_products.PreparationError, OSError) as error:
        raise ExecutionError(str(error)) from error


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f'missing physical file: {path}')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def file_identity(root: Path, path: Path) -> dict:
    path = physical(root, path)
    return {'path': path.relative_to(root).as_posix(), 'sha256': digest(path),
            'size': path.stat().st_size}


def read(path: Path) -> object:
    try:
        return static_products.read(path)
    except (static_products.PreparationError, OSError, ValueError) as error:
        raise ExecutionError(str(error)) from error


def same_json(left: object, right: object) -> bool:
    return static_products.same_json(left, right)


def snapshot(directory: Path) -> dict:
    """Seal retained fixture nodes without opening FIFOs or following links.

    Device identities, ownership and link counts describe fixtures that cannot
    be represented as regular payload bytes. Inode numbers and timestamps are
    intentionally absent; they do not describe the runtime contract and change
    when an otherwise equivalent tree is copied.
    """
    require(directory.is_dir() and not directory.is_symlink(), 'snapshot needs a physical directory')
    result = {}
    pending = [directory]
    while pending:
        parent = pending.pop()
        for path in sorted(parent.iterdir()):
            metadata = path.lstat()
            mode = metadata.st_mode
            entry = {'mode': stat.S_IMODE(mode), 'uid': metadata.st_uid,
                     'gid': metadata.st_gid, 'links': metadata.st_nlink}
            if stat.S_ISDIR(mode):
                entry['kind'] = 'directory'
                pending.append(path)
            elif stat.S_ISREG(mode):
                entry.update(kind='file', size=metadata.st_size, sha256=digest(path))
            elif stat.S_ISLNK(mode):
                entry.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISFIFO(mode):
                entry['kind'] = 'fifo'
            elif stat.S_ISSOCK(mode):
                entry['kind'] = 'socket'
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                entry.update(kind='character' if stat.S_ISCHR(mode) else 'block',
                             major=os.major(metadata.st_rdev), minor=os.minor(metadata.st_rdev))
            else:
                raise ExecutionError(f'unsupported fixture node: {path}')
            result[path.relative_to(directory).as_posix()] = entry
    return result


def invocation(root: Path, command: list[str], environment: Mapping[str, str]) -> dict:
    return {'command': command, 'cwd': str(root), 'environment': dict(environment)}


def run_step(root: Path, step: Path, command: list[str], environment: Mapping[str, str]) -> None:
    """Run once, retaining both raw streams and status even when execution fails."""
    step = physical(root, step)
    require(not step.exists(), 'workload execution requires a fresh step directory')
    step.mkdir(parents=True)
    (step / 'tmp').mkdir()
    static_products.write_new(step / 'invocation.json', invocation(root, command, environment))
    status = 127
    process = None
    try:
        with (step / 'stdout').open('xb') as stdout, (step / 'stderr').open('xb') as stderr:
            try:
                process = subprocess.Popen(command, cwd=root, env=dict(environment),
                                           stdin=subprocess.DEVNULL, stdout=stdout,
                                           stderr=stderr, start_new_session=True)
                status = process.wait()
            except OSError as error:
                stderr.write((str(error) + '\n').encode())
            except BaseException:
                # An interrupted Python parent must retain the actual child
                # termination status, not the command-not-started sentinel.
                # The private process group contains ordinary leaf descendants;
                # each specialized leaf retains its own detached-child cleanup.
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        status = process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        status = process.wait()
                raise
    finally:
        (step / 'status').write_text(f'{status}\n', encoding='ascii')
    require(status == 0, f'workload exit status {status}: {step}')


def check_step(root: Path, step: Path, command: list[str], environment: Mapping[str, str],
               *, source_mount: str | None = None) -> dict:
    expected = invocation(Path(source_mount) if source_mount else root, command, environment)
    require(same_json(read(step / 'invocation.json'), expected), 'workload invocation changed')
    require((step / 'status').read_bytes() == b'0\n', 'workload status is not successful')
    return {name: file_identity(root, step / name)
            for name in ('invocation.json', 'stdout', 'stderr', 'status')}


def leaf_directory(root: Path, step: Path, source_mount: str) -> Path:
    """Admit only one retained leaf within this exact command's private scratch."""
    require(isinstance(source_mount, str) and Path(source_mount).is_absolute(), 'invalid source mount')
    prefix = source_mount.rstrip('/') + '/'
    leaves = set()
    for name in re.findall(r'evidence: ([^\n]+)', (step / 'stdout').read_text(errors='replace')):
        require(name.startswith(prefix), 'workload evidence escapes source mount')
        leaf = physical(root, root / name[len(prefix):])
        require(leaf.is_dir() and leaf.parent == step / 'tmp', 'workload evidence escapes exact step scratch')
        leaves.add(leaf)
    require(len(leaves) == 1, 'workload must declare one retained evidence root')
    leaf = leaves.pop()
    require(set((step / 'tmp').iterdir()) == {leaf}, 'workload scratch contains undeclared artifacts')
    return leaf


def identical_objects(records: Mapping[str, Mapping[str, str]]) -> None:
    require(set(records) == set(PAIRS), 'workload object product roster differs')
    primary = records['primary']
    require(bool(primary), 'workload has no canonical object roles')
    require(all(isinstance(role, str) and isinstance(value, str)
                and re.fullmatch('[0-9a-f]{64}', value) for role, value in primary.items()),
            'invalid workload object identity')
    require(all(same_json(dict(value), dict(primary)) for value in records.values()),
            'workload object bytes or role roster differ across products')


def workload_roster():
    # Both owners validate finite source-bound contracts. Delaying imports lets
    # the raw execution/fixture primitives be tested without a product build.
    import owned_posix_family_workloads as workloads
    workloads.validate_workloads()
    for workload in workloads.WORKLOADS:
        source_file(ROOT, workload.script)
    return workloads.WORKLOADS


def mounted(root: Path, path: Path, source_mount: str) -> str:
    return str(Path(source_mount) / physical(root, path).relative_to(root))


def case_command(root: Path, workload, products: Mapping[str, Path], source_mount: str) -> list[str]:
    command = ['bash', str(Path(source_mount) / workload.script)]
    require(workload.product_scope in ('static', 'dynamic', 'both'), 'unknown workload product scope')
    if workload.product_scope in ('static', 'both'):
        command += ['--static-sysroot', mounted(root, products['static'], source_mount)]
    if workload.product_scope in ('dynamic', 'both'):
        command.append(mounted(root, products['dynamic'], source_mount))
    return command


def case_environment(root: Path, step: Path, source_mount: str) -> dict[str, str]:
    # No inherited LD_*, compiler overrides, or private qualification selectors
    # can silently change a workload. Installed drivers additionally apply their
    # own fixed compiler environment. The native image owns these tool paths.
    from generate_qualification_manifest import EXECUTION_CONTRACT
    return {'PATH': EXECUTION_CONTRACT['rust_bin_directory'] +
                   ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'RUSTUP_HOME': EXECUTION_CONTRACT['rustup_home'],
            'CARGO_HOME': str(Path(source_mount) / '.work/x86_64/cargo'),
            'CRABC_WORK_DIR': str(Path(source_mount) / '.work/x86_64'),
            'LC_ALL': 'C', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1',
            'TZ': 'UTC', 'PYTHONNOUSERSITE': '1',
            'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_COUNT': '1',
            'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': source_mount,
            'TMPDIR': mounted(root, step / 'tmp', source_mount)}


def input_products(root: Path, request: dict) -> tuple[dict, dict[str, dict[str, Path]]]:
    import owned_dynamic_qualification as dynamic
    require(root == dynamic.ROOT, 'product owners must use this coordinator checkout')
    require(isinstance(request, dict) and set(request) == {
        'schema', 'source_mount', 'static_preparation', 'dynamic_qualification'}, 'execution request fields differ')
    require(request['schema'] == SCHEMA, 'execution request schema differs')
    source_mount = request['source_mount']
    require(isinstance(source_mount, str) and Path(source_mount).is_absolute()
            and '..' not in Path(source_mount).parts, 'invalid execution source mount')
    paths = {}
    for name in ('static_preparation', 'dynamic_qualification'):
        value = request[name]
        require(isinstance(value, str) and not Path(value).is_absolute(), 'input receipt path must be checkout-relative')
        paths[name] = physical(root, root / value)
    static = static_products.validate_receipt(root, paths['static_preparation'])
    shared = dynamic.validate_receipt(paths['dynamic_qualification'])
    source = static_products.source_identity(root)
    require(same_json(static['source'], source)
            and shared['source_sha256'] == source['content_sha256'], 'product source seals differ')
    require(shared['family_completion'] is False and shared['public_support'] is False,
            'product qualification cannot replace family execution')
    static_paths = static_products.product_paths(paths['static_preparation'].parent)
    dynamic_work = physical(root, root / shared['work'])
    products = {label: {'static': static_paths[label], 'dynamic': dynamic_work / dynamic_label}
                for label, dynamic_label in PAIRS.items()}
    evidence = {name: file_identity(root, path) for name, path in paths.items()}
    evidence['source'] = source
    evidence['static_products'] = {label: static['products'][label]['manifest'] for label in PAIRS}
    evidence['dynamic_products'] = {label: {'path': products[label]['dynamic'].relative_to(root).as_posix(),
        'manifest_sha256': shared['products'][PAIRS[label]]} for label in PAIRS}
    evidence['dynamic_work'] = dynamic_work.relative_to(root).as_posix()
    # The validated dynamic receipt retains the observed oracle's actual bytes,
    # source pins/specs probe, and full three-product case qualification.
    preparation = dynamic.read(dynamic_work / 'qualification-prepare.json')
    evidence['oracle'] = preparation['oracle']
    return evidence, products


def source_file(root: Path, value: str) -> dict:
    path = root / value
    require(not Path(value).is_absolute() and '..' not in Path(value).parts
            and path.resolve(strict=True) == path, 'workload source is not a physical checkout file')
    return {'path': value, 'sha256': digest(path)}


def collect_step(root: Path, work: Path, label: str, workload,
                 products: Mapping[str, Path], source_mount: str) -> dict:
    import owned_posix_family_observations as observations
    step = work / 'runs' / label / workload.id
    command = case_command(root, workload, products, source_mount)
    environment = case_environment(root, step, source_mount)
    step_artifacts = check_step(root, step, command, environment, source_mount=source_mount)
    leaf = leaf_directory(root, step, source_mount)
    objects = {}
    for role in workload.source_object_roles:
        require(role.role not in objects, 'duplicate canonical object role')
        path = physical(root, leaf / role.object_path)
        require(path.is_relative_to(leaf), 'canonical workload object escapes leaf')
        objects[role.role] = {'source': source_file(root, role.source),
                             'object': file_identity(root, path)}
    require(objects, 'workload has no retained object roles')
    sources = {value: source_file(root, value) for value in
               (workload.script, *workload.required_supplementary_sources)}
    raw = observations.collect(workload.id, leaf,
                               static_required=workload.product_scope in ('both', 'static'), root=root)
    # All link receipts, dependency traces, inspected ELF, compiler identities,
    # raw fixture files and special nodes remain under this immutable snapshot.
    # The source-bound leaf checks its own specialized one-/multi-object links;
    # the coordinator preserves them rather than substituting a weaker schema.
    return {'workload': workload.id, 'dynamic_case': workload.dynamic_case,
            'static_product': label if workload.product_scope != 'dynamic' else None,
            'dynamic_product': PAIRS[label] if workload.product_scope != 'static' else None,
            'step': step_artifacts, 'sources': sources, 'objects': objects,
            'leaf': leaf.relative_to(root).as_posix(), 'observations': raw,
            'artifacts': snapshot(leaf)}


def spelling_evidence(roster, records: Mapping[str, dict]) -> dict:
    """Connect every spelling to actual static and dynamic workload receipts.

    The dynamic fork transaction has a private DSO/TLS workload. Its static
    counterpart is the explicitly required pair of existing atfork and POSIX
    fork/exec sources. This is the sole named bridge; composition cannot become
    a fallback when a primary owner lacks the required product scope.
    """
    import owned_posix_family_workloads as workloads
    by_id = {workload.id: workload for workload in roster}
    owners = {symbol: workload.id for workload in roster for symbol in workload.primary_symbols}
    result = {'static': {}, 'dynamic': {}}
    for symbol, owner in owners.items():
        workload = by_id[owner]
        static_owner = owner
        if workload.product_scope == 'dynamic':
            require(symbol in workloads.STATIC_SUPPLEMENTAL_OWNERS,
                    f'no explicit static spelling workload: {symbol}')
            static_owner = workloads.STATIC_SUPPLEMENTAL_OWNERS[symbol]
        require(static_owner in by_id and by_id[static_owner].product_scope in ('static', 'both'),
                f'static spelling workload is absent: {symbol}')
        require(workload.product_scope in ('dynamic', 'both'), f'dynamic spelling workload is absent: {symbol}')
        result['static'][symbol] = {'workload': static_owner, 'cells': {
            f'{label}:{mode}': records[label][static_owner]['receipt']
            for label in PAIRS for mode in workloads.STATIC_LINKAGES}}
        result['dynamic'][symbol] = {'workload': owner, 'case': workload.dynamic_case, 'cells': {
            f'{PAIRS[label]}:{mode}:{entry}': records[label][owner]['receipt']
            for label in PAIRS for mode in workloads.DYNAMIC_LINKAGES for entry in workloads.DYNAMIC_ENTRIES}}
    return result


def collect(root: Path, work: Path) -> dict:
    work = physical(root, work)
    request = read(work / 'request.json')
    inputs, products = input_products(root, request)
    for name in ('source-before.json', 'source-after.json'):
        require(same_json(read(work / name), inputs['source']), f'execution source changed: {name}')
    roster = workload_roster()
    identifiers = {workload.id for workload in roster}
    require(len(identifiers) == len(roster), 'duplicate family workload')
    require({entry.name for entry in (work / 'runs').iterdir()} == set(PAIRS), 'execution product roster differs')
    records = {}
    for label in PAIRS:
        directory = work / 'runs' / label
        require({entry.name for entry in directory.iterdir()} == identifiers, 'execution workload roster differs')
        records[label] = {}
        for workload in roster:
            observed = collect_step(root, work, label, workload, products[label], request['source_mount'])
            receipt = directory / workload.id / 'receipt.json'
            require(same_json(read(receipt), observed), f'workload receipt changed: {label}/{workload.id}')
            records[label][workload.id] = {'receipt': file_identity(root, receipt), **observed}
    object_sets = {}
    for workload in roster:
        objects = {label: {role: identity['object']['sha256']
                          for role, identity in records[label][workload.id]['objects'].items()}
                   for label in PAIRS}
        identical_objects(objects)
        object_sets[workload.id] = objects['primary']
    require(same_json(static_products.source_identity(root), inputs['source']), 'source changed during matrix validation')
    return {'schema': SCHEMA, 'status': 'workload-matrix-verified',
            'family': 'libc.posix-runtime', 'work': work.relative_to(root).as_posix(),
            'inputs': inputs, 'request': file_identity(root, work / 'request.json'),
            'source_seals': {name: file_identity(root, work / name)
                             for name in ('source-before.json', 'source-after.json')},
            'workloads': json.loads(json.dumps([asdict(workload) for workload in roster])),
            'objects': object_sets, 'spelling_evidence': spelling_evidence(roster, records), 'runs': records,
            'native_aggregate_complete': False, 'family_completion': False, 'public_support': False}


def execute(root: Path, work: Path, static_preparation: Path, dynamic_qualification: Path) -> Path:
    import owned_dynamic_qualification as dynamic
    work = physical(root, work)
    require(not work.exists(), 'family execution requires a fresh run directory')
    request = {'schema': SCHEMA, 'source_mount': str(root),
               'static_preparation': physical(root, static_preparation).relative_to(root).as_posix(),
               'dynamic_qualification': physical(root, dynamic_qualification).relative_to(root).as_posix()}
    inputs, products = input_products(root, request)
    roster = workload_roster()
    # The required dynamic cases must exist in the complete source-bound
    # product qualification; canonical aliases may dispatch an explicit static
    # replay while keeping their registered dynamic case identity.
    require(all(workload.dynamic_case in dynamic.CASES for workload in roster
                if workload.product_scope != 'static'), 'unregistered dynamic family workload')
    work.mkdir(parents=True)
    static_products.write_new(work / 'request.json', request)
    static_products.write_new(work / 'source-before.json', inputs['source'])
    try:
        for label in PAIRS:
            for workload in roster:
                step = work / 'runs' / label / workload.id
                dynamic.require_live_oracle(root / inputs['dynamic_work'], inputs['oracle'])
                require(same_json(static_products.source_identity(root), inputs['source']),
                        'source changed before workload execution')
                print(f'POSIX matrix {label}/{workload.id}: running', flush=True)
                try:
                    run_step(root, step, case_command(root, workload, products[label], str(root)),
                             case_environment(root, step, str(root)))
                finally:
                    # Retention happens after runtime permission checks. It
                    # preserves executable/write bits and never follows links.
                    if step.exists():
                        static_products.make_retained_evidence_readable(step)
                dynamic.require_live_oracle(root / inputs['dynamic_work'], inputs['oracle'])
                require(same_json(static_products.source_identity(root), inputs['source']),
                        'source changed during workload execution')
                record = collect_step(root, work, label, workload, products[label], str(root))
                static_products.write_new(step / 'receipt.json', record)
                print(f'POSIX matrix {label}/{workload.id}: PASS', flush=True)
    finally:
        try:
            static_products.write_new(work / 'source-after.json', static_products.source_identity(root))
        except static_products.PreparationError as error:
            static_products.write_new(work / 'source-after-error.json', {'error': str(error)})
        static_products.make_retained_evidence_readable(work)
    result = collect(root, work)
    path = work / 'execution.json'
    static_products.write_new(path, result)
    static_products.make_retained_evidence_readable(work)
    return path


def validate_receipt(root: Path, path: Path) -> dict:
    path = physical(root, path)
    require(path.name == 'execution.json', 'expected execution.json receipt')
    observed = collect(root, path.parent)
    require(same_json(read(path), observed), 'family execution receipt changed')
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('--static-preparation', type=Path, required=True)
    run.add_argument('--dynamic-qualification', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'run':
            print(execute(ROOT, args.output, args.static_preparation, args.dynamic_qualification))
        else:
            validate_receipt(ROOT, args.receipt)
            print('owned POSIX workload matrix: valid; native aggregate and family closure remain separate')
    except (ExecutionError, static_products.PreparationError, OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f'owned POSIX workload execution failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

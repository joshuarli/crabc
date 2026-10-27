#!/usr/bin/env python3
"""Collect and replay the five source owners of six remaining native aliases."""
from __future__ import annotations

import argparse
from enum import Enum
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import core_image
import feature_archive_roster as feature_roster
import musl_oracle
import native_abi_inventory as inventory
import native_static_source_runtime_closure as source_runtime
import owned_dynamic_qualification as qualification
import owned_math_fenv_all_entry_receipt as math_receipt
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import public_data_ordinary_link_evidence as ordinary
from loader_debug_abi_evidence import Elf

ROOT = HERE.parents[1]
SCHEMA = 'crabc.x86_64-owned-feature-alias-receipt/v1'
ALIASES = {
    'signal': (('__sysv_signal', 'signal'), ('bsd_signal', 'signal')),
    'passwd': (('endpwent', 'setpwent'),),
    'exec': (('execvpe', '__execvpe'),),
    'temporary': (('mkostemps', '__mkostemps'),),
    'netdb': (('setnetent', 'sethostent'),),
}
FEATURES = {'signal': 'x86-signal-legacy-aliases', 'passwd': 'x86-owned-static-runtime',
            'exec': 'x86-process-exec', 'temporary': 'x86-owned-static-runtime', 'netdb': 'x86-netdb-setent'}
OWNER_SOURCES = {'signal': 'libc/src/c_abi/x86_64/signal_control.rs',
                 'passwd': 'libc/src/c_abi/x86_64/owned_passwd.rs',
                 'exec': 'libc/src/c_abi/x86_64/process_exec_path.rs',
                 'temporary': 'libc/src/c_abi/x86_64/temporary_objects.rs',
                 'netdb': 'libc/src/c_abi/x86_64/sethostent.rs'}
PROBES = {'signal': 'compat/x86_64/libc_signal_legacy_aliases_probe.c',
          'passwd': 'compat/x86_64/owned_passwd_probe.c',
          'exec': 'compat/x86_64/owned_process_control_probe.c',
          'temporary': 'compat/x86_64/owned_string_temporary_alias_contract_probe.c',
          'netdb': 'compat/x86_64/libc_sethostent_probe.c'}
OVERRIDES = {'signal': ('compat/x86_64/owned_feature_alias_override_probe.c', 'CRABC_FEATURE_SIGNAL_OVERRIDE'),
             'passwd': ('compat/x86_64/owned_feature_alias_override_probe.c', 'CRABC_FEATURE_PASSWD_OVERRIDE'),
             'exec': ('compat/x86_64/libc_process_exec_probe.c', 'CRABC_PROCESS_EXEC_STRONG_OVERRIDE'),
             'temporary': ('compat/x86_64/owned_string_temporary_alias_override_probe.c', None),
             'netdb': ('compat/x86_64/libc_sethostent_probe.c', 'CRABC_SETHOSTENT_OVERRIDE')}
PROBE_HEADERS = {
    PROBES['signal']: ('errno.h', 'signal.h'),
    PROBES['passwd']: tuple('errno.h fcntl.h pthread.h pwd.h signal.h stdio.h stdlib.h string.h sys/prctl.h sys/resource.h sys/stat.h sys/syscall.h sys/wait.h unistd.h'.split()),
    PROBES['exec']: tuple('errno.h fcntl.h limits.h pthread.h signal.h sched.h spawn.h stddef.h sys/resource.h sys/stat.h sys/syscall.h sys/types.h sys/wait.h sys/utsname.h unistd.h'.split()),
    PROBES['temporary']: tuple('errno.h fcntl.h stdio.h stdlib.h string.h sys/stat.h unistd.h'.split()),
    PROBES['netdb']: ('limits.h', 'netdb.h'),
    OVERRIDES['signal'][0]: ('errno.h', 'pwd.h', 'signal.h'),
    OVERRIDES['exec'][0]: tuple('errno.h fcntl.h stdint.h sys/prctl.h sys/syscall.h unistd.h'.split()),
    OVERRIDES['temporary'][0]: tuple('errno.h fcntl.h stdio.h stdlib.h string.h unistd.h'.split()),
}
PASSWD_CASES = ('lookup', 'ranges', 'enumeration', 'stream', 'output', 'missing', 'directory',
                'not-directory', 'read-error', 'open-error', 'local-only', 'threads',
                'database-contract', 'fork', 'cancellation', 'allocation')
MODES = ('static', 'static-pie', 'pie', 'non-pie')
ORACLE_CC = Path('/usr/local/bin/crabc-x86_64-musl-gcc')
SOURCE_FILES = tuple(sorted({*OWNER_SOURCES.values(), *PROBES.values(),
    *(row[0] for row in OVERRIDES.values()), 'compat/x86_64/owned_feature_alias_receipt.py',
    'compat/x86_64/feature_archive_roster.py', 'compat/x86_64/native_static_source_runtime_closure.py',
    'compat/x86_64/musl_oracle.py', 'docker/x86_64-musl-oracle-gcc',
    'compat/x86_64/parity.toml', 'libc/Cargo.toml', 'compat/upstreams.toml',
    'compat/x86_64/tests/test_owned_feature_alias_receipt.py'}))
FLAGS = {'family_completion': False, 'promotion_ready': False, 'public_support': False}


class FeatureAliasError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FeatureAliasError(message)


def same(left: object, right: object) -> bool:
    return ordinary.same_json(left, right)


def read(path: Path) -> dict[str, Any]:
    return inventory.read_json(path, 'feature alias receipt input')


def identity(path: Path) -> dict[str, Any]:
    return inventory.file_record(path, logical_path=path.relative_to(ROOT).as_posix())


def alias_requirements() -> dict[str, dict[str, Any]]:
    features = {row.identifier: row for row in feature_roster.load_feature_archive_roster()}
    result = {}
    for owner, pairs in ALIASES.items():
        feature = features[FEATURES[owner]]
        for public, target in pairs:
            aliases = [row for row in feature.aliases if row.name == public]
            require(len(aliases) == 1 and aliases[0].target == target
                    and aliases[0].binding == 'weak-same-address', 'source feature alias differs: ' + public)
            result[public] = {
                'name': public, 'target': target, 'binding': aliases[0].binding, 'owner': feature.identifier,
                'state': feature.state, 'evidence_record': feature.evidence_record, 'runner': feature.runner,
                'baseline_features': list(feature.baseline_features), 'enabled_features': list(feature.enabled_features),
                'feature_selection_source': feature.feature_selection_source,
                'sources': ['compat/x86_64/feature_archive_roster.py', 'compat/x86_64/parity.toml'],
            }
    return result


def source_product_seal(static: Path, dynamic: Path, preparation: Path) -> dict[str, Any]:
    prep = static_products.validate_receipt(ROOT, preparation)
    source = qualification.source_digest()
    require(prep['source']['content_sha256'] == source, 'static preparation source differs')
    require(any(ROOT / row['path'] == static for row in prep['products'].values()),
            'selected static product is absent from preparation')
    products.validate_dynamic_product_source(dynamic, source)
    static_manifest, _ = products._validate_static_product(static)
    dynamic_manifest, _ = products._validate_dynamic_product(dynamic)
    commands = read(static / 'share/crabc/build.commands.json')
    command = owned_runtime_command(commands)
    require(read(static_manifest)['allocator_backend'] == 'accepted-c', 'static product does not select the accepted C backend')
    shared_command = dynamic_runtime_command(read(dynamic / 'share/crabc/libc-shared.provenance.json'))
    return {'source': prep['source'], 'preparation': identity(preparation),
            'static_manifest': identity(static_manifest), 'dynamic_manifest': identity(dynamic_manifest),
            'static_tree': ordinary.execution_tree(ROOT, static, 'selected static product'),
            'dynamic_tree': ordinary.execution_tree(ROOT, dynamic, 'selected dynamic product'),
            'owned_runtime_command': command, 'dynamic_runtime_command': shared_command,
            'sources': {name: identity(ROOT / name) for name in SOURCE_FILES},
            'feature_alias_requirements': alias_requirements(), 'image': core_image.CORE_IMAGE_ID}


def owned_runtime_command(commands: dict[str, Any]) -> list[str]:
    require(commands['build_profile'] == 'release' and type(commands['commands']) is dict,
            'selected static producer command profile differs')
    command = commands['commands'].get('libc')
    require(type(command) is list and '-p' in command and 'crabc-libc' in command,
            'selected static libc command differs')
    require(command.count('--features') == 1 and command[command.index('--features') + 1] == 'x86-owned-static-runtime'
            and '--no-default-features' in command and '--release' in command,
            'selected owned-runtime feature activation differs')
    return command


def dynamic_runtime_command(provenance: dict[str, Any]) -> list[str]:
    command = provenance['libc_command']
    require(provenance['allocator_backend'] == 'accepted-c' and type(command) is list
            and command.count('--features') == 1
            and command[command.index('--features') + 1] == 'x86-owned-dynamic-runtime'
            and '--no-default-features' in command and '--release' in command,
            'selected dynamic owned-runtime feature or accepted C backend differs')
    return command


def tool_seal(static: Path, dynamic: Path) -> dict[str, Any]:
    result = math_receipt.expected_tool_seal(static, dynamic)
    pin = musl_oracle.load_pin(ROOT / 'compat/upstreams.toml')
    marker = Path('/opt/musl-1.2.6/.crabc-oracle')
    require(marker.read_text() == musl_oracle.manifest(pin), 'installed oracle source pin differs')
    require(ORACLE_CC.read_bytes() == (ROOT / 'docker/x86_64-musl-oracle-gcc').read_bytes(),
            'installed oracle compiler wrapper differs')
    result['oracle-pin'] = pin
    result['oracle-marker'] = math_receipt.tool_identity(marker)
    for name in ('ar', 'nm', 'readelf', 'env', 'timeout', 'chroot', 'python3', 'gcc', 'as', 'ld'):
        path = shutil.which(name, path='/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
        require(path is not None, 'missing image tool: ' + name)
        result[name] = {'invocation': path, **math_receipt.tool_identity(Path(path))}
    for name in ('lib/libc.a', 'lib/musl-gcc.specs'):
        result['oracle-' + name] = math_receipt.tool_identity(Path('/opt/musl-1.2.6') / name)
    return result


class Commands:
    def __init__(self, work: Path, capture: bool):
        self.work, self.capture = work, capture
        self.records: list[dict[str, Any]] = []
        self.environment = {'PATH': '/opt/cargo/bin:/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                            'TMPDIR': str(work / 'tmp'), 'CARGO_HOME': str(ROOT / '.work/x86_64/cargo'),
                            'RUSTUP_HOME': '/opt/rustup'}

    def run(self, label: str, argv: list[str], *, cwd: Path = ROOT, inspect: bool = False) -> bytes:
        prefix = self.work / 'commands' / label
        files = {name: prefix.with_suffix('.' + name) for name in ('stdout', 'stderr', 'status')}
        if self.capture:
            completed = subprocess.run(argv, cwd=cwd, env=self.environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            files['stdout'].write_bytes(completed.stdout)
            files['stderr'].write_bytes(completed.stderr)
            files['status'].write_text(str(completed.returncode) + '\n')
        require(files['status'].read_bytes() == b'0\n', 'feature alias command failed: ' + label)
        if inspect and not self.capture:
            completed = subprocess.run(argv, cwd=cwd, env=self.environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            require(completed.returncode == 0 and completed.stdout == files['stdout'].read_bytes()
                    and completed.stderr == files['stderr'].read_bytes(), 'ELF inspection differs: ' + label)
        self.records.append({'label': label, 'argv': argv, 'cwd': str(cwd),
                             'environment': self.environment,
                             'streams': {name: identity(path) for name, path in files.items()}})
        return files['stdout'].read_bytes()

    def runtime(self, label: str, argv: list[str], expected: bytes) -> None:
        require(self.run(label, argv) == expected, 'runtime transcript differs: ' + label)
        require((self.work / 'commands' / (label + '.stderr')).read_bytes() == b'',
                'runtime diagnostic differs: ' + label)


def inspect_elf(commands: Commands, label: str, path: Path, *, archive: bool = False, elf_type: str = 'DYN') -> Any:
    streams = [commands.run(label + '-' + suffix, ['/usr/bin/readelf', flag, str(path)], inspect=True).decode()
               for flag, suffix in (('-hW', 'header'), ('-SW', 'sections'), ('-sW', 'symbols'))]
    if archive:
        members = inventory.parse_archive_members(commands.run(label + '-members', ['/usr/bin/ar', 't', str(path)], inspect=True).decode())
        return inventory.parse_archive_elf_facts(*streams, members, expected_archive=str(path))
    return inventory.parse_elf_facts(*streams, expected_type=elf_type)


def definitions(facts: Any, name: str, *, table_name: str = '.symtab') -> list[dict[str, Any]]:
    result = []
    for member in facts if isinstance(facts, list) else [facts]:
        sections = {str(row['index']): row for row in member['sections']}
        for table in member['symbol_tables']:
            if table['name'] != table_name:
                continue
            for row in table['rows']:
                if row['name'] == name and row['section_index'] != 'UND':
                    result.append({'member_index': member.get('member_index'), 'member': member.get('member'),
                                   'table_section_index': table['section_index'], 'row': row,
                                   'section': sections.get(row['section_index'])})
    return result


class AliasPlacement(Enum):
    ARCHIVE = 'archive'
    SHARED = 'shared'
    EXECUTABLE = 'executable'


class OverrideBinding(Enum):
    GLOBAL = 'GLOBAL'
    LOCAL = 'LOCAL'


def alias_pair(facts: Any, public: str, target: str, *,
               placement: AliasPlacement = AliasPlacement.ARCHIVE) -> dict[str, Any]:
    require(isinstance(placement, AliasPlacement), 'unknown alias placement')
    left, right = definitions(facts, public), definitions(facts, target)
    require(len(left) == len(right) == 1, 'missing or ambiguous alias definitions: ' + public)
    left, right = left[0], right[0]
    hidden = target in {'__execvpe', '__mkostemps'}
    left_binding = 'LOCAL' if placement is AliasPlacement.EXECUTABLE else 'WEAK'
    right_binding = 'LOCAL' if placement is AliasPlacement.EXECUTABLE or (placement is AliasPlacement.SHARED and hidden) else 'GLOBAL'
    for item, binding, visibility in ((left, left_binding, 'DEFAULT'),
                                      (right, right_binding, 'HIDDEN' if hidden else 'DEFAULT')):
        row, section = item['row'], item['section']
        require(row['type'] == 'FUNC' and row['binding'] == binding and row['visibility'] == visibility
                and row['version'] is None and row['version_default'] is False
                and section is not None and section['type'] == 'PROGBITS' and 'X' in section['flags'],
                'alias definition metadata differs: ' + public)
    require(left['member_index'] == right['member_index']
            and left['table_section_index'] == right['table_section_index']
            and all(left['row'][name] == right['row'][name] for name in ('section_index', 'value', 'type', 'size_bytes')),
            'alias crosses its definition domain: ' + public)
    if placement is AliasPlacement.SHARED:
        dyn = definitions(facts, public, table_name='.dynsym')
        require(len(dyn) == 1 and all(dyn[0]['row'][name] == left['row'][name]
                                    for name in ('value', 'section_index', 'type', 'binding', 'visibility')),
                'public alias dynamic export differs: ' + public)
        require(not hidden or not definitions(facts, target, table_name='.dynsym'),
                'hidden alias target is dynamically exported: ' + target)
    return {'public': public, 'target': target, 'alias': left, 'provider': right}


def require_override_definitions(facts: Any, owner: str, binding: OverrideBinding) -> None:
    for public, _target in ALIASES[owner]:
        rows = definitions(facts, public)
        require(len(rows) == 1 and rows[0]['row']['type'] == 'FUNC'
                and rows[0]['row']['binding'] == binding.value and rows[0]['row']['visibility'] == 'DEFAULT'
                and rows[0]['section'] is not None and 'X' in rows[0]['section']['flags'],
                'caller strong override definition differs: ' + public)


def feature_proofs(commands: Commands) -> dict[str, Any]:
    work = commands.work
    result = {}
    features = {row.identifier: row for row in feature_roster.load_feature_archive_roster()}
    baseline = None
    for owner, feature in (('baseline', ''), ('signal', FEATURES['signal']), ('exec', FEATURES['exec']), ('netdb', FEATURES['netdb'])):
        graph = work / ('source-runtime-' + owner)
        argv = ['/usr/bin/python3', '-B', str(HERE / 'native_static_source_runtime_closure.py'), 'build', '--work', str(graph)]
        if feature:
            argv += ['--features', feature]
        commands.run('feature-build-' + owner, argv)
        with tempfile.TemporaryDirectory(dir=ROOT / '.work/tmp', prefix='feature-alias-replay-') as temporary:
            replay = source_runtime.replay_retained_graph(graph, feature, Path(temporary))
        archive = graph / 'cargo-target' / source_runtime.TARGET / 'debug/libc.a'
        facts = inspect_elf(commands, 'feature-' + owner, archive, archive=True)
        nm = commands.run('feature-' + owner + '-bindings', ['/usr/bin/nm', '-A', '-g', '--defined-only', str(archive)], inspect=True)
        bindings = math_receipt.archive_public_bindings(nm.decode(), 'feature ' + owner,
                                                      replay.source_runtime_members, replay.archive_members)
        if owner == 'baseline':
            baseline = bindings
            expected = {line.strip() for line in (ROOT / 'compat/x86_64/static_c_abi_exports.txt').read_text().splitlines()
                        if line.strip() and not line.lstrip().startswith('#')}
            require(set(bindings) == expected, 'isolated baseline archive public surface differs')
            continue
        roster = features[feature]
        require(roster.baseline_features == () and roster.enabled_features == (feature,),
                'isolated feature profile differs: ' + owner)
        additions = set(roster.additive_callables) | {name for pair in ALIASES[owner] for name in pair}
        additions -= set(baseline)
        require(set(bindings) == set(baseline) | additions
                and all(bindings[name] == value for name, value in baseline.items()),
                'isolated feature archive delta or baseline binding differs: ' + owner)
        result[owner] = {'profile': feature, 'archive': identity(archive), 'receipt': identity(graph / 'receipt.json'),
                         'additions': sorted(additions),
                         'aliases': [alias_pair(facts, public, target) for public, target in ALIASES[owner]]}
    return result


def probe_specs(owner: str) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    source, define = OVERRIDES[owner]
    flags = ('-D' + define,) if define is not None else ()
    main_flags = ('-DCRABC_PROCESS_CONTROL_EXECUTABLE="/consumer"',) if owner == 'exec' else ()
    return (('behavior', PROBES[owner], main_flags), ('override', source, flags))


def expected_transcript(owner: str, probe: str, oracle: bool) -> bytes:
    if probe == 'override':
        return b'owned-string-temporary-alias-override-ok\n' if owner == 'temporary' else b''
    if owner == 'temporary':
        return b'owned-string-temporary-alias-contract-ok\n'
    if owner == 'passwd':
        return b'owned passwd scenario passed\n'
    if owner == 'exec':
        return b'owned-process-control-ok fexecve-seccomp=' + (b'9\n' if oracle else b'38\n')
    return b''


def probe_dependencies(dependency: Path, source: Path, obj: Path, dynamic: Path) -> dict[str, Any]:
    dependency = inventory.physical_regular(dependency, 'feature alias compiler dependency file')
    text = dependency.read_text().replace('\\\r\n', ' ').replace('\\\n', ' ')
    require(':' in text, 'compiler dependency file lacks its object target')
    target, values = text.split(':', 1)
    require(target.strip() == str(obj), 'compiler dependency object target differs')
    names = values.split()
    require(names and len(names) == len(set(names)) and names.count(str(source)) == 1,
            'compiler dependency source or path roster differs')
    headers = {}
    header_root = dynamic / 'usr/include'
    for name in names:
        require('\\' not in name and '..' not in Path(name).parts,
                'compiler dependency path uses unsupported escaping or traversal')
        path = inventory.physical_regular(Path(name), 'feature alias compiler dependency input')
        if path == source:
            continue
        require(path.is_relative_to(header_root), 'compiler dependency escapes selected installed headers')
        headers[path.relative_to(header_root).as_posix()] = identity(path)
    expected = PROBE_HEADERS[source.relative_to(ROOT).as_posix()]
    require(set(expected) <= set(headers), 'compiler dependency file omits a required installed header')
    return {'dependency_file': identity(dependency), 'source': identity(source), 'headers': headers}


def copied_consumer(binary: Path, copied: Path) -> dict[str, Any]:
    binary = inventory.physical_regular(binary, 'feature alias linked consumer')
    copied = inventory.physical_regular(copied, 'feature alias copied consumer')
    require(copied.read_bytes() == binary.read_bytes(), 'copied consumer differs')
    mode = stat.S_IMODE(binary.stat().st_mode)
    require(mode & 0o111 and stat.S_IMODE(copied.stat().st_mode) == mode, 'copied consumer mode differs')
    return identity(copied)


def copied_payload(dynamic: Path, root: Path, binary: Path, *, capture: bool) -> dict[str, Any]:
    manifest, files = products._validate_dynamic_product(dynamic)
    aliases = read(manifest)['symlinks']
    if capture:
        shutil.copytree(dynamic, root, symlinks=True)
        shutil.copy2(binary, root / 'consumer')
    consumer = copied_consumer(binary, root / 'consumer')
    directories = {Path('.')}
    for name, expected in files.items():
        require(inventory.sha256(root / name) == expected, 'copied selected payload differs: ' + name)
        require(stat.S_IMODE((root / name).stat().st_mode) == stat.S_IMODE((dynamic / name).stat().st_mode),
                'copied selected payload mode differs: ' + name)
        directories.update(Path(name).parents)
    for name in directories:
        copied = root / name
        require(copied.is_dir() and not copied.is_symlink()
                and stat.S_IMODE(copied.stat().st_mode) == stat.S_IMODE((dynamic / name).stat().st_mode),
                'copied selected directory mode differs: ' + name.as_posix())
    for name, target in aliases.items():
        require((root / name).is_symlink() and os.readlink(root / name) == target,
                'copied selected alias differs: ' + name)
    return {'manifest': identity(manifest), 'consumer': consumer,
            'files': files, 'aliases': aliases}


def installed_owner(commands: Commands, owner: str, static: Path, dynamic: Path,
                    installed_facts: dict[str, Any]) -> dict[str, Any]:
    work = commands.work / owner
    if commands.capture:
        work.mkdir()
    pairs = {key: [alias_pair(facts, public, target, placement=AliasPlacement.SHARED if key == 'shared' else AliasPlacement.ARCHIVE) for public, target in ALIASES[owner]]
             for key, facts in installed_facts.items()}
    binaries, links, runs, payloads, objects, dependencies = {}, {}, [], {}, {}, {}
    for probe, source, defines in probe_specs(owner):
        obj = work / (probe + '.o')
        commands.run(owner + '-' + probe + '-compile', [str(dynamic / 'bin/crabc-cc-dynamic'), '--dynamic-pie',
                     '-std=c11', '-D_GNU_SOURCE', '-fno-builtin', '-fno-stack-protector', '-pthread', *defines,
                     '--application-dependency-file', str(work / (probe + '.d')),
                     '-c', str(ROOT / source), '-o', str(obj)])
        dependencies[probe] = probe_dependencies(work / (probe + '.d'), ROOT / source, obj, dynamic)
        objects[probe] = identity(obj)
        if probe == 'override':
            require_override_definitions(inspect_elf(commands, owner + '-override-object', obj, elf_type='REL'), owner, OverrideBinding.GLOBAL)
        for mode in ('oracle', *MODES):
            name = owner + '-' + probe + '-' + mode
            executable = work / (probe + '-' + mode)
            if mode == 'oracle':
                argv = [str(ORACLE_CC), '-static', '-fno-pie', '-no-pie', '-pthread', str(obj), '-o', str(executable)]
            elif mode in ('static', 'static-pie'):
                argv = [str(static / 'bin/crabc-cc'), '-' + mode, '--link-receipt', executable.name + '.link.json',
                        str(obj), '-o', str(executable)]
            else:
                argv = [str(dynamic / 'bin/crabc-cc-dynamic'), '--dynamic-' + mode, '-pthread', str(obj), '-o', str(executable)]
            commands.run(name + '-link', argv, cwd=work)
            binaries[probe + '-' + mode] = identity(executable)
            if mode != 'oracle':
                receipt = executable.with_name(executable.name + '.link.json') if mode.startswith('static') else Path(str(executable) + '.crabc-link.json')
                product = static if mode.startswith('static') else dynamic
                links[probe + '-' + mode] = products.validate_link(product, obj, executable, receipt, mode)
            final = inspect_elf(commands, name + '-final', executable, elf_type='DYN' if mode in ('static-pie', 'pie') else 'EXEC')
            if probe == 'override':
                require_override_definitions(final, owner, OverrideBinding.LOCAL if mode in ('oracle', 'static', 'static-pie') else OverrideBinding.GLOBAL)
            elif mode in ('static', 'static-pie'):
                for public, target in ALIASES[owner]:
                    alias_pair(final, public, target, placement=AliasPlacement.EXECUTABLE)
            entries = ('kernel', 'direct') if mode in ('pie', 'non-pie') else ('process',)
            for entry in entries:
                root = work / (probe + '-' + mode + '-' + entry + '-root')
                dynamic_mode = mode in ('pie', 'non-pie')
                before = copied_payload(dynamic, root, executable, capture=commands.capture) if dynamic_mode else None
                if commands.capture:
                    if not dynamic_mode:
                        root.mkdir()
                        shutil.copy2(executable, root / 'consumer')
                    (root / 'scratch').mkdir(exist_ok=True)
                    (root / 'etc').mkdir(exist_ok=True)
                consumer_before = copied_consumer(executable, root / 'consumer')
                scenarios = PASSWD_CASES if owner == 'passwd' and probe == 'behavior' else ('once',)
                for scenario in scenarios:
                    args = [scenario, 'oracle' if mode == 'oracle' else 'owned'] if owner == 'passwd' and probe == 'behavior' else ['/scratch'] if owner == 'temporary' else []
                    launch = ['/lib/ld-crabc-x86_64.so.1', '/consumer'] if entry == 'direct' else ['/consumer']
                    label = name + '-' + entry + '-' + scenario
                    commands.runtime(label, ['/usr/bin/timeout', '60', '/usr/bin/env', '-i', 'PATH=/', 'EXEC_TOKEN=parent',
                                             'LC_ALL=C', '/usr/sbin/chroot', str(root), *launch, *args],
                                     expected_transcript(owner, probe, mode == 'oracle'))
                    runs.append(label)
                consumer_after = copied_consumer(executable, root / 'consumer')
                require(same(consumer_before, consumer_after), 'copied consumer changed during workload')
                if dynamic_mode:
                    after = copied_payload(dynamic, root, executable, capture=False)
                    require(same(before, after), 'copied product changed during workload')
                    payloads[probe + '-' + mode + '-' + entry] = after
                else:
                    payloads[probe + '-' + mode + '-' + entry] = {'consumer': consumer_after}
    return {'feature_owner': FEATURES[owner], 'owner_source': identity(ROOT / OWNER_SOURCES[owner]),
            'aliases': pairs, 'objects': objects, 'dependencies': dependencies, 'binaries': binaries, 'links': links,
            'runtime_cells': runs, 'payloads': payloads}


def reconstruct(work: Path, static: Path, dynamic: Path, preparation: Path, *, capture: bool) -> dict[str, Any]:
    before = source_product_seal(static, dynamic, preparation)
    tools_before = tool_seal(static, dynamic)
    commands = Commands(work, capture)
    if capture:
        (work / 'commands').mkdir()
        (work / 'tmp').mkdir()
    features = feature_proofs(commands)
    installed = {'static': inspect_elf(commands, 'installed-static', static / 'usr/lib/libc.a', archive=True),
                 'shared': inspect_elf(commands, 'installed-shared', dynamic / 'usr/lib/libc.so')}
    owners = {owner: installed_owner(commands, owner, static, dynamic, installed) for owner in ALIASES}
    for owner in ('passwd', 'temporary'):
        owners[owner]['feature_selection'] = {'preparation': before['preparation'],
                                             'command': before['owned_runtime_command']}
    for owner in features:
        owners[owner]['feature_selection'] = features[owner]
    after = source_product_seal(static, dynamic, preparation)
    require(same(before, after), 'source or selected products changed during component proof')
    tools_after = tool_seal(static, dynamic)
    require(same(tools_before, tools_after), 'native tools changed during component proof')
    return {'schema': SCHEMA, 'source_products_before': before, 'source_products_after': after,
            'tools': tools_before, 'commands': commands.records, 'owners': owners, **FLAGS}


def validate_report(path: Path, *, static_product: Path, dynamic_product: Path,
                    static_preparation: Path) -> dict[str, Any]:
    path = inventory.physical_regular(path, 'feature alias report')
    require(path.name == 'report.json' and path.is_relative_to(ROOT / '.work'), 'feature alias report path differs')
    record = read(path)
    observed = reconstruct(path.parent, static_product, dynamic_product, static_preparation, capture=False)
    require(same(record, observed), 'feature alias receipt does not reconstruct from source and selected products')
    return observed


def collect(output: Path, *, static_product: Path, dynamic_product: Path, static_preparation: Path) -> Path:
    output = ordinary.fresh_output(ROOT, output)
    require(output.is_relative_to(ROOT / '.work/x86_64'), 'feature alias output must be below .work/x86_64')
    ordinary.admit_output_disjoint(ROOT, output, static_preparation, static_product, dynamic_product)
    (ROOT / '.work/tmp').mkdir(parents=True, exist_ok=True)
    output.mkdir()
    record = reconstruct(output, static_product, dynamic_product, static_preparation, capture=True)
    path = output / 'report.json'
    path.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'validate-report'))
    parser.add_argument('path', type=Path)
    for name in ('static-product', 'dynamic-product', 'static-preparation'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    inputs = {name: Path(os.path.abspath(getattr(args, name))) for name in ('static_product', 'dynamic_product', 'static_preparation')}
    try:
        if args.mode == 'collect':
            print(collect(Path(os.path.abspath(args.path)), **inputs))
        else:
            validate_report(Path(os.path.abspath(args.path)), **inputs)
            print('owned feature aliases: component proof valid; qualification remains false')
    except (FeatureAliasError, OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f'owned feature aliases: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

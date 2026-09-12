#!/usr/bin/env python3
"""Focused native loader debugger and CRT ABI evidence; no promotion authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ORACLE = Path('/opt/musl-1.2.6/lib/libc.so')
CC = '/usr/local/bin/crabc-x86_64-musl-gcc'
INTERPRETER = '/lib/ld-crabc-x86_64.so.1'
SCHEMA = 'crabc.x86_64-loader-debug-crt-abi/v1'
PUBLIC = {'_dl_debug_addr': ('OBJECT', 'GLOBAL', 8),
          '_dl_debug_state': ('FUNC', 'WEAK', None),
          '_init': ('FUNC', 'WEAK', None), '_fini': ('FUNC', 'WEAK', None)}
OUTPUTS = {'debug': 'loader-debug-abi-ok\n', 'copy': 'loader-debug-abi-ok\n', 'interpose': 'loader-debug-abi-ok\n',
           'crt': 'loader-crt-abi-ok\n', 'lifecycle': 'loader-crt-lifecycle-ok\n',
           'archive-default': '', 'archive-override': ''}
WORKLOADS = [
    ('debug', 'loader_debug_abi_probe.c', ['-fPIC']),
    ('copy', 'loader_debug_abi_probe.c', ['-fPIE', '-DDEBUG_COPY_REFERENCE']),
    ('crt', 'loader_crt_abi_probe.c', ['-fPIC']),
    ('lifecycle', 'loader_crt_lifecycle_probe.c', ['-fPIC']),
    ('plugin', 'loader_debug_abi_plugin.c', ['-fPIC']),
    ('interposer', 'loader_debug_abi_interpose.c', ['-fPIC']),
    ('archive', 'loader_crt_archive_probe.c', ['-fPIE']),
    ('override', 'loader_crt_archive_override.c', ['-fPIE']),
]


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Elf:
    """Read selected symbol/relocation facts directly from retained ELF bytes."""
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b'\x7fELF\x02\x01\x01', 'expected ELF64 little endian')
        self.elf_type = self.unpack('<H', 16)[0]
        require(self.unpack('<H', 18)[0] == 62, 'expected native x86-64 ELF')
        self.entry = self.unpack('<Q', 24)[0]
        phoff = self.unpack('<Q', 32)[0]
        phsize, phcount = self.unpack('<HH', 54)
        require(phcount == 0 or phsize == 56, 'malformed ELF program table')
        self.programs = [self.unpack('<IIQQQQQQ', phoff + index * phsize) for index in range(phcount)]
        offset = self.unpack('<Q', 40)[0]
        size, count = self.unpack('<HH', 58)
        require(size == 64 and count > 0, 'missing ELF section table')
        self.sections = [self.unpack('<IIQQQQIIQQ', offset + index * size) for index in range(count)]

    def unpack(self, shape, offset):
        require(0 <= offset <= len(self.data) - struct.calcsize(shape), 'truncated ELF record')
        return struct.unpack_from(shape, self.data, offset)

    def symbol_row(self, section_index, index):
        section = self.sections[section_index]
        require(section[1] in (2, 11) and section[9] == 24 and index < section[5] // 24,
                'invalid ELF symbol index')
        name, info, other, owner, value, size = self.unpack('<IBBHQQ', section[4] + index * 24)
        strings = self.sections[section[6]]
        require(strings[1] == 3 and name < strings[5], 'invalid ELF symbol name')
        start, limit = strings[4] + name, strings[4] + strings[5]
        require(limit <= len(self.data), 'truncated ELF strings')
        end = self.data.find(b'\0', start, limit)
        require(end >= 0, 'unterminated ELF symbol')
        version = 1
        for versions in self.sections:
            if versions[1] == 0x6fffffff and versions[6] == section_index:
                require(index * 2 + 2 <= versions[5], 'truncated symbol version table')
                version = self.unpack('<H', versions[4] + index * 2)[0]
        return {'name': self.data[start:end].decode('ascii'), 'type': {1: 'OBJECT', 2: 'FUNC'}.get(info & 15, str(info & 15)),
                'binding': {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}.get(info >> 4, str(info >> 4)),
                'visibility': {0: 'DEFAULT', 2: 'HIDDEN', 3: 'PROTECTED'}.get(other & 3, str(other & 3)),
                'section': owner, 'value': value, 'size': size, 'version_index': version}

    def symbol(self, name, dynamic=True, required=True):
        found = []
        for index, section in enumerate(self.sections):
            if section[1] != (11 if dynamic else 2):
                continue
            require(section[5] % 24 == 0, 'malformed symbol table size')
            for number in range(section[5] // 24):
                row = self.symbol_row(index, number)
                if row['name'] == name and row['section'] != 0:
                    found.append(row)
        require(len(found) <= 1 and (bool(found) or not required), f'missing/duplicate {name}')
        return found[0] if found else None

    def copy_relocations(self, name):
        rows = []
        for section in self.sections:
            if section[1] != 4:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'malformed RELA table')
            for offset in range(0, section[5], 24):
                destination, info, addend = self.unpack('<QQq', section[4] + offset)
                if info & 0xffffffff == 5 and self.symbol_row(section[6], info >> 32)['name'] == name:
                    rows.append({'destination': destination, 'addend': addend})
        return rows


def public_metadata(path):
    elf = Elf(path)
    result = {}
    for name, (kind, binding, size) in PUBLIC.items():
        row = elf.symbol(name)
        require(row['type'] == kind and row['binding'] == binding and row['visibility'] == 'DEFAULT'
                and row['version_index'] in (0, 1) and (size is None or row['size'] == size),
                f'public ABI metadata differs: {name}')
        result[name] = row
    return result


def trace_events(text):
    events = []
    for line in text.splitlines():
        match = re.fullmatch(r'debug-event=([01]),maps-added=([01])', line)
        require(match is not None, 'malformed debugger event')
        events.append(tuple(map(int, match.groups())))
    require(5 <= len(events) <= 255 and len(events) % 2 == 1 and events[0] == (0, 0),
            'missing initial or paired debugger events')
    previous = 0
    for index, (state, added) in enumerate(events):
        require(state == index % 2, 'unbalanced debugger transaction')
        require(added >= previous and (added == previous or state == 0), 'debugger graph mutation outside commit')
        previous = added
    require(previous == 1, 'missing runtime plugin publication')
    return [list(row) for row in events]


def expected_cases():
    result = set()
    for lane in ('oracle', 'candidate'):
        for mode in ('pie', 'non-pie'):
            for entry in ('kernel', 'direct'):
                for probe in ('debug', 'copy', 'interpose', 'crt', 'lifecycle'):
                    result.add(f'{lane}-{mode}-{entry}-{probe}')
                result.add(f'{lane}-{mode}-{entry}-trace')
                result.add(f'{lane}-{mode}-{entry}-interpose-trace')
        for mode in ('static', 'static-pie'):
            for probe in ('lifecycle', 'archive-default', 'archive-override'):
                result.add(f'{lane}-{mode}-{probe}')
    return result


def relative(path):
    path = Path(path).resolve()
    require(path.is_relative_to(ROOT), 'evidence path outside checkout')
    return path.relative_to(ROOT).as_posix()


def record(path):
    return {'path': relative(path), 'sha256': digest(path), 'size': Path(path).stat().st_size}


def artifact(item):
    path = ROOT / item['path']
    require(not Path(item['path']).is_absolute() and path.is_relative_to(ROOT / '.work')
            and path.resolve() == path and path.is_file() and not path.is_symlink(), 'unsafe evidence artifact')
    require(record(path) == item, f'artifact identity changed: {path}')
    return path


def validate_report(path):
    import owned_dynamic_qualification as qualification
    report = json.loads(Path(path).read_text())
    require(report['schema'] == SCHEMA and report['status'] == 'component-verified'
            and report['family_complete'] is False and report['public_support'] is False, 'invalid component boundary')
    require(report['source_sha256'] == qualification.source_digest(), 'evidence source changed')
    require(report['source_commit'] == qualification.git('rev-parse', 'HEAD').decode().strip(), 'evidence revision changed')
    require(re.fullmatch(r'crabc-core-evidence@sha256:[0-9a-f]{64}', report['image']) is not None, 'missing pinned image identity')
    for item in report['artifacts'].values():
        artifact(item)
    metadata = public_metadata(artifact(report['artifacts']['candidate-libc']))
    require(report['public_metadata'] == metadata, 'changed public metadata result')
    loader_elf = Elf(artifact(report['artifacts']['candidate-loader']))
    loader_hook = loader_elf.symbol('_dl_debug_state')
    require(loader_hook['type'] == 'FUNC' and loader_hook['binding'] == 'WEAK'
            and loader_hook['visibility'] == 'DEFAULT' and loader_hook['version_index'] in (0, 1),
            'loader breakpoint export metadata changed')
    require(report['loader_hook_metadata'] == loader_hook, 'changed loader hook result')
    require(public_metadata(artifact(report['artifacts']['oracle-libc'])), 'invalid oracle metadata')
    qualification.validate_oracle(Path(path).resolve().parent, report['oracle'])
    require(report['oracle']['runtime_sha256'] == report['artifacts']['oracle-libc']['sha256'],
            'oracle bytes differ from retained pinned oracle identity')
    require(set(report['executions']) == expected_cases(), 'incomplete execution roster')
    commands = json.loads(artifact(report['artifacts']['commands']).read_text())
    for command in commands:
        require(command['status'] == 0, 'failed retained build/link command')
        artifact(command['stdout'])
        artifact(command['stderr'])
    for probe, source_name, flags in WORKLOADS:
        rows = [row for row in commands if Path(row['stdout']['path']).name == 'compile-' + probe + '.stdout']
        require(len(rows) == 1, 'workload was not compiled exactly once')
        command = rows[0]['command']
        object_path = report['artifacts'][probe + '-object']['path']
        source_path = 'compat/x86_64/' + source_name
        require(command[:-3] == [CC, '-std=c11', '-fno-stack-protector', *flags, '-c']
                and command[-3] in (str(ROOT / source_path), '/workspace/' + source_path)
                and command[-2] == '-o'
                and command[-1] in (str(ROOT / object_path), '/workspace/' + object_path),
                'workload source/object compile identity differs')
    for name, execution in report['executions'].items():
        observed = {key: value for key, value in execution.items() if key not in ('events', 'linked_input')}
        require(commands.count(observed) == 1, 'execution does not match retained command')
        require(execution['status'] == 0, f'failed execution: {name}')
        parts = name.split('-')
        lane = parts[0]
        mode = 'non-pie' if parts[1:3] == ['non', 'pie'] else ('static-pie' if parts[1:3] == ['static', 'pie'] else parts[1])
        probe = ('interpose' if name.endswith('-interpose-trace') else 'debug') if name.endswith('-trace') else next(key for key in OUTPUTS if name.endswith('-' + key))
        require(execution['linked_input'] == report['artifacts'][f'{lane}-{mode}-{probe}-elf'], 'execution uses a different linked input')
        stdout = artifact(execution['stdout']).read_text()
        stderr = artifact(execution['stderr']).read_text()
        if name.endswith('-trace'):
            require(stdout == OUTPUTS['debug'], 'trace consumer failed')
            require(execution['events'] == trace_events(stderr), 'changed debugger event result')
            provider_elf = Elf(artifact(report['artifacts'][lane + '-libc']))
            observed_loader = loader_elf if lane == 'candidate' else provider_elf
            command = execution['command']
            observer_path = report['artifacts']['observer']['path']
            require(len(command) == 10 and command[:2] == ['timeout', '25']
                    and command[2] in (str(ROOT / observer_path), '/workspace/' + observer_path)
                    and command[5:8] == ['/consumer', str(observed_loader.entry),
                                             str(observed_loader.symbol('_dl_debug_state')['value'])]
                    and command[9] == str(provider_elf.symbol('_dl_debug_addr')['value']),
                    'trace does not observe the inspected loader export and libc pointer')
        else:
            probe = next(key for key in OUTPUTS if name.endswith('-' + key))
            require(stdout == OUTPUTS[probe] and stderr == '', f'changed observable result: {name}')
    for name, item in report['artifacts'].items():
        if name.endswith('-elf'):
            binary_name = name.removesuffix('-elf')
            binary_elf = Elf(artifact(item))
            fixed = '-non-pie-' in binary_name or ('-static-' in binary_name and '-static-pie-' not in binary_name)
            require(binary_elf.elf_type == (2 if fixed else 3), 'execution ELF type differs from selected mode')
            interpreters = sum(row[0] == 3 for row in binary_elf.programs)
            require(interpreters == (0 if '-static-' in binary_name else 1), 'execution interpreter boundary changed')
            matching = [command for command in commands if Path(command['stdout']['path']).name == 'link-' + binary_name + '.stdout']
            require(len(matching) == 1, 'missing exact final-link command')
            command = matching[0]['command']
            probe = 'archive' if '-archive-' in binary_name else binary_name.rsplit('-', 1)[1]
            if probe == 'interpose': probe = 'debug'
            object_path = report['artifacts'][probe + '-object']['path']
            require(any(value in (str(ROOT / object_path), '/workspace/' + object_path) for value in command), 'final link did not consume the shared workload object')
            if binary_name.endswith('-interpose'):
                interposer = report['artifacts']['interposer-object']['path']
                require('-rdynamic' in command and any(value in (str(ROOT / interposer), '/workspace/' + interposer) for value in command),
                        'missing strong application interposer input')
                symbol = Elf(artifact(item)).symbol('_dl_debug_state')
                require(symbol['binding'] == 'GLOBAL' and symbol['type'] == 'FUNC'
                        and symbol['visibility'] == 'DEFAULT', 'application hook is not a strong exported definition')
            require(not any('whole-archive' in value for value in command), 'ordinary extraction replaced by whole archive')
            if '-archive-' in binary_name:
                require('-nostdlib' in command and command[0] == CC, 'archive extraction command changed')
                override = report['artifacts']['override-object']['path']
                has_override = any(value in (str(ROOT / override), '/workspace/' + override) for value in command)
                require(has_override == binary_name.endswith('-override'), 'archive override object selection changed')
        if name.endswith('-copy-elf'):
            copies = Elf(artifact(item)).copy_relocations('_dl_debug_addr')
            require(len(copies) == 1 and copies[0]['addend'] == 0, 'missing exact debugger COPY relocation')
        if name.endswith('-archive-default-elf') or name.endswith('-archive-override-elf'):
            binding = 'WEAK' if '-default-' in name else 'GLOBAL'
            for hook in ('_init', '_fini'):
                row = Elf(artifact(item)).symbol(hook, dynamic=False)
                require(row['type'] == 'FUNC' and row['binding'] == binding, 'archive provider binding changed')
    require(report['oracle_trace_events'] == report['executions']['oracle-pie-kernel-trace']['events'], 'oracle trace changed')
    for name, execution in report['executions'].items():
        if name.endswith('-trace'):
            require(execution['events'] == report['oracle_trace_events'], f'not the same debugger transaction sequence: {name}')
    import crabc_cc_owned_dynamic
    import crabc_cc_static
    dynamic = artifact(report['artifacts']['dynamic-manifest']).parents[2]
    static = artifact(report['artifacts']['static-manifest']).parents[2]
    crabc_cc_owned_dynamic.validate(dynamic)
    crabc_cc_static.validate_installed_runtime(static)
    for item in report['artifacts'].values():
        artifact(item)
    return report


class Collector:
    def __init__(self, output):
        self.output = output.resolve()
        require(self.output.is_relative_to(ROOT / '.work') and not self.output.exists(), 'output must be a fresh .work directory')
        self.output.mkdir(parents=True)
        (self.output / 'raw').mkdir()
        self.commands = []
        self.artifacts = {}
        self.executions = {}

    def keep(self, name, path):
        self.artifacts[name] = record(path)
        return path

    def run(self, name, command, expected=0):
        stdout, stderr = [self.output / 'raw' / (name + suffix) for suffix in ('.stdout', '.stderr')]
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run([str(value) for value in command], cwd=ROOT, stdout=out, stderr=err, timeout=300)
        row = {'command': [str(value) for value in command], 'status': result.returncode,
               'stdout': record(stdout), 'stderr': record(stderr)}
        self.commands.append(dict(row))
        (self.output / 'commands.json').write_text(json.dumps(self.commands, indent=2) + '\n')
        require(result.returncode == expected, f'{name} failed ({result.returncode}); {stderr}')
        return row

    def execute(self, name, command, probe, binary):
        row = self.run(name, command)
        require(artifact(row['stdout']).read_text() == OUTPUTS[probe], f'{name}: wrong output')
        if name.endswith('-trace'):
            row['events'] = trace_events(artifact(row['stderr']).read_text())
        else:
            require(artifact(row['stderr']).read_text() == '', f'{name}: unexpected diagnostic')
        self.executions[name] = {**row, 'linked_input': record(binary)}

    def collect(self):
        import owned_dynamic_qualification as qualification
        source = qualification.source_digest()
        commit = qualification.require_clean_source()
        image = os.environ.get('CRABC_LOADER_DEBUG_IMAGE_ID', '')
        require(re.fullmatch(r'crabc-core-evidence@sha256:[0-9a-f]{64}', image) is not None, 'dispatcher must supply CRABC_LOADER_DEBUG_IMAGE_ID')
        self.run('oracle-pin', ['bash', ROOT / 'compat/x86_64/run_musl_oracle.sh'])
        loader_tests = self.output / 'loader-tests'
        test_cfg = ['crabc_general_initial_graph', 'crabc_general_initial_lifecycle',
                    'crabc_general_initial_tls_materialization_v1', 'crabc_general_loader_libc_tls_runtime_v1',
                    'crabc_dynamic_main_thread_runtime_v1', 'feature="x86_64-owned-dynamic-runtime"']
        self.run('compile-loader-tests', ['rustc', '--edition=2021', '--test',
                 *[value for cfg in test_cfg for value in ('--cfg', cfg)],
                 ROOT / 'ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs', '-o', loader_tests])
        self.keep('loader-tests', loader_tests)
        self.run('loader-tests', [loader_tests])
        oracle = qualification.capture_oracle(self.output)
        for name in qualification.ORACLE_FILES:
            self.keep('oracle-' + name, self.output / 'qualification-oracle' / name)
        for name in ('libc.a', 'crt1.o', 'rcrt1.o', 'crti.o', 'crtn.o'):
            saved = self.output / ('oracle-' + name)
            shutil.copyfile(ORACLE.with_name(name), saved)
            self.keep('oracle-' + name, saved)
        static, dynamic = [self.output / value for value in ('static-product', 'dynamic-product')]
        self.run('build-static', ['python3', '-B', ROOT / 'scripts/build_x86_64_owned_sysroot.py', '--output', static])
        self.run('build-dynamic', ['python3', '-B', ROOT / 'scripts/build_x86_64_owned_dynamic_sysroot.py', '--output', dynamic])
        state = json.loads((dynamic / 'share/crabc/dynamic-product-state.json').read_text())
        require(state['source_sha256'] == source, 'dynamic product source differs')
        for lane, path in [('candidate', dynamic / 'usr/lib/libc.so'), ('oracle', ORACLE)]:
            if lane == 'oracle':
                saved = self.output / 'oracle-libc.so'
                shutil.copyfile(path, saved)
                path = saved
            self.keep(lane + '-libc', path)
        self.keep('static-manifest', static / 'share/crabc/manifest.json')
        self.keep('dynamic-manifest', dynamic / 'share/crabc/manifest.json')
        self.keep('dynamic-state', dynamic / 'share/crabc/dynamic-product-state.json')
        self.keep('candidate-loader', dynamic / 'lib/ld-crabc-x86_64.so.1')
        objects = {}
        for probe, source_name, flags in WORKLOADS:
            objects[probe] = self.output / (probe + '.o')
            self.run('compile-' + probe, [CC, '-std=c11', '-fno-stack-protector', *flags, '-c',
                     ROOT / 'compat/x86_64' / source_name, '-o', objects[probe]])
            self.keep(probe + '-object', objects[probe])
        observer = self.output / 'debugger-observer'
        self.run('compile-observer', [CC, '-static', '-no-pie', '-std=c11', ROOT / 'compat/x86_64/loader_debug_abi_trace.c', '-o', observer])
        self.keep('observer', observer)
        for lane in ('oracle', 'candidate'):
            execution_root = self.output / (lane + '-root')
            if lane == 'candidate':
                shutil.copytree(dynamic, execution_root, symlinks=True)
                provider = execution_root / 'usr/lib/libc.so'
                loader = execution_root / INTERPRETER.lstrip('/')
                interpreter = INTERPRETER
                hook = Elf(loader).symbol('_dl_debug_state')
                require(hook['binding'] == 'WEAK' and hook['type'] == 'FUNC' and hook['visibility'] == 'DEFAULT', 'loader debugger hook metadata differs')
                driver = dynamic / 'bin/crabc-cc-dynamic'
                plugin = self.output / 'candidate-plugin.so'
                self.run('link-candidate-plugin', [driver, '--dynamic-shared-object', objects['plugin'], '-o', plugin])
            else:
                provider = execution_root / ORACLE.relative_to('/')
                provider.parent.mkdir(parents=True)
                shutil.copy2(ORACLE, provider)
                interpreter = '/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1'
                loader = execution_root / interpreter.lstrip('/')
                loader.symlink_to('libc.so')
                hook = Elf(provider).symbol('_dl_debug_state')
                plugin = self.output / 'oracle-plugin.so'
                self.run('link-oracle-plugin', [CC, '-shared', objects['plugin'], '-Wl,-soname,libloader-debug-plugin.so', '-o', plugin])
            plugin_target = execution_root / 'usr/lib/libloader-debug-plugin.so'
            plugin_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(plugin, plugin_target)
            # Both roots use the ordinary default library search path.
            if lane == 'oracle':
                (execution_root / 'lib').mkdir()
                (execution_root / 'lib/libloader-debug-plugin.so').symlink_to('/usr/lib/libloader-debug-plugin.so')
            self.keep(lane + '-plugin', plugin)
            for mode in ('pie', 'non-pie'):
                for probe in ('debug', 'copy', 'interpose', 'crt', 'lifecycle'):
                    binary = self.output / f'{lane}-{mode}-{probe}'
                    command = ([driver, '--dynamic-' + mode] if lane == 'candidate'
                               else [CC, '-pie' if mode == 'pie' else '-no-pie'])
                    inputs = [objects[probe]] if probe != 'interpose' else ['-rdynamic', objects['debug'], objects['interposer']]
                    self.run('link-' + binary.name, [*command, *inputs, '-o', binary])
                    self.keep(binary.name + '-elf', binary)
                    shutil.copy2(binary, execution_root / 'consumer')
                    require(digest(binary) == digest(execution_root / 'consumer'), 'execution copy differs from retained ELF')
                    for entry in ('kernel', 'direct'):
                        call = ['/consumer'] if entry == 'kernel' else [interpreter, '/consumer']
                        self.execute(f'{lane}-{mode}-{entry}-{probe}', ['timeout', '25', 'env', '-i', 'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                                     'chroot', execution_root, *call], probe, binary)
                        if probe in ('debug', 'interpose'):
                            suffix = 'trace' if probe == 'debug' else 'interpose-trace'
                            self.execute(f'{lane}-{mode}-{entry}-{suffix}', ['timeout', '25', observer, execution_root,
                                'kernel' if entry == 'kernel' else interpreter, '/consumer', str(Elf(loader).entry),
                                str(hook['value']), provider, str(Elf(provider).symbol('_dl_debug_addr')['value'])], 'debug', binary)
                    require(digest(binary) == digest(execution_root / 'consumer'), 'execution changed the retained consumer copy')
            for mode in ('static', 'static-pie'):
                binary = self.output / f'{lane}-{mode}-lifecycle'
                static_flags = ['-static', '-no-pie'] if mode == 'static' else ['-static', '-pie', '-Wl,--no-dynamic-linker,-Bsymbolic']
                # The pinned GCC specs always select Scrt1.o. Select the
                # actual pinned self-relocating rcrt1 explicitly for PIE.
                oracle_lib = ORACLE.parent
                command = ([static / 'bin/crabc-cc', '-' + mode, objects['lifecycle']] if lane == 'candidate'
                           else [CC, '-nostdlib', *static_flags,
                                 oracle_lib / ('crt1.o' if mode == 'static' else 'rcrt1.o'), oracle_lib / 'crti.o',
                                 objects['lifecycle'], oracle_lib / 'libc.a', oracle_lib / 'crtn.o'])
                self.run('link-' + binary.name, [*command, '-o', binary])
                self.keep(binary.name + '-elf', binary)
                self.execute(binary.name, ['timeout', '25', binary], 'lifecycle', binary)
                for kind in ('default', 'override'):
                    binary = self.output / f'{lane}-{mode}-archive-{kind}'
                    inputs = [objects['archive']] + ([objects['override']] if kind == 'override' else [])
                    library = static / 'usr/lib/libc.a' if lane == 'candidate' else ORACLE.with_name('libc.a')
                    libraries = [library] + ([static / 'usr/lib/libcrabc-builtins.a'] if lane == 'candidate' else [])
                    self.run('link-' + binary.name, [CC, '-nostdlib', *static_flags, '-Wl,-e,_start,--gc-sections',
                             '-Wl,-Map,' + str(binary) + '.map', *inputs, *libraries, '-o', binary])
                    self.keep(binary.name + '-elf', binary)
                    self.keep(binary.name + '-map', Path(str(binary) + '.map'))
                    self.execute(binary.name, ['timeout', '25', binary], 'archive-' + kind, binary)
        require(source == qualification.source_digest() and commit == qualification.require_clean_source(), 'source changed during component collection')
        report = {'schema': SCHEMA, 'status': 'component-verified', 'family_complete': False, 'public_support': False,
                  'source_commit': commit, 'source_sha256': source, 'image': image, 'oracle': oracle,
                  'artifacts': self.artifacts,
                  'public_metadata': public_metadata(dynamic / 'usr/lib/libc.so'),
                  'loader_hook_metadata': Elf(dynamic / 'lib/ld-crabc-x86_64.so.1').symbol('_dl_debug_state'),
                  'executions': self.executions,
                  'oracle_trace_events': self.executions['oracle-pie-kernel-trace']['events']}
        self.keep('commands', self.output / 'commands.json')
        path = self.output / 'report.json'
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        validate_report(path)
        return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    collect = commands.add_parser('collect')
    collect.add_argument('--output', required=True, type=Path)
    validate = commands.add_parser('validate-report')
    validate.add_argument('report', type=Path)
    args = parser.parse_args()
    try:
        if args.mode == 'collect':
            print(Collector(args.output).collect())
        else:
            validate_report(args.report)
            print('loader debugger/CRT component report: PASS')
    except (EvidenceError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'loader debugger/CRT evidence: {error}\n')


if __name__ == '__main__':
    main()

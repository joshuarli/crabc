#!/usr/bin/env python3
"""Reconstruct the installed dynamic address-taken C11 atomic extension.

This companion proves one deliberately narrow project extension.  It is not
musl evidence, a C11-header closure claim, or a general C ABI policy.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

import owned_crypt_profile as sealed
import owned_dynamic_receipt as receipt_contract
import owned_crypt_runtime_evidence as copies
import owned_posix_family_execution as family
import owned_posix_native_observations as native
import owned_posix_product_evidence as products

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'crabc.x86_64-owned-atomic-addressable-profile/v1'
MODES = ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct')
ATOMIC_SYMBOLS = ('atomic_flag_clear', 'atomic_flag_clear_explicit',
    'atomic_flag_test_and_set', 'atomic_flag_test_and_set_explicit',
    'atomic_signal_fence', 'atomic_thread_fence')
C_SOURCE = 'compat/x86_64/atomic_addressable_abi_probe.c'
CXX_SOURCE = 'compat/x86_64/atomic_addressable_abi_probe.cpp'
MAIN_SOURCE = 'compat/x86_64/atomic_addressable_abi_dynamic_main.c'
SOURCES = (C_SOURCE, CXX_SOURCE, MAIN_SOURCE, 'include/stdatomic.h',
    'compat/x86_64/run_atomic_addressable_abi.sh',
    'compat/x86_64/run_owned_atomic_addressable_profile.sh',
    'compat/x86_64/owned_atomic_addressable_profile.py',
    'compat/x86_64/owned-atomic-addressable-profile.md',
    'compat/x86_64/owned_posix_native_dispositions.py',
    'compat/x86_64/owned-posix-native-dispositions.md',
    'compat/x86_64/owned_posix_native_observations.py',
    'compat/x86_64/owned_posix_native_execution.py',
    'compat/x86_64/owned-posix-native-execution.md',
    'compat/x86_64/owned_dynamic_receipt.py',
    'compat/x86_64/owned_posix_product_evidence.py',
    'compat/x86_64/owned_crypt_profile.py',
    'compat/x86_64/owned_crypt_runtime_evidence.py',
    'compat/x86_64/owned_posix_family_execution.py',
    'compat/x86_64/crabc_cc_owned_dynamic.py',
    'compat/x86_64/crabc_cc_static.py', 'compat/x86_64/static_c_abi_exports.txt')
ENVIRONMENT = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '1', 'TZ': 'UTC'}


class AtomicAddressableProfileError(RuntimeError):
    """The finite installed-product atomic companion is incomplete or changed."""


require, same, keys = native.require, native.same, native.keys


def source_records(root):
    return {path: {'path': path, 'sha256': native.digest(root / path),
                   'mode': (root / path).stat().st_mode} for path in SOURCES}


def product_record(root, product):
    manifest, _ = products._validate_dynamic_product(product)
    return {'manifest': family.file_identity(root, manifest), 'tree': family.snapshot(product)}


def live_tools(product):
    helper = product / 'share/crabc/crabc_cc_static.py'
    require(native.physical(helper) == helper, 'atomic installed compiler helper is not physical')
    sys.path.insert(0, str(helper.parent))
    try:
        import crabc_cc_static as compiler
        require(Path(compiler.__file__).resolve() == helper, 'atomic installed compiler helper import drifted')
        result = {role: {'path': str(path), 'sha256': native.digest(path)} for role, path in
                  (('compiler', Path(compiler.compiler()).resolve(strict=True)),
                   ('linker', Path(compiler.linker(product)).resolve(strict=True)))}
    finally:
        sys.path.pop(0)
        sys.modules.pop('crabc_cc_static', None)
    return result


def _tool_roster(tools):
    """Require the fixed compiler/linker identity shape used by one profile run."""
    keys(tools, ('compiler', 'linker'), 'atomic compiler/linker roster')
    for role, item in tools.items():
        keys(item, ('path', 'sha256'), 'atomic recorded tool identity')
        require(isinstance(item['path'], str) and Path(item['path']).is_absolute()
                and '..' not in Path(item['path']).parts
                and isinstance(item['sha256'], str) and re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None,
                'atomic malformed tool identity')
    return tools


def _recorded_tools(work):
    """Read the container's retained tool identities without probing this host."""
    tools = _tool_roster(native.read_json(work / 'profile-tools-before.json'))
    same(native.read_json(work / 'profile-tools-after.json'), tools, 'atomic tools before/after seal')
    return tools


def _write(path, value):
    family.static_products.write_new(path, value)


def prepare(root, work, product):
    work, product = family.physical(root, work), family.physical(root, product)
    require(work.is_dir() and not work.is_relative_to(product), 'atomic evidence cannot be inside installed product')
    require(not any(work.iterdir()), 'atomic evidence work directory must be fresh')
    _write(work / 'profile-request.json', {'schema': SCHEMA, 'source_mount': str(root),
                                            'product': product.relative_to(root).as_posix()})
    _write(work / 'profile-source-before.json', source_records(root))
    _write(work / 'profile-product-before.json', product_record(root, product))
    _write(work / 'profile-tools-before.json', live_tools(product))


def _reader(root, work, product=None):
    work = family.physical(root, work)
    request = native.read_json(work / 'profile-request.json')
    keys(request, ('schema', 'source_mount', 'product'), 'atomic profile request')
    same(request['schema'], SCHEMA, 'atomic profile request schema')
    same(request['source_mount'], '/workspace', 'atomic profile recorded source mount')
    require(isinstance(request['product'], str) and not Path(request['product']).is_absolute(),
            'atomic profile product path differs')
    selected = family.physical(root, root / request['product'])
    if product is not None:
        same(str(selected), str(family.physical(root, product)), 'atomic companion selected product')
    products._validate_dynamic_product(selected)
    return native.Reader(work, request['source_mount'], selected, root)


def _command(root, work, label, command):
    try:
        sealed.run_command(root, work, label, command, ENVIRONMENT)
    except sealed.CryptProfileError as error:
        raise AtomicAddressableProfileError(str(error)) from error


def _dependency_command(reader, tools):
    prefix = ['-nostdinc', '-isystem', reader.recorded(reader.product / 'usr/include'),
              '-ffreestanding', '-fno-builtin', '-fno-stack-protector']
    return [tools['compiler']['path'], *prefix, '-std=c11', '-D_GNU_SOURCE', '-fPIE', '-M',
            reader.recorded(reader.root / C_SOURCE)]


def _compile_commands(reader, tools):
    driver = reader.recorded(reader.product / 'bin/crabc-cc-dynamic')
    return {
        'c': [driver, '--dynamic-pie', '-std=c11', '-D_GNU_SOURCE', '-fno-builtin', '-fno-stack-protector',
              '-c', reader.recorded(reader.root / C_SOURCE), '-o', reader.recorded(reader.leaf / 'atomic-c.o')],
        # The sealed C driver intentionally admits C only.  This direct pinned compiler
        # translation has no C++ headers and is linked only by the installed product.
        'cxx': [tools['compiler']['path'], '-x', 'c++', '-std=c++17', '-nostdinc', '-nostdinc++',
                '-ffreestanding', '-fno-exceptions', '-fno-rtti', '-fno-threadsafe-statics', '-fno-builtin',
                '-fno-stack-protector', '-fPIC', '-c', reader.recorded(reader.root / CXX_SOURCE),
                '-o', reader.recorded(reader.leaf / 'atomic-cxx.o')],
        'main': [driver, '--dynamic-pie', '-std=c11', '-fno-builtin', '-fno-stack-protector',
                 '-c', reader.recorded(reader.root / MAIN_SOURCE), '-o', reader.recorded(reader.leaf / 'atomic-main.o')],
        'cxx-undefined': ['/usr/bin/nm', '--undefined-only', reader.recorded(reader.leaf / 'atomic-cxx.o')],
    }


def _header_dependencies(reader, path):
    text = native.read_bytes(path).decode('ascii').replace('\\\n', ' ')
    require(':' in text, 'atomic installed header dependency transcript is malformed')
    names = text.split(':', 1)[1].split()
    require(names and len(names) == len(set(names)), 'atomic installed header dependency roster differs')
    source = reader.root / C_SOURCE
    headers = reader.product / 'usr/include'
    bindings = {}
    for name in names:
        local = reader.local(name, within=reader.root)
        require(local == source or local.is_relative_to(headers), 'atomic dependency escaped source or installed headers')
        bindings[name] = native.digest(local)
    require(reader.recorded(source) in bindings and all(reader.recorded(headers / name) in bindings
            for name in ('stdatomic.h', 'features.h', 'bits/alltypes.h')),
            'atomic installed header proof omits required headers')
    return bindings


def _cxx_undefined(raw):
    text = raw.decode('ascii')
    found = {line.split()[-1] for line in text.splitlines() if line.split()}
    require(set(ATOMIC_SYMBOLS) <= found, 'atomic C++ object omitted a C ABI function reference')
    banned = re.compile(r'(^_Z|^__gxx_personality_v0$|^__cxa|^_Unwind_|^_Zn|^_Zd|^__stack_chk_fail$|^__tls_get_addr$)')
    require(not any(banned.search(name) for name in found), 'atomic C++ object requires a C++ or dynamic-TLS runtime')
    require(found <= set(ATOMIC_SYMBOLS) | {'crabc_x86_64_atomic_addressable_cxx_probe', '_GLOBAL_OFFSET_TABLE_'},
            'atomic C++ object has an unowned undefined reference')
    return sorted(found)


def _link_command(reader, objects, binary, mode, linker):
    library = reader.product / 'usr/lib'
    runtime = [library / ('Scrt1.o' if mode == 'pie' else 'crt1.o'), library / 'crabc-dynamic-attach.o',
               library / 'crti.o']
    return [linker, *(('-pie',) if mode == 'pie' else ()), '--hash-style=sysv', '-z', 'relro', '-z', 'now',
            '-z', 'noexecstack', '-z', 'text', '--no-undefined', '--allow-shlib-undefined', '--enable-new-dtags',
            '-rpath', '/usr/lib', '--dynamic-linker', sealed.INTERPRETER,
            *(reader.recorded(path) for path in [*runtime, *objects, library / 'libc.so',
                                                   library / 'libcrabc-builtins.a', library / 'crtn.o']),
            '-o', reader.recorded(binary)]


def _collect_link(reader, objects, binary, mode, tools):
    receipt_path = Path(str(binary) + '.crabc-link.json')
    receipt = native.read_json(receipt_path)
    search = receipt_contract.validate(
        receipt, format=native.PRODUCT_FORMAT, label='atomic sealed link receipt',
        fail=lambda message: require(False, message),
    )
    library = reader.product / 'usr/lib'
    runtime = [library / 'crti.o', library / 'libc.so', library / 'crtn.o',
               library / ('Scrt1.o' if mode == 'pie' else 'crt1.o'), library / 'crabc-dynamic-attach.o']
    builtins = library / 'libcrabc-builtins.a'
    expected = {'format': native.PRODUCT_FORMAT, 'mode': 'pie' if mode == 'pie' else 'exec',
        'binding': 'now', 'runtime_imports': [], 'application_runpath': '/usr/lib', 'application_dsos': {},
        'campaign_complete': False, 'output_path': reader.recorded(binary), 'output_sha256': native.digest(binary),
        'manifest_sha256': native.digest(reader.manifest),
        'owned_runtime_inputs': sorted(path.relative_to(reader.product).as_posix() for path in [*runtime, builtins]),
        'input_receipts': [reader.binding(path) for path in [*runtime, *objects, builtins]]}
    same({key: receipt[key] for key in expected}, expected, 'atomic canonical installed link inputs')
    receipt_contract.require_runpath(
        search, '/usr/lib', label='atomic sealed link receipt', fail=lambda message: require(False, message)
    )
    linker = keys(receipt['resolved_linker'], ('path', 'sha256'), "atomic linker's identity")
    require(isinstance(linker['path'], str) and Path(linker['path']).name == 'ld.lld'
            and isinstance(linker['sha256'], str) and re.fullmatch('[0-9a-f]{64}', linker['sha256']) is not None,
            'atomic linker differs')
    same(linker, tools['linker'], 'atomic sealed linker differs from retained tool')
    same(receipt['link_command'], _link_command(reader, objects, binary, mode, linker['path']),
         'atomic sealed linker invocation')
    direct = {reader.recorded(path) for path in [*runtime, *objects]}
    archive = reader.recorded(builtins)
    trace = receipt['link_trace']
    require(isinstance(trace, list) and all(isinstance(item, str) and (item in direct or item == archive or
            (item.startswith(archive + '(') and item.endswith(')'))) for item in trace) and direct <= set(trace),
            'atomic sealed link trace admits foreign or missing inputs')
    return {'receipt': reader.identity(receipt_path), 'objects': [reader.identity(path) for path in objects],
            'executable': reader.identity(binary), 'elf': sealed.require_elf(binary, mode), 'linker': linker}


def _collect_copy(reader, mode, binary):
    product = reader.product
    manifest = native.read_json(reader.manifest)
    files, aliases = manifest['files'], manifest['symlinks']
    execution = reader.leaf / ('dynamic-' + mode + '-root')
    record = reader.leaf / ('dynamic-' + mode + '-execution-payload.json')
    def file_pair(source, copied):
        same(native.digest(source), native.digest(copied), 'atomic execution copy bytes')
        return {'source': reader.binding(source), 'execution': reader.binding(copied)}
    def alias_pair(name, target):
        source, copied = product / name, execution / name
        require(source.is_symlink() and copied.is_symlink() and os.readlink(source) == target
                and os.readlink(copied) == target, 'atomic execution loader alias differs')
        return {'source': {'path': reader.recorded(source), 'target': target},
                'execution': {'path': reader.recorded(copied), 'target': target}}
    expected = {'schema': copies.EXECUTION_PAYLOAD_SCHEMA,
        'product': {'root': reader.recorded(product),
                    'manifest': file_pair(reader.manifest, execution / 'share/crabc/manifest.json')},
        'execution_root': reader.recorded(execution),
        'payload': {name: file_pair(product / name, execution / name) for name in files},
        'aliases': {name: alias_pair(name, target) for name, target in aliases.items()},
        'consumer': file_pair(binary, execution / 'consumer')}
    copies.assert_execution_tree(execution, files, aliases, execution / 'consumer')
    same(native.read_json(record), expected, 'atomic execution payload')
    return reader.identity(record)


def run(root, work, product):
    root, work, product = root.resolve(strict=True), family.physical(root, work), family.physical(root, product)
    prepare(root, work, product)
    reader = _reader(root, work, product)
    tools = _tool_roster(native.read_json(work / 'profile-tools-before.json'))
    commands = _compile_commands(reader, tools)
    try:
        _command(root, work, 'dependencies', _dependency_command(reader, tools))
        for label in ('c', 'cxx', 'main', 'cxx-undefined'):
            _command(root, work, label, commands[label])
        require(all((work / name).is_file() for name in ('atomic-c.o', 'atomic-cxx.o', 'atomic-main.o')),
                'atomic compiler omitted an object')
        for name in ('atomic-c.o', 'atomic-cxx.o', 'atomic-main.o'):
            sealed.require_elf(work / name, 'object')
        _header_dependencies(reader, work / 'dependencies.stdout')
        _cxx_undefined(native.read_bytes(work / 'cxx-undefined.stdout'))
        providers = sealed.elf_facts(product / 'usr/lib/libc.so')['symbols']
        for symbol in ATOMIC_SYMBOLS:
            same([item for item in providers if item['name'] == symbol],
                 [{'name': symbol, 'binding': 1, 'type': 2, 'visibility': 0, 'defined': True}],
                 'atomic installed provider ' + symbol)
        objects = [work / name for name in ('atomic-c.o', 'atomic-cxx.o', 'atomic-main.o')]
        for mode in ('pie', 'non-pie'):
            binary = work / ('dynamic-' + mode + '-consumer')
            _command(root, work, 'link-' + mode,
                     [str(product / 'bin/crabc-cc-dynamic'), '--dynamic-' + mode,
                      *(str(path) for path in objects), '-o', str(binary)])
            _collect_link(reader, objects, binary, mode, tools)
            execution = work / ('dynamic-' + mode + '-root')
            shutil.copytree(product, execution, symlinks=True)
            shutil.copyfile(binary, execution / 'consumer')
            (execution / 'consumer').chmod(binary.stat().st_mode & 0o7777)
            record = work / ('dynamic-' + mode + '-execution-payload.json')
            copies.record_execution_payload(product, execution, binary, execution / 'consumer', record)
            for entry in ('kernel', 'direct'):
                _command(root, work, 'dynamic-' + mode + '-' + entry,
                         sealed.runtime_command(work, 'dynamic-' + mode + '-' + entry))
            copies.audit_execution_payload(product, execution, binary, execution / 'consumer', record)
    finally:
        for name, capture in (('source-after', lambda: source_records(root)),
                              ('product-after', lambda: product_record(root, product)),
                              ('tools-after', lambda: live_tools(product))):
            path = work / ('profile-' + name + '.json')
            if not path.exists():
                _write(path, capture())
    result = collect(root, work, product=product)
    _write(work / 'atomic-addressable-profile.json', result)
    return work / 'atomic-addressable-profile.json'


def collect(root, work, *, product=None):
    reader = _reader(root, work, product)
    work, product = reader.leaf, reader.product
    sources, payload, tools = source_records(root), product_record(root, product), _recorded_tools(work)
    for phase, value in (('source', sources), ('product', payload)):
        for point in ('before', 'after'):
            same(native.read_json(work / ('profile-' + phase + '-' + point + '.json')), value,
                 'atomic ' + phase + ' seal changed')
    commands = _compile_commands(reader, tools)
    build = {'dependencies': sealed.collect_command(reader, 'dependencies', _dependency_command(reader, tools)),
             'c': sealed.collect_command(reader, 'c', commands['c'], raw_stdout=b''),
             'cxx': sealed.collect_command(reader, 'cxx', commands['cxx'], raw_stdout=b''),
             'main': sealed.collect_command(reader, 'main', commands['main'], raw_stdout=b''),
             'cxx_undefined': sealed.collect_command(reader, 'cxx-undefined', commands['cxx-undefined'])}
    build['headers'] = _header_dependencies(reader, work / 'dependencies.stdout')
    build['objects'] = {name: reader.identity(work / ('atomic-' + name + '.o')) for name in ('c', 'cxx', 'main')}
    for name in build['objects']:
        build['objects'][name]['elf'] = sealed.require_elf(work / ('atomic-' + name + '.o'), 'object')
    build['cxx_undefined_symbols'] = _cxx_undefined(native.read_bytes(work / 'cxx-undefined.stdout'))
    providers = sealed.elf_facts(product / 'usr/lib/libc.so')['symbols']
    build['exports'] = {symbol: [item for item in providers if item['name'] == symbol] for symbol in ATOMIC_SYMBOLS}
    for symbol, row in build['exports'].items():
        same(row, [{'name': symbol, 'binding': 1, 'type': 2, 'visibility': 0, 'defined': True}],
             'atomic installed provider ' + symbol)
    objects = [work / name for name in ('atomic-c.o', 'atomic-cxx.o', 'atomic-main.o')]
    entries = {}
    for mode in ('pie', 'non-pie'):
        binary = work / ('dynamic-' + mode + '-consumer')
        link = _collect_link(reader, objects, binary, mode, tools)
        link['command'] = sealed.collect_command(reader, 'link-' + mode,
            [reader.recorded(product / 'bin/crabc-cc-dynamic'), '--dynamic-' + mode,
             *(reader.recorded(path) for path in objects), '-o', reader.recorded(binary)], raw_stdout=b'')
        copied = _collect_copy(reader, mode, binary)
        for entry in ('kernel', 'direct'):
            label = mode + '-' + entry
            raw = sealed.collect_command(reader, 'dynamic-' + label,
                sealed.runtime_command(Path(reader.recorded(work)), 'dynamic-' + label), raw_stdout=b'')
            entries[label] = {'link': link, 'copy': copied, 'raw': raw}
    require(set(entries) == set(MODES), 'atomic dynamic entry roster differs')
    artifacts = family.snapshot(work)
    artifacts.pop('atomic-addressable-profile.json', None)
    return {'schema': SCHEMA, 'status': 'profile-companion-verified', 'source_mount': str(reader.mount),
            'product': payload, 'sources': sources, 'tools': tools, 'build': build, 'entries': entries,
            'artifacts': artifacts, 'native_aggregate_complete': False, 'family_completion': False,
            'campaign_complete': False, 'public_support': False}


def validate_receipt(root, path, *, product=None):
    path = family.physical(root, path)
    require(path.name == 'atomic-addressable-profile.json', 'expected atomic-addressable-profile.json receipt')
    observed = collect(root, path.parent, product=product)
    same(native.read_json(path), observed, 'atomic whole-run profile receipt')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('run', 'validate'):
        item = commands.add_parser(action)
        if action == 'run':
            item.add_argument('--work', type=Path, required=True)
            item.add_argument('--product', type=Path, required=True)
        else:
            item.add_argument('receipt', type=Path)
            item.add_argument('--product', type=Path)
    parsed = parser.parse_args()
    try:
        if parsed.action == 'run':
            path = run(ROOT, parsed.work, parsed.product)
            print(path)
        else:
            print(json.dumps(validate_receipt(ROOT, parsed.receipt, product=parsed.product), sort_keys=True))
    except (native.NativeObservationError, AtomicAddressableProfileError, products.ProductEvidenceError, OSError) as error:
        print('owned atomic addressable profile: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

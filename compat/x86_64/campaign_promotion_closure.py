#!/usr/bin/env python3
"""Read current qualification and selected products before public policy changes.

A completed ledger does not establish execution. This boundary rereads the
selected ordered receipt, reviewed full product receipts, accepted-C dependency
provenance and actual allocator symbol ownership. Public policy may still be
false during readiness; changing it requires fresh source-bound evidence.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

import aarch64_parity_inventory as inventory
import generate_qualification_manifest as manifest
import owned_dynamic_qualification as dynamic
import owned_static_sysroot_package as package
import run_qualification_manifest as qualification
import static_product_contract as static
import validate_parity_ledger as ledger
import qualification_gates as gates

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'compat/allocator'))
import x86_64_m10_gate as allocator_promotion
import x86_64_m9_gate as allocator_performance


class PromotionClosureError(RuntimeError):
    """Actual current-source execution or native ownership remains unqualified."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionClosureError(message)


def validate_native_product(tree: Path, kind: str, provenance: Mapping, *, ar: str, nm: str) -> None:
    """Reinspect owned native products instead of trusting an audit's pass bit."""
    from scripts import build_x86_64_owned_sysroot as common
    from scripts import build_x86_64_owned_dynamic_sysroot as shared

    require(provenance.get('allocator_lifecycle_test_audit') is False,
            f'{kind} native product selects lifecycle test instrumentation')
    graph = provenance['dependency_graph']
    require(graph.get('target') == common.TARGET
            and graph.get('features') == [f'x86-owned-{kind}-native-shadow']
            and graph.get('edges') == ['normal', 'build']
            and graph.get('native_allocator_selected') is True and graph.get('c_allocator_selected') is False
            and any(name.startswith('crabc-mimalloc ') for name in graph['packages'])
            and not any(name.startswith('libmimalloc-sys ') for name in graph['packages']),
            f'{kind} product native dependency ownership differs')
    upstream = hashlib.sha256((ROOT / 'crabc-mimalloc/UPSTREAM.md').read_bytes()).hexdigest()
    if kind == 'static':
        allocator = provenance['allocator_backend']
        require(allocator.get('implementation') == 'native Rust; production-shaped selection'
                and allocator.get('upstream_sha256') == upstream
                and all(allocator.get(key) is None for key in ('crate', 'compiler', 'source_and_header_sha256')),
                'static native allocator provenance differs')
        artifact = tree / 'usr/lib/libc.a'
        definitions = common.archive_defined_symbols(nm, artifact)
        imports = allocator_promotion.symbol_names(nm, artifact, '--undefined-only', '--extern-only')
        shared.validate_native_allocator_symbols(definitions, imports, set())
    else:
        require(provenance.get('native_allocator') == {'path': 'crabc-mimalloc/UPSTREAM.md', 'sha256': upstream}
                and all(provenance.get(key) is None for key in
                        ('accepted_allocator', 'allocator_headers', 'allocator_compiler', 'excluded_c_allocator')),
                'dynamic native allocator provenance differs')
        artifact = tree / 'usr/lib/libc.so'
        loader = tree / 'lib/ld-crabc-x86_64.so.1'
        definitions = shared.elf_symbols(nm, artifact, '--defined-only')
        imports = shared.elf_symbols(nm, artifact, '--undefined-only')
        loader_symbols = shared.elf_symbols(nm, loader, '--defined-only') | shared.elf_symbols(nm, loader, '--undefined-only')
        shared.validate_native_allocator_symbols(definitions, imports, loader_symbols)
        require('__crabc_x86_native_mimalloc_process_finalizer' in definitions,
                'dynamic native allocator process finalizer is absent')
    require({'malloc', 'calloc', 'realloc', 'free', 'aligned_alloc', 'posix_memalign', 'malloc_usable_size'} <= definitions,
            f'{kind} native allocator entry ownership differs')
    unmet = allocator_promotion.audit_product(tree, ar=ar, nm=nm, cargo_packages=graph['packages'])
    require(not unmet, f'{kind} native product purity differs: {unmet}')


def validate_native_promotion(receipt_path: Path, profile: str) -> dict:
    """Rerun the owning allocator readers after the complete full chain."""
    require(profile == 'full', 'native promotion requires full qualification, including performance')
    # The publication already selects and hashes the performance receipt.
    # Keep that selection stable while the allocator readers consume it.
    gates.read_publication('performance.release', 'performance-release')
    pointer = gates.publication_path('performance.release', 'performance-release')
    selection = pointer.read_bytes()
    performance_receipt = ROOT / json.loads(selection)['receipt']
    # Allocator source and performance are checked in their producer image by
    # the host composition. This phase remains non-promoting on its own.
    allocator_work = ROOT / '.work/allocator-x86_64'
    artifact_root = allocator_work / 'target/compat/allocator/x86_64'
    reports = {name: (allocator_work / 'reports/allocator/x86_64' / path.name
                      if name in {'M1', 'M2', 'M3'} else
                      allocator_work / 'reports/allocator/x86_64/m8-gate/report.json'
                      if name == 'M8' else artifact_root / f'{name.lower()}-gate/report.json')
               for name, path in allocator_promotion.PRIOR_REPORTS.items()}
    head = allocator_promotion.git_head()
    require(head['clean'], 'native promotion requires clean current allocator source')
    m10_path = static.evidence_directory(artifact_root / 'm10-gate/report.json')
    retained_m10 = static.read_json(m10_path)
    allocator_profile = retained_m10.get('qualification_profile')
    require(allocator_profile in {'baseline', 'full'}, 'native promotion requires qualified allocator performance')
    fresh_m10 = allocator_promotion.evaluate(m0={'status': 0}, receipt=performance_receipt, head=head,
                                            qualification_receipt=receipt_path, profile=allocator_profile, prior_reports=reports,
                                            native_artifact_audit=artifact_root / 'm10-gate/native-artifact-audit.json')
    require(fresh_m10 == retained_m10 and fresh_m10['overall_status'] == 'passed'
            and fresh_m10['phase'] == 'post-switch-qualification',
            'native promotion M10 differs from current post-switch allocator qualification')
    # M10's retained artifact audit names its own installed trees. Reinspect
    # them too; a historical passed bit cannot establish physical ownership.
    audit_path = static.evidence_directory(artifact_root / 'm10-gate/native-artifact-audit.json')
    audit = static.read_json(audit_path)
    nm, ar = qualification.tool_identity('nm')['path'], qualification.tool_identity('ar')['path']
    for kind, product in audit['products'].items():
        tree = static.evidence_directory(ROOT / product['path'])
        name = 'libc-static.provenance.json' if kind == 'static' else 'libc-shared.provenance.json'
        provenance = static.read_json(tree / 'share/crabc' / name)
        document = static.read_json(tree / 'share/crabc/manifest.json')
        require(document.get('allocator_backend', provenance.get('allocator_backend')) == 'native'
                and provenance.get('allocator_lifecycle_test_audit') is False,
                f'{kind} audit product does not select the production native allocator')
        validate_native_product(tree, kind, provenance, ar=ar, nm=nm)
    require(pointer.read_bytes() == selection and static.read_json(m10_path) == retained_m10 and static.read_json(audit_path) == audit,
            'allocator qualification changed during promotion validation')
    return {'m10': retained_m10, 'audit': audit, 'performance': selection}


def validate_promotion_closure(receipt_path: Path | None) -> dict:
    """Compose existing owning readers without creating another receipt or seal."""
    require(receipt_path is not None, "promotion requires an explicit complete qualification receipt")
    qualification.require_pinned_native_execution()
    before = qualification.source_identity()
    chain = qualification.validate_chain_receipt(receipt_path)
    contract = manifest.load_contract()
    profile = contract['qualification_profile']
    active = list(manifest.active_chain(profile))
    require(chain.get('qualification_profile') == profile
            and chain.get('active_gate_ids') == active
            and chain.get('deferred_gate_ids') == list(manifest.deferred_gate_ids(profile))
            and chain.get('complete_profile') is True and chain.get('outcome') == 'passed'
            and chain.get('qualified_gates') == active and chain.get('through') == active[-1],
            "promotion requires the complete selected profile, not a prefix or historical full shape")
    require(chain.get('source_before') == before and chain.get('source_after') == before,
            "qualification source differs from promotion source")
    data = ledger.load_toml(ledger.LEDGER_PATH)
    ledger.validate_ledger(data, require_receipts=True)
    required = ledger.completion_family_ids(data)
    require(data.get('completion', {}).get('qualification_profile', 'full') == profile,
            "ledger and qualification profiles differ")
    families = {row['id']: row for row in data['family']}
    require(all(families[name]['status'] == 'foundation-verified' for name in required),
            "functional prerequisite families remain incomplete")
    capabilities = inventory.validate_inventory()
    require(all(row['contract_state'] == 'implemented-foundation'
                for row in capabilities['capabilities']), "capability implementation remains incomplete")

    sys.path.insert(0, str(ROOT))
    from scripts import build_x86_64_owned_sysroot as static_builder
    from scripts import build_x86_64_owned_dynamic_sysroot as dynamic_builder
    backend = static_builder.DEFAULT_ALLOCATOR_BACKEND
    require(backend in {'accepted-c', 'native'}
            and static_builder.build.__kwdefaults__['allocator_backend'] == backend
            and dynamic_builder.build.__kwdefaults__['allocator_backend'] == backend,
            'source selects mixed or unqualified allocator defaults')
    native_proof = validate_native_promotion(receipt_path, profile) if backend == 'native' else None
    static_receipt = static.load_publication()
    dynamic_receipt = dynamic.load_publication()
    require(static_receipt is not None and dynamic_receipt is not None,
            "reviewed current-source static and dynamic qualification publications are required")
    source = static.source_digest()
    require(source == dynamic.source_digest()
            and static_receipt['source_sha256'] == source
            and dynamic_receipt['source_sha256'] == source,
            "reviewed product source differs from promotion source")
    nm = qualification.tool_identity('nm')['path']
    scratch = static.evidence_directory(ROOT / '.work/x86_64/tmp')
    scratch.mkdir(parents=True, exist_ok=True)
    report = static.evidence_directory(ROOT / static_receipt['report'])
    with tempfile.TemporaryDirectory(prefix='.promotion-static.', dir=scratch) as temporary:
        tree = package.extract_archive(report / 'archives/primary.tar.xz', Path(temporary) / 'tree')
        product_manifest = static.read_json(tree / 'share/crabc/manifest.json')
        provenance = static.read_json(tree / 'share/crabc/libc-static.provenance.json')
        require(product_manifest['allocator_backend'] == backend
                and product_manifest.get('allocator_lifecycle_test_audit', False) is False
                and provenance.get('allocator_lifecycle_test_audit') is False,
                'static product does not select the production allocator')
        if backend == 'native':
            validate_native_product(tree, 'static', provenance,
                                    ar=qualification.tool_identity('ar')['path'], nm=nm)
        else:
            require(product_manifest['allocator_backend'] == 'accepted-c'
                    and provenance.get('allocator_lifecycle_test_audit') is False,
                    "static product does not select the accepted-C allocator")
            graph = provenance['dependency_graph']
            require(graph.get('c_allocator_selected') is True and graph.get('native_allocator_selected') is False
                    and graph.get('edges') == ['normal', 'build']
                    and any(name.startswith('libmimalloc-sys ') for name in graph['packages'])
                    and not any(name.startswith('crabc-mimalloc ') for name in graph['packages']),
                    "static product accepted-C dependency ownership differs")
            allocator = provenance['allocator_backend']
            require(allocator['crate'] == static_builder.C_ALLOCATOR_PIN
                    and allocator['implementation'] == 'accepted C backend; native Rust promotion remains separate'
                    and static_builder.ALLOCATOR_MEMBER.fullmatch(allocator['member']) is not None
                    and all(re.fullmatch(r'[0-9a-f]{64}', allocator[key]) is not None
                            for key in ('archive_sha256', 'member_sha256'))
                    and allocator['compiler']['path'] == '/usr/bin/gcc'
                    and re.fullmatch(r'[0-9a-f]{64}', allocator['compiler']['sha256']) is not None
                    and 'libmimalloc-sys/c_src/mimalloc/v3/src/static.c' in allocator['source_and_header_sha256']
                    and any(name.startswith('include/') for name in allocator['source_and_header_sha256']),
                    "static accepted-C allocator provenance differs")
            archive = tree / 'usr/lib/libc.a'
            definitions = static_builder.archive_defined_symbols(nm, archive)
            output = static_builder.run([nm, '--undefined-only', '--extern-only', str(archive)])
            imports = {line.split()[-1] for line in output.decode('utf-8', errors='replace').splitlines()
                       if len(line.split()) >= 2 and not line.endswith(':')}
            hidden_symbols = set(dynamic_builder.SHARED_LIBC_MIMALLOC_HIDDEN_LIST.read_text(
                encoding='utf-8').splitlines())
            allocator_symbols = {name for name in definitions if name.startswith(('mi_', '_mi_'))}
            allocator_imports = {name for name in imports if name.startswith(('mi_', '_mi_'))}
            require({'malloc', 'free', 'mi_malloc', 'mi_free'} <= definitions
                    and allocator_symbols <= hidden_symbols and allocator_imports <= hidden_symbols,
                    "static accepted-C allocator symbol ownership differs")
    work = dynamic.evidence_path(ROOT / dynamic_receipt['work'])
    for product in ('installed', 'second', 'extracted'):
        tree = dynamic.evidence_path(work / product)
        state = dynamic.read(tree / 'share/crabc/dynamic-product-state.json')
        provenance = dynamic.read(tree / 'share/crabc/libc-shared.provenance.json')
        require(state['allocator_backend'] == provenance['allocator_backend'] == backend
                and state['allocator_lifecycle_test_audit'] is False
                and provenance['allocator_lifecycle_test_audit'] is False,
                'dynamic product does not select the production allocator')
        if backend == 'native':
            validate_native_product(tree, 'dynamic', provenance,
                                    ar=qualification.tool_identity('ar')['path'], nm=nm)
        else:
            require(state['allocator_backend'] == provenance['allocator_backend'] == 'accepted-c'
                    and state['allocator_lifecycle_test_audit'] is False
                    and provenance['allocator_lifecycle_test_audit'] is False,
                    "dynamic product does not select the accepted-C allocator")
            graph = provenance['dependency_graph']
            require(graph.get('c_allocator_selected') is True and graph.get('native_allocator_selected') is False
                    and graph.get('edges') == ['normal', 'build']
                    and any(name.startswith('libmimalloc-sys ') for name in graph['packages'])
                    and not any(name.startswith('crabc-mimalloc ') for name in graph['packages']),
                    "dynamic product accepted-C dependency ownership differs")
            allocator_headers = provenance['allocator_headers']
            allocator_compiler = provenance['allocator_compiler']
            require(provenance['accepted_allocator'] == dynamic_builder.common.C_ALLOCATOR_PIN
                    and isinstance(allocator_headers, Mapping)
                    and 'libmimalloc-sys/c_src/mimalloc/v3/src/static.c' in allocator_headers
                    and any(name.startswith('include/') for name in allocator_headers)
                    and all(re.fullmatch(r'[0-9a-f]{64}', digest) is not None
                            for digest in allocator_headers.values())
                    and allocator_compiler['path'] == '/usr/bin/gcc'
                    and re.fullmatch(r'[0-9a-f]{64}', allocator_compiler['sha256']) is not None,
                    "dynamic accepted-C allocator provenance differs")
            hidden_policy = provenance['shared_mimalloc_hidden_exports']
            require(hidden_policy['source']['path'] == 'libc/src/c_abi/x86_64/owned_mimalloc_hidden.list'
                    and hidden_policy['source']['sha256'] == dynamic_builder.MIMALLOC_V3_HIDDEN_LIST_SHA256
                    and hidden_policy['linker_policy'] == 'exact-local-symbols'
                    and 'mi_malloc' in hidden_policy['members'] and 'mi_free' in hidden_policy['members'],
                    "dynamic accepted-C hidden-symbol provenance differs")
            libc = tree / 'usr/lib/libc.so'
            loader = tree / 'lib/ld-crabc-x86_64.so.1'
            definitions = dynamic_builder.elf_symbols(nm, libc, '--defined-only')
            loader_symbols = (dynamic_builder.elf_symbols(nm, loader, '--defined-only')
                              | dynamic_builder.elf_symbols(nm, loader, '--undefined-only'))
            allocator_symbols = {name for name in definitions if name.startswith(('mi_', '_mi_'))}
            exported = dynamic_builder.common.run([nm, '--dynamic', '--defined-only', str(libc)]).decode().splitlines()
            dynamic_exports = {line.split()[-1] for line in exported if len(line.split()) >= 2 and not line.endswith(':')}
            allocator_edges = {'malloc', 'calloc', 'realloc', 'reallocarray', 'free', 'aligned_alloc', 'memalign',
                               'posix_memalign', 'malloc_usable_size', '__libc_malloc', '__libc_calloc',
                               '__libc_realloc', '__libc_free'}
            require({'malloc', 'free', 'mi_malloc', 'mi_free'} <= definitions
                    and allocator_symbols <= set(hidden_policy['members'])
                    and not any(name.startswith(('mi_', '_mi_')) for name in dynamic_exports)
                    and not (loader_symbols & (allocator_edges | allocator_symbols)),
                    "dynamic accepted-C allocator symbol ownership differs")
    require(static.load_publication() == static_receipt and dynamic.load_publication() == dynamic_receipt
            and qualification.validate_chain_receipt(receipt_path) == chain,
            'qualification or reviewed products changed during promotion validation')
    require(qualification.source_identity() == before
            and qualification.execution_inputs() == chain['inputs_after'],
            "source or execution inputs changed during promotion validation")
    return {'qualification_profile': profile, 'source': before,
            'qualification_receipt': str(receipt_path), 'functional_readiness': backend == 'accepted-c',
            **({'native_allocator_pending': True,
                'allocator_qualification_profile': native_proof['m10']['qualification_profile']}
               if native_proof is not None else {}),
            'public_support': data['policy']['public_support']}


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-receipt', required=True, type=Path)
    args = parser.parse_args(arguments)
    try:
        result = validate_promotion_closure(args.qualification_receipt)
    except (RuntimeError, OSError, KeyError, ValueError, TypeError) as error:
        print(f'x86 campaign promotion closure: UNMET ({error})', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if result.get('native_allocator_pending') is True:
        print('x86 campaign promotion closure: native allocator validation pending', file=sys.stderr)
        return 3
    print('x86 campaign promotion closure: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

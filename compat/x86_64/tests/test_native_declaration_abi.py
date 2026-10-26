#!/usr/bin/env python3
"""Focused behavior checks for the native declaration ABI companion."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_declaration_abi.py"


def load_module():
    specification = importlib.util.spec_from_file_location("native_declaration_abi_test", MODULE_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ABI = load_module()


def observation(name: str, *, definition: str = "extern-declaration-without-initializer") -> dict[str, object]:
    return {
        "name": name,
        "definition_observation": definition,
        "mangled_name_observation": name,
        "source": {
            "declaring_header": "demo.h",
            "include_root": "candidate-header-root",
        },
    }


def group(
    *,
    name: str = "foo",
    profile: str = "cxx17-gnu",
    candidate: list[dict[str, object]] | None = None,
    reference: list[dict[str, object]] | None = None,
    category: str = "reference-backed",
) -> dict[str, object]:
    return {
        "category": category,
        "input_header": "demo.h",
        "profile": profile,
        "name": name,
        "candidate_observations": candidate or [observation(name)],
        "reference_observations": reference if reference is not None else [observation(name)],
    }


class NativeDeclarationAbiTests(unittest.TestCase):
    def selected_boundary_fixture(self):
        deferred = {
            "alloca": {
                "id": "x86-header-callable-builtin-v1",
                "members": ["alloca"],
                "resolution": "compiler-builtin",
            },
            "seqbuf_dump": {
                "id": "x86-header-callable-consumer-supplied-v1",
                "members": ["seqbuf_dump"],
                "resolution": "consumer-supplied",
            },
        }
        no_provider = [
            "_flush_cache", "cachectl", "cacheflush", "getcontext", "makecontext",
            "pthread_mutexattr_getprioceiling", "pthread_mutexattr_setprioceiling",
            "setcontext", "swapcontext",
        ]
        deferred.update({name: {
            "id": "x86-header-callable-oracle-no-provider-v1",
            "members": no_provider,
            "resolution": "oracle-declared-no-provider",
        } for name in no_provider})
        compiler = {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}
        products = {
            kind: {
                "root": f"/workspace/.work/products/{kind}",
                "manifest": {"mode": 0o644, "path": f"/workspace/.work/products/{kind}/share/crabc/manifest.json",
                             "sha256": ("b" if kind == "static" else "c") * 64, "size": 1},
                "installed_headers": {"path": f"/workspace/.work/products/{kind}/usr/include",
                                      "tree_sha256": "d" * 64},
                "libc": {"mode": 0o644 if kind == "static" else 0o755,
                         "path": f"/workspace/.work/products/{kind}/usr/lib/libc.{ 'a' if kind == 'static' else 'so' }",
                         "sha256": ("e" if kind == "static" else "f") * 64, "size": 1},
            }
            for kind in ("static", "dynamic")
        }
        alloca = {
            "header": "alloca.h",
            "profile": "c11-gnu",
            "compiler": copy.deepcopy(compiler),
            "qual_type": "void *(size_t)",
            "undefined_symbols": [],
            "relocation_symbols": [],
            "links": [
                {"linkage": kind, "returncode": 0,
                 "raw": {key: {"path": kind + "-" + key} for key in ("command", "output", "receipt")}}
                for kind in ("static", "dynamic")
            ],
            "raw": {key: {"path": value} for key, value in {
                "source": "alloca-source", "object": "alloca-object", "symbols": "alloca-symbols",
                "relocations": "alloca-relocations", "compile": "alloca-compile",
            }.items()},
        }
        seqbuf_jobs = []
        for tree in ("candidate", "reference"):
            for language, profile, qual_type, symbol in (
                ("c", "c11-gnu", "void (void)", "seqbuf_dump"),
                ("cxx", "cxx17-gnu", "void ()", "_Z11seqbuf_dumpv"),
            ):
                seqbuf_jobs.append({
                    "tree": tree,
                    "header": "sys/soundcard.h",
                    "language": language,
                    "profile": profile,
                    "qual_type": qual_type,
                    "definition_symbol": symbol,
                    "consumer_undefined_symbol": symbol,
                    "same_language_link": {
                        "returncode": 0,
                        "undefined_symbols": [],
                        "raw": {key: {"path": "same-" + key} for key in ("command", "output", "symbols", "relocations")},
                    },
                    "opposite_language_link": {
                        "returncode": 0,
                        "undefined_symbols": [symbol],
                        "raw": {key: {"path": "opposite-" + key} for key in ("command", "output", "symbols", "relocations")},
                    },
                    "raw": {key: {"path": value} for key, value in {
                        "definition_source": "definition-source", "definition_object": "definition-object",
                        "definition_compile": "definition-compile",
                        "definition_symbols": "definition-symbols", "definition_relocations": "definition-relocations",
                        "consumer_source": "consumer-source", "consumer_object": "consumer-object",
                        "consumer_compile": "consumer-compile",
                        "consumer_symbols": "consumer-symbols", "consumer_relocations": "consumer-relocations",
                    }.items()},
                })
        providers = {
            tree: {
                "static": [{"name": "unrelated", "binding": "GLOBAL", "visibility": "DEFAULT",
                            "section_index": "1", "type": "FUNC"}],
                "shared": [{"name": "unrelated", "binding": "GLOBAL", "visibility": "DEFAULT",
                            "section_index": "1", "type": "FUNC"}],
            }
            for tree in ("candidate", "reference")
        }
        raw_provider_observations = {
            "candidate": {"static": {key: {"path": "candidate-" + key} for key in ("members", "headers", "sections", "symbols")},
                          "shared": {"symbols": {"path": "candidate-shared-symbols"}}},
            "reference": {"static": {key: {"path": "reference-" + key} for key in ("members", "headers", "sections", "symbols")},
                          "shared": {"symbols": {"path": "reference-shared-symbols"}}},
        }
        return deferred, products, compiler, alloca, {"jobs": seqbuf_jobs}, providers, raw_provider_observations

    def test_selected_callable_boundary_receipt_has_exact_owner_scope_and_raw_observations(self):
        arguments = self.selected_boundary_fixture()
        receipt = ABI._selected_callable_boundary_summary(*arguments)
        replayed = ABI._selected_callable_boundary_summary(*arguments, retained=receipt)
        self.assertEqual(replayed, receipt)
        self.assertEqual(receipt["alloca"]["owner"]["resolution"], "compiler-builtin")
        self.assertEqual(receipt["alloca"]["no_libc_import"], {"undefined_symbols": [], "relocation_symbols": []})
        self.assertEqual(receipt["seqbuf_dump"]["owner"]["resolution"], "consumer-supplied")
        self.assertEqual(len(receipt["seqbuf_dump"]["jobs"]), 4)
        self.assertEqual(receipt["seqbuf_dump"]["jobs"][1]["definition_symbol"], "_Z11seqbuf_dumpv")
        self.assertEqual(receipt["oracle_no_provider"]["members"], sorted(name for name in arguments[0]
                                                                           if arguments[0][name]["resolution"] == "oracle-declared-no-provider"))
        self.assertEqual(receipt["oracle_no_provider"]["provider_absence"], {
            tree: {form: [] for form in ("static", "shared")}
            for tree in ("candidate", "reference")
        })
        self.assertEqual(receipt["oracle_no_provider"]["raw_provider_observations"], arguments[6])
        self.assertEqual(receipt["products"], arguments[1])

    def test_selected_callable_replay_accepts_the_report_v2_boundary_shape(self):
        class ReplayReached(Exception):
            pass

        arguments = self.selected_boundary_fixture()
        receipt = ABI._selected_callable_boundary_summary(*arguments)
        scratch = ROOT / ".work" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            boundary_output = Path(temporary) / "reviewed-cpp-linkage"
            selected_root = boundary_output / "selected-callable-boundaries"
            (selected_root / "alloca" / "c11-gnu").mkdir(parents=True)
            tools = {
                "clang": {"identity": {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}},
                "readelf": {"identity": {"path": "/tools/readelf"}},
            }
            extra_tools = {"ld": {"identity": {"path": "/tools/ld"}}}
            with mock.patch.object(ABI, "_profile_records", return_value={}), \
                    mock.patch.object(ABI, "_validate_artifact_descriptor", side_effect=ReplayReached):
                with self.assertRaises(ReplayReached):
                    ABI._selected_callable_boundary_evidence(
                        boundary_output,
                        Path("/workspace") / boundary_output.relative_to(ROOT),
                        static_product=Path("/unused/static"),
                        dynamic_product=Path("/unused/dynamic"),
                        products=arguments[1],
                        deferred=arguments[0],
                        tools=tools,
                        extra_tools=extra_tools,
                        resource_include="/resource/include",
                        timeout_seconds=1,
                        provider_rows=arguments[5],
                        raw_provider_observations=arguments[6],
                        command=lambda *args, **kwargs: None,
                        owned_linker={"path": "/tools/ld", "sha256": "c" * 64},
                        retained=receipt,
                    )

    def test_selected_callable_boundary_receipt_rejects_missing_owner_evidence_and_providers(self):
        arguments = self.selected_boundary_fixture()
        missing_owner = copy.deepcopy(arguments)
        del missing_owner[0]["seqbuf_dump"]
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "consumer-supplied"):
            ABI._selected_callable_boundary_summary(*missing_owner)

        missing_name = copy.deepcopy(arguments)
        del missing_name[0]["swapcontext"]
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "no-provider roster"):
            ABI._selected_callable_boundary_summary(*missing_name)

        injected_provider = copy.deepcopy(arguments)
        injected_provider[5]["candidate"]["static"].append({
            "name": "getcontext", "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "1", "type": "FUNC",
        })
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "candidate static libc provides"):
            ABI._selected_callable_boundary_summary(*injected_provider)

    def test_selected_callable_boundary_receipt_rejects_wrong_declaration_compiler_or_consumer(self):
        for index, path, value, message in (
            (3, ("qual_type",), "long *(size_t)", "alloca declaration"),
            (3, ("compiler", "path"), "/tools/other-clang", "alloca compiler"),
            (4, ("jobs", 0, "qual_type"), "int (void)", "seqbuf_dump declaration"),
            (4, ("jobs", 1, "consumer_undefined_symbol"), "seqbuf_dump", "declaration or consumer linkage"),
        ):
            arguments = self.selected_boundary_fixture()
            value_target = arguments[index]
            for key in path[:-1]:
                value_target = value_target[key]
            value_target[path[-1]] = value
            with self.subTest(message=message), self.assertRaisesRegex(ABI.NativeDeclarationAbiError, message):
                ABI._selected_callable_boundary_summary(*arguments)

    def test_selected_callable_boundary_receipt_rejects_changed_product_seal(self):
        arguments = self.selected_boundary_fixture()
        retained = ABI._selected_callable_boundary_summary(*arguments)
        changed = copy.deepcopy(arguments)
        changed[1]["dynamic"]["libc"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "retained selected callable boundary differs"):
            ABI._selected_callable_boundary_summary(*changed, retained=retained)

    @contextlib.contextmanager
    def reviewed_header_products(self):
        scratch = ROOT / '.work/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            output = work / 'evidence'
            (output / 'reviewed-cpp-linkage').mkdir(parents=True)
            roots = {kind: work / kind for kind in ('static', 'dynamic')}
            kernel = {'linux/example.h': b'#define KERNEL_EXAMPLE 1\n'}
            manifest = ''.join(f'{hashlib.sha256(value).hexdigest()}  ./{name}\n'
                               for name, value in sorted(kernel.items()))
            products = {}
            for kind, root in roots.items():
                shutil.copytree(ROOT / 'include', root / 'usr/include')
                for name, value in kernel.items():
                    path = root / 'usr/include/crabc-linux-uapi' / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(value)
                product_manifest = root / 'share/crabc/manifest.json'
                product_manifest.parent.mkdir(parents=True)
                product_manifest.write_text('{}\n')
                identity = ABI._external_identity(product_manifest, 'fixture product manifest')
                identity['path'] = str(ABI.SOURCE_MOUNT / product_manifest.relative_to(ROOT))
                products[kind] = {'root': str(ABI.SOURCE_MOUNT / root.relative_to(ROOT)), 'manifest': identity}
            retained = {'classification': None, 'jobs': None, 'links': None, 'oracle_inputs': None,
                        'products': products, 'raw': None, 'tools': {'ar': {'identity': {}, 'version': {}}}}
            with mock.patch.object(ABI.callable_inventory, 'LINUX_UAPI_HEADER_MANIFEST_SHA256',
                                   hashlib.sha256(manifest.encode()).hexdigest()):
                yield output, roots, retained

    def test_reviewed_cpp_links_accept_authenticated_installed_header_composition(self):
        class RetainedToolReplay(Exception):
            pass

        with self.reviewed_header_products() as (output, roots, retained):
            with mock.patch.object(ABI, '_cpp_boundary_plans', return_value=[]), \
                    mock.patch.object(ABI, '_profile_records', return_value={}), \
                    mock.patch.object(ABI, '_validate_tool_identity', side_effect=RetainedToolReplay):
                with self.assertRaises(RetainedToolReplay):
                    ABI._cpp_linkage_evidence(output, [], tools={}, resource_include='/unused',
                                              static_product=roots['static'], dynamic_product=roots['dynamic'],
                                              timeout_seconds=1, retained=retained)

    def test_reviewed_cpp_links_reject_header_composition_drift_in_either_product(self):
        def replace_with_symlink(path):
            path.unlink()
            path.symlink_to(ROOT / 'include/stdio.h')

        mutations = {
            'project-bytes': lambda root: (root / 'stdio.h').write_text('foreign\n'),
            'kernel-bytes': lambda root: (root / 'crabc-linux-uapi/linux/example.h').write_text('foreign\n'),
            'project-file': lambda root: (root / 'foreign.h').write_text('foreign\n'),
            'kernel-file': lambda root: (root / 'crabc-linux-uapi/linux/foreign.h').write_text('foreign\n'),
            'project-directory': lambda root: (root / 'foreign').mkdir(),
            'kernel-directory': lambda root: (root / 'crabc-linux-uapi/foreign').mkdir(),
            'missing-kernel': lambda root: shutil.rmtree(root / 'crabc-linux-uapi'),
            'project-symlink': lambda root: replace_with_symlink(root / 'stdio.h'),
            'kernel-symlink': lambda root: replace_with_symlink(root / 'crabc-linux-uapi/linux/example.h'),
            'nonregular-entry': lambda root: os.mkfifo(root / 'foreign'),
        }
        for kind in ('static', 'dynamic'):
            for name, mutate in mutations.items():
                with self.subTest(product=kind, mutation=name), self.reviewed_header_products() as (output, roots, retained):
                    mutate(roots[kind] / 'usr/include')
                    with mock.patch.object(ABI, '_cpp_boundary_plans', return_value=[]), \
                            mock.patch.object(ABI, '_profile_records', return_value={}), \
                            mock.patch.object(ABI, '_validate_tool_identity', side_effect=AssertionError('accepted drift')):
                        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, f'reviewed {kind} installed header tree rejected'):
                            ABI._cpp_linkage_evidence(output, [], tools={}, resource_include='/unused',
                                                      static_product=roots['static'], dynamic_product=roots['dynamic'],
                                                      timeout_seconds=1, retained=retained)

    def test_selected_callable_candidate_inventory_survives_the_bridge_handoff(self):
        bridge_provider = {
            "name": "membarrier", "binding": "GLOBAL", "visibility": "DEFAULT",
            "section_index": "1", "type": "FUNC", "size_bytes": 16,
        }
        candidate_static = [{"name": "candidate-static", "binding": "GLOBAL", "visibility": "DEFAULT",
                             "section_index": "1", "type": "FUNC"}]
        reference_static = [{"name": "reference-static", "binding": "GLOBAL", "visibility": "DEFAULT",
                             "section_index": "1", "type": "FUNC"}]
        reference_shared = [{"name": "reference-shared", "binding": "GLOBAL", "visibility": "DEFAULT",
                             "section_index": "1", "type": "FUNC"}]
        with self.reviewed_header_products() as (output, roots, _retained):
            boundary_output = output / "reviewed-cpp-linkage"
            shutil.rmtree(boundary_output)
            handoff = {}

            def retain_tool(_output, _source, destination, description):
                name = "ar" if "ar " in description else "ld"
                digest = "b" * 64 if name == "ar" else "c" * 64
                return {
                    "mode": 0o755, "path": f"/tools/{name}", "sha256": digest, "size": 1,
                    "retained": {"mode": 0o755, "path": destination.name, "sha256": digest, "size": 1},
                }

            def capture_command(root, directory, label, argv, *, cwd, environment, timeout_seconds):
                stdout_path = directory / f"{label}.stdout"
                stdout_path.write_text(label + "\n", encoding="ascii")
                return {"returncode": 0, "stdout": ABI._artifact_identity(root, stdout_path, label + " stdout")}

            def static_inventory(_members, _headers, _sections, _symbols, archive):
                return candidate_static if archive.endswith("/usr/lib/libc.a") else reference_static

            def dynamic_inventory(text):
                return [bridge_provider] if text == "candidate-shared-symbols\n" else reference_shared

            def selected_boundary(*_args, **kwargs):
                handoff.update(kwargs["provider_rows"])
                return {"handoff": True}

            with mock.patch.object(ABI, "_cpp_boundary_plans", return_value=[]), \
                    mock.patch.object(ABI, "_profile_records", return_value={}), \
                    mock.patch.object(ABI, "_retain_tool_identity", side_effect=retain_tool), \
                    mock.patch.object(ABI, "_capture_command", side_effect=capture_command), \
                    mock.patch.object(ABI.elf_facts, "installed_header_tree_digest", return_value="d" * 64), \
                    mock.patch.object(ABI.abi_inventory, "parse_archive_members", return_value=["member.o"]), \
                    mock.patch.object(ABI, "oracle_static_provider_rows", side_effect=static_inventory), \
                    mock.patch.object(ABI.abi_inventory, "parse_dynamic_symbol_rows", side_effect=dynamic_inventory), \
                    mock.patch.object(ABI, "reviewed_cpp_linkage_boundary", return_value={
                        "candidate_symbol": "membarrier", "reference_symbol": "_Z10membarrierii",
                    }), \
                    mock.patch.object(ABI, "_selected_callable_product_seal", return_value={}), \
                    mock.patch.object(ABI, "_selected_callable_boundary_evidence", side_effect=selected_boundary):
                report = ABI._cpp_linkage_evidence(
                    output, [], tools={"readelf": {"identity": {"path": "/tools/readelf"}}},
                    resource_include="/tools/resource", static_product=roots["static"],
                    dynamic_product=roots["dynamic"], timeout_seconds=1,
                )
        self.assertEqual(handoff, {
            "candidate": {"static": candidate_static, "shared": [bridge_provider]},
            "reference": {"static": reference_static, "shared": reference_shared},
        })
        self.assertEqual(report["selected_callable_boundaries"], {"handoff": True})

    def test_selected_callable_alloca_compile_argv_uses_workspace_product_path(self):
        class CompileCaptured(Exception):
            pass

        with self.reviewed_header_products() as (output, roots, _retained):
            boundary_output = output / "alloca-argv"
            boundary_output.mkdir()
            recorded_output = Path("/workspace") / boundary_output.relative_to(ROOT)
            captured = {}

            def capture_compile(_directory, label, argv, _previous=None):
                if label == "compile":
                    captured["argv"] = argv
                    raise CompileCaptured
                raise AssertionError(f"unexpected selected boundary command: {label}")

            profile = ABI.callable_inventory.Profile("c11-gnu", "c", "c11", ("_GNU_SOURCE=1",))
            with mock.patch.object(ABI, "_profile_records", return_value={"c11-gnu": profile}), \
                    self.assertRaises(CompileCaptured):
                ABI._selected_callable_boundary_evidence(
                    boundary_output, recorded_output, static_product=roots["static"],
                    dynamic_product=roots["dynamic"], products={}, deferred={},
                    tools={"clang": {"identity": {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}},
                           "readelf": {"identity": {"path": "/tools/readelf"}}},
                    extra_tools={"ld": {"identity": {"path": "/tools/ld"}}},
                    resource_include="/tools/resource", timeout_seconds=1, provider_rows={},
                    raw_provider_observations={}, command=capture_compile, owned_linker={},
                )
            expected_header_root = Path("/workspace") / roots["static"].relative_to(ROOT) / "usr/include"
            argv = captured["argv"]
            self.assertEqual(argv[argv.index("-I") + 1], str(expected_header_root))
            with mock.patch.object(ABI, "ROOT", Path("/workspace")), \
                    mock.patch.object(ABI, "_physical_path", side_effect=lambda path, *_args, **_kwargs: Path(path)):
                collector_product = Path("/workspace") / roots["static"].relative_to(ROOT)
                self.assertEqual(ABI._installed_product_header_root(collector_product), expected_header_root)

    def test_selected_callable_collector_consumes_real_symbol_and_relocation_rows(self):
        compiler, readelf = (shutil.which(name) for name in ("clang", "readelf"))
        if any(tool is None for tool in (compiler, readelf)):
            self.skipTest("native compiler and ELF reader are required")
        scratch = ROOT / ".work" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            tiny_object = Path(temporary) / "alloca.o"
            source = (
                "#include <alloca.h>\n"
                "int selected_alloca(void) {\n"
                "    volatile size_t size = 64;\n"
                "    volatile unsigned char *bytes = alloca(size);\n"
                "    bytes[0] = (unsigned char)size;\n"
                "    return bytes[0] != (unsigned char)size;\n"
                "}\n"
            )
            compiled = subprocess.run(
                [compiler, "-x", "c", "-std=c11", "-I", str(ROOT / "include"), "-O0",
                 "-fno-stack-protector", "-fdata-sections", "-c", "-o", str(tiny_object), "-"],
                input=source,
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "LANG": "C", "LC_ALL": "C", "TMPDIR": str(scratch)},
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            symbols = subprocess.run(
                [readelf, "-sW", str(tiny_object)], text=True, capture_output=True, check=True,
            ).stdout
            relocations = subprocess.run(
                [readelf, "-rW", str(tiny_object)], text=True, capture_output=True, check=True,
            ).stdout
            parsed_symbols = ABI.parse_symbol_table(symbols)
            undefined_symbols = sorted({row["name"] for row in parsed_symbols
                                        if row["binding"] in {"GLOBAL", "WEAK"}
                                        and row["section"] == "UND" and row["name"]})
            self.assertEqual(undefined_symbols, [])

            class LinkReached(Exception):
                pass

            with self.reviewed_header_products() as (output, roots, _retained):
                boundary_output = output / "selected-boundary-parser"
                boundary_output.mkdir()
                recorded_output = Path("/workspace") / boundary_output.relative_to(ROOT)

                def collect_command(directory, label, argv, _previous=None):
                    if label == "link":
                        raise LinkReached
                    if label == "compile":
                        recorded_object = Path(argv[argv.index("-o") + 1])
                        physical_object = boundary_output / recorded_object.relative_to(recorded_output)
                        physical_object.write_bytes(tiny_object.read_bytes())
                        output_text = ""
                    elif label == "symbols":
                        output_text = symbols
                    elif label == "relocations":
                        output_text = relocations
                    else:
                        raise AssertionError(f"unexpected selected boundary command: {label}")
                    stdout_path = directory / f"{label}.stdout"
                    stdout_path.write_text(output_text, encoding="utf-8")
                    return {
                        "returncode": 0,
                        "stdout": ABI._artifact_identity(boundary_output, stdout_path, f"selected {label} stdout"),
                    }

                deferred = self.selected_boundary_fixture()[0]
                tools = {
                    "clang": {"identity": {"mode": 0o755, "path": compiler, "sha256": "a" * 64, "size": 1}},
                    "readelf": {"identity": {"path": readelf}},
                }
                profile = ABI.callable_inventory.Profile("c11-gnu", "c", "c11", ("_GNU_SOURCE=1",))
                with mock.patch.object(ABI, "_profile_records", return_value={"c11-gnu": profile}), \
                        self.assertRaises(LinkReached):
                    ABI._selected_callable_boundary_evidence(
                        boundary_output,
                        recorded_output,
                        static_product=roots["static"],
                        dynamic_product=roots["dynamic"],
                        products={},
                        deferred=deferred,
                        tools=tools,
                        extra_tools={"ld": {"identity": {"path": "/tools/ld"}}},
                        resource_include="/tools/resource",
                        timeout_seconds=1,
                        provider_rows={},
                        raw_provider_observations={},
                        command=collect_command,
                        owned_linker={},
                    )

    def test_physical_c_bridge_links_and_pinned_cpp_reference_fails_without_a_provider(self):
        compiler, linker, readelf, archiver, objcopy = (shutil.which(name) for name in ("clang", "ld", "readelf", "ar", "objcopy"))
        if any(tool is None for tool in (compiler, linker, readelf, archiver, objcopy)):
            self.skipTest("native compiler, linker, archive and ELF readers are required")
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            reference_headers = work / "reference" / "sys"
            reference_headers.mkdir(parents=True)
            (reference_headers / "membarrier.h").write_text("int membarrier(int, int);\n", encoding="ascii")
            provider = work / "provider.o"
            subprocess.run([compiler, "-x", "c", "-fPIC", "-c", "-o", str(provider), "-"],
                           input="int membarrier(int command, int flags) { return command + flags; }\n",
                           text=True, capture_output=True, check=True)
            archive = work / "libc.a"
            shared = work / "libc.so"
            subprocess.run([archiver, "rcs", str(archive), str(provider)], capture_output=True, check=True)
            empty = work / "empty.o"
            subprocess.run([compiler, "-x", "assembler", "-c", "-o", str(empty), "-"],
                           input="", text=True, capture_output=True, check=True)
            subprocess.run([objcopy, "--strip-all", str(empty)], capture_output=True, check=True)
            subprocess.run([archiver, "r", str(archive), str(empty)], capture_output=True, check=True)
            members = ABI.abi_inventory.parse_archive_members(subprocess.run([archiver, "t", str(archive)],
                                                               capture_output=True, text=True, check=True).stdout)
            facts = [subprocess.run([readelf, flag, str(archive)], capture_output=True, text=True, check=True).stdout
                     for flag in ("-hW", "-SW", "-sW")]
            provider_rows = ABI.oracle_static_provider_rows(members, *facts, str(archive))
            self.assertTrue(any(row["name"] == "membarrier" and row["section_index"] != "UND" for row in provider_rows))
            omitted_symbols = "".join(f"File: {archive}({member})\n\n" for member in members)
            with self.assertRaisesRegex(ABI.abi_inventory.InventoryError, "symbol/section table counts"):
                ABI.oracle_static_provider_rows(members, facts[0], facts[1], omitted_symbols, str(archive))
            subprocess.run([linker, "-shared", str(provider), "-o", str(shared)], capture_output=True, check=True)
            for tree in ("candidate", "reference"):
                for profile in ("c11-gnu", "c11-strict", "cxx17-gnu", "cxx17-strict"):
                    with self.subTest(tree=tree, profile=profile):
                        item = group(name="membarrier", profile=profile)
                        item["input_header"] = "sys/membarrier.h"
                        plan = next(row for row in ABI.linkage_jobs_from_callable_account({"groups": [item]})
                                    if row["tree"] == tree)
                        source = work / (tree + "-" + profile + ".c")
                        source.write_text(ABI.generated_source(plan, executable_probe=True), encoding="ascii")
                        probe = source.with_suffix(".o")
                        cpp = profile.startswith("cxx")
                        include = ROOT / "include" if tree == "candidate" else work / "reference"
                        subprocess.run([compiler, "-x", "c++" if cpp else "c", "-std=c++17" if cpp else "-std=c11",
                                        "-nostdinc", "-I", str(include), "-fPIC", "-fdata-sections", "-c",
                                        str(source), "-o", str(probe)], capture_output=True, check=True)
                        symbols = subprocess.run([readelf, "-sW", str(probe)], capture_output=True, text=True, check=True).stdout
                        relocations = subprocess.run([readelf, "-rW", str(probe)], capture_output=True, text=True, check=True).stdout
                        observed = ABI.evaluate_object_linkage(plan, ABI.parse_symbol_table(symbols), ABI.parse_relocations(relocations))[0]
                        negative = tree == "reference" and cpp
                        self.assertEqual(observed["status"], "ordinary-linkage-identity-mismatch" if negative else "ordinary-undefined-reference")
                        for form in ("static", "static-pie", "pie", "non-pie"):
                            output = work / (tree + "-" + profile + "-" + form)
                            static = form.startswith("static")
                            command = [linker, "--no-demangle", "--no-undefined", "-e", "main"]
                            if form in ("static-pie", "pie"):
                                command.append("-pie")
                            if static:
                                command.append("--no-dynamic-linker")
                            command.extend([str(probe), str(archive if static else shared), "-o", str(output)])
                            linked = subprocess.run(command, capture_output=True, text=True, check=False)
                            if negative:
                                self.assertNotEqual(linked.returncode, 0)
                                self.assertIn("_Z10membarrierii", linked.stderr)
                                continue
                            self.assertEqual(linked.returncode, 0, linked.stderr)
                            symbols = subprocess.run([readelf, "-sW", str(output)], capture_output=True, text=True, check=True).stdout
                            sections = subprocess.run([readelf, "-SW", str(output)], capture_output=True, text=True, check=True).stdout
                            joined = ABI.physical_reference_join(output, symbols, sections, static=static)
                            self.assertEqual(joined["symbol"], "membarrier")
                            self.assertEqual(joined["kind"], "static-provider-address" if static else "dynamic-provider-reference")
                            if form == "static":
                                table = ABI.abi_inventory.parse_elf_symbol_tables(symbols)[0]
                                holder = next(row for row in table["rows"] if row["name"] == "crabc_native_declaration_abi_reference_0")
                                section = next(row for row in ABI.abi_inventory.parse_elf_sections(sections)["sections"]
                                               if str(row["index"]) == holder["section_index"])
                                position = int(section["offset"], 16) + int(holder["value"], 16) - int(section["address"], 16)
                                altered = bytearray(output.read_bytes())
                                struct.pack_into("<Q", altered, position, joined["provider_address"] + 1)
                                output.write_bytes(altered)
                                with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "pointer"):
                                    ABI.physical_reference_join(output, symbols, sections, static=True)

    def test_reviewed_cpp_boundary_keeps_the_reference_symbol_and_requires_no_provider(self):
        reviewed = ABI.callable_declarations.REVIEWED_CPP_LINKAGE_DIFFERENCE
        plans = []
        jobs = []
        for tree in ("candidate", "reference"):
            for profile in ("c11-gnu", "c11-strict", "cxx17-gnu", "cxx17-strict"):
                cpp_reference = tree == "reference" and profile.startswith("cxx")
                item = group(name="membarrier", profile=profile)
                item["input_header"] = reviewed["header"]
                plan = next(row for row in ABI.linkage_jobs_from_callable_account({"groups": [item]})
                            if row["tree"] == tree)
                plans.append(plan)
                observed = ({"category": "reference-backed", "expected_symbol": "membarrier",
                             "holder": plan["references"][0]["holder"],
                             "observed_symbol": "_Z10membarrierii", "relocation_type": "R_X86_64_64",
                             "status": "ordinary-linkage-identity-mismatch"} if cpp_reference else
                            {"category": "reference-backed", "name": "membarrier",
                             "status": "ordinary-undefined-reference", "symbol": "membarrier"})
                jobs.append({**plan, "observations": [observed]})
        providers = {form: [{"name": "membarrier", "type": "FUNC", "binding": "GLOBAL",
                             "visibility": "DEFAULT", "section_index": "1"}]
                     for form in ("static", "shared")}
        boundary = ABI.reviewed_cpp_linkage_boundary(plans, jobs, providers)
        self.assertEqual(boundary["disposition"], "oracle-declared-no-provider")
        self.assertEqual(boundary["reference_symbol"], "_Z10membarrierii")
        self.assertEqual(boundary["reference_job_indices"], [6, 7])
        self.assertEqual(jobs[6]["observations"][0]["status"], "ordinary-linkage-identity-mismatch")
        for form in providers:
            with self.subTest(form=form):
                changed = copy.deepcopy(providers)
                changed[form].append({**changed[form][0], "name": "_Z10membarrierii"})
                with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "provider"):
                    ABI.reviewed_cpp_linkage_boundary(plans, jobs, changed)
        changed = copy.deepcopy(jobs)
        changed[6]["observations"][0]["observed_symbol"] = "_Z10membarrieriii"
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "reference"):
            ABI.reviewed_cpp_linkage_boundary(plans, changed, providers)

    def test_x86_membarrier_c_and_cpp_profiles_emit_the_c_abi_symbol(self):
        clang = shutil.which("clang")
        nm = shutil.which("nm")
        if clang is None or nm is None:
            self.skipTest("native C++ compiler and symbol reader are required")
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            for profile in ("c11-gnu", "c11-strict", "cxx17-gnu", "cxx17-strict"):
                with self.subTest(profile=profile):
                    output = Path(temporary) / (profile + ".o")
                    cpp = profile.startswith("cxx")
                    command = [clang, "-x", "c++" if cpp else "c",
                               "-std=c++17" if cpp else "-std=c11",
                               "-nostdinc", "-isystem", str(ROOT / "include")]
                    if profile.endswith("-gnu"):
                        command.append("-D_GNU_SOURCE=1")
                    command += ["-c", "-o", str(output), "-"]
                    source = ("#include <sys/membarrier.h>\n"
                              "static __typeof__(&membarrier) volatile reference "
                              "__attribute__((used)) = &membarrier;\n")
                    compiled = subprocess.run(command, input=source, text=True, capture_output=True, check=False)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    symbols = subprocess.run([nm, "--undefined-only", str(output)],
                                             text=True, capture_output=True, check=True).stdout
                    self.assertEqual(symbols.splitlines(), ["                 U membarrier"])

    def _ordinary_job_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, object], dict[str, object], dict[str, object]]:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        output = Path(temporary.name)
        directory = output / "raw" / "candidate" / "demo.h" / "c11-gnu"
        directory.mkdir(parents=True)
        plan = ABI.linkage_jobs_from_callable_account({"groups": [group(profile="c11-gnu")]})[0]
        source = directory / "source.c"
        source.write_text(ABI.generated_source(plan), encoding="utf-8")
        object_file = directory / "ordinary.o"
        object_file.write_bytes(b"ordinary-object\n")
        symbol_text = """Symbol table '.symtab' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     8 OBJECT  LOCAL  DEFAULT    3 crabc_native_declaration_abi_reference_0
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND foo
"""
        relocation_text = """Relocation section '.rela.data.crabc_native_declaration_abi_reference_0' at offset 0x1 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000200000001 R_X86_64_64       0000000000000000 foo + 0
"""
        profiles = ABI._profile_records()
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        source_collector = collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "source.c"
        object_collector = collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "ordinary.o"
        environment = {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "TMPDIR": str(collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "tmp"),
            "TZ": "UTC",
        }
        tools = {
            "clang": {"identity": {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}},
            "readelf": {"identity": {"mode": 0o755, "path": "/tools/readelf", "sha256": "b" * 64, "size": 1}},
        }

        def command(label: str, argv: list[str], stdout: str) -> dict[str, object]:
            command_path = directory / f"{label}.command.json"
            stdout_path = directory / f"{label}.stdout"
            stderr_path = directory / f"{label}.stderr"
            status_path = directory / f"{label}.status.json"
            command_path.write_text(json.dumps(argv) + "\n", encoding="utf-8")
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            status_path.write_text('{"returncode": 0}\n', encoding="utf-8")
            return {
                "argv": argv,
                "command": ABI._artifact_identity(output, command_path, label + " command"),
                "cwd": "/workspace",
                "environment": environment,
                "returncode": 0,
                "status": ABI._artifact_identity(output, status_path, label + " status"),
                "stderr": ABI._artifact_identity(output, stderr_path, label + " stderr"),
                "stdout": ABI._artifact_identity(output, stdout_path, label + " stdout"),
            }

        compile_argv = ABI._compile_argv(
            Path("/tools/clang"), profiles["c11-gnu"], Path("/workspace/include"),
            Path("/tools/resource"), Path("/opt/linux-5.10-uapi/include"), source_collector, object_collector,
        )
        raw = {
            "compile": command("compile", compile_argv, ""),
            "symbols": command("symbols", ["/tools/readelf", "-sW", str(object_collector)], symbol_text),
            "relocations": command("relocations", ["/tools/readelf", "-rW", str(object_collector)], relocation_text),
            "source": ABI._artifact_identity(output, source, "source"),
        }
        observations = ABI.evaluate_object_linkage(plan, ABI.parse_symbol_table(symbol_text), ABI.parse_relocations(relocation_text))
        job = {
            "header": "demo.h", "language": "c", "names": ["foo"],
            "object": ABI._artifact_identity(output, object_file, "object"), "observations": observations,
            "ordinal": 0, "profile": "c11-gnu", "raw": raw, "references": plan["references"], "tree": "candidate",
        }
        return temporary, output, plan, tools, job

    def _tool_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, dict[str, object], dict[str, object]]:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        output = Path(temporary.name)
        tools_directory = output / "inputs" / "tools"
        tools_directory.mkdir(parents=True)
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        environment = {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "TMPDIR": str(collector_output / "inputs" / "tools"), "TZ": "UTC",
        }

        def command(label: str, argv: list[str]) -> dict[str, object]:
            command_path = tools_directory / f"{label}.command.json"
            stdout_path = tools_directory / f"{label}.stdout"
            stderr_path = tools_directory / f"{label}.stderr"
            status_path = tools_directory / f"{label}.status.json"
            command_path.write_text(json.dumps(argv) + "\n", encoding="utf-8")
            stdout_path.write_text("tool-version\n", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            status_path.write_text('{"returncode": 0}\n', encoding="utf-8")
            return {
                "argv": argv,
                "command": ABI._artifact_identity(output, command_path, label + " command"),
                "cwd": "/workspace",
                "environment": environment,
                "returncode": 0,
                "status": ABI._artifact_identity(output, status_path, label + " status"),
                "stderr": ABI._artifact_identity(output, stderr_path, label + " stderr"),
                "stdout": ABI._artifact_identity(output, stdout_path, label + " stdout"),
            }

        resource = tools_directory / "clang-resource" / "stddef.h"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(b"retained resource header\n")
        resource_record = ABI._artifact_identity(output, resource, "resource")
        readelf = tools_directory / "readelf"
        readelf.write_bytes(b"retained readelf\n")
        readelf.chmod(0o755)
        readelf_record = ABI._artifact_identity(output, readelf, "readelf")
        clang_identity = {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}
        header_tools = {
            "clang": {"path": "/tools/clang", "sha256": "a" * 64, "size": 1},
            "resource_headers": [],
            "resource_include": "/tools/resource",
        }
        tools = {
            "clang": {
                "identity": clang_identity,
                "requested": "clang",
                "resource_include": {
                    "path": "/tools/resource",
                    "records": [{
                        "kind": "file", "mode": resource_record["mode"], "path": "stddef.h",
                        "retained": resource_record, "sha256": resource_record["sha256"], "size": resource_record["size"],
                    }],
                },
                "version": command("clang-version", ["/tools/clang", "--version"]),
            },
            "readelf": {
                "identity": {
                    "mode": readelf_record["mode"], "path": "/tools/readelf", "sha256": readelf_record["sha256"],
                    "size": readelf_record["size"], "retained": readelf_record,
                },
                "requested": "readelf",
                "version": command("readelf-version", ["/tools/readelf", "--version"]),
            },
        }
        return temporary, output, collector_output, tools, header_tools

    def test_generated_c_and_cxx_sources_use_the_header_not_synthetic_declarations(self) -> None:
        plans = ABI.linkage_jobs_from_callable_account({"groups": [group(profile="c11-gnu"), group(profile="cxx17-gnu")]})
        self.assertEqual(
            [(item["tree"], item["language"], item["names"]) for item in plans],
            [("candidate", "c", ["foo"]), ("candidate", "cxx", ["foo"]),
             ("reference", "c", ["foo"]), ("reference", "cxx", ["foo"])],
        )
        for plan in plans:
            source = ABI.generated_source(plan)
            self.assertIn("#include <demo.h>", source)
            self.assertIn("&foo", source)
            self.assertNotIn("extern ", source)

    def test_cxx_mangled_reference_is_retained_from_the_object_observation(self) -> None:
        plan = ABI.linkage_jobs_from_callable_account({"groups": [group()]})[0]
        symbols = ABI.parse_symbol_table(
            """Symbol table '.symtab' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     8 OBJECT  LOCAL  DEFAULT    3 crabc_native_declaration_abi_reference_0
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND _Z3foov
"""
        )
        relocations = ABI.parse_relocations(
            """Relocation section '.rela.data.crabc_native_declaration_abi_reference_0' at offset 0x1 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000200000001 R_X86_64_64       0000000000000000 _Z3foov + 0
"""
        )
        self.assertEqual(
            ABI.evaluate_object_linkage(plan, symbols, relocations),
            [{
                "category": "reference-backed",
                "expected_symbol": "foo",
                "holder": "crabc_native_declaration_abi_reference_0",
                "observed_symbol": "_Z3foov",
                "relocation_type": "R_X86_64_64",
                "status": "ordinary-linkage-identity-mismatch",
            }],
        )

        symbols[2]["name"] = "foo"
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "relocation"):
            ABI.evaluate_object_linkage(plan, symbols, [])
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "unambiguous retained relocation"):
            ABI.evaluate_object_linkage(
                plan,
                symbols,
                [{
                    "section": ".rela.data.some_other_source_holder",
                    "symbol": "foo",
                    "type": "R_X86_64_64",
                }],
            )
        self.assertEqual(
            ABI.evaluate_object_linkage(
                plan,
                symbols,
                [{
                    "addend": 0,
                    "offset": 0,
                    "section": ".rela.data.crabc_native_declaration_abi_reference_0",
                    "symbol": "foo",
                    "symbol_index": 2,
                    "type": "R_X86_64_64",
                }],
            ),
            [{
                "category": "reference-backed",
                "name": "foo",
                "status": "ordinary-undefined-reference",
                "symbol": "foo",
            }],
        )

    def test_ambiguous_direct_declaration_fails_before_source_generation(self) -> None:
        ambiguous = group(candidate=[observation("foo"), observation("foo")])
        ambiguous["candidate_observations"][1]["mangled_name_observation"] = "_Z3foov"
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "ambiguous"):
            ABI.linkage_jobs_from_callable_account({"groups": [ambiguous]})

    def test_header_defined_case_is_retained_as_a_limit_not_forced_to_undefined(self) -> None:
        plan = ABI.linkage_jobs_from_callable_account(
            {"groups": [group(name="inline_foo", candidate=[observation("inline_foo", definition="function-body-present")], reference=[] , category="candidate-project-extension")]}
        )[0]
        result = ABI.evaluate_object_linkage(
            plan,
            [{"name": "inline_foo", "binding": "LOCAL", "visibility": "DEFAULT", "type": "FUNC", "section": ".text"}],
            [],
        )
        self.assertEqual(result[0]["status"], "header-defined-or-inline")
        self.assertEqual(result[0]["source_definition_observation"], "function-body-present")

    def test_reviewed_native_tgkill_extension_has_a_candidate_object_plan_only(self) -> None:
        extension = group(
            name="tgkill",
            profile="c11-gnu",
            candidate=[observation("tgkill")],
            reference=[],
            category="reviewed-native-extension",
        )
        plans = ABI.linkage_jobs_from_callable_account({"groups": [extension]})
        self.assertEqual(
            plans,
            [{
                "tree": "candidate",
                "header": "demo.h",
                "profile": "c11-gnu",
                "language": "c",
                "names": ["tgkill"],
                "references": [{
                    "category": "reviewed-native-extension",
                    "holder": "crabc_native_declaration_abi_reference_0",
                    "name": "tgkill",
                    "source_definition_observations": ["extern-declaration-without-initializer"],
                    "expected_observation": "ordinary-undefined-reference",
                }],
            }],
        )

    def test_replayed_header_envelope_reuses_the_existing_public_replay(self) -> None:
        """A selection caller can pass its one authenticated header envelope.

        The declaration component still derives its finite plan from the full
        envelope, but it must not reopen the 616MB raw header receipt after
        the selection reader has already replayed it.
        """
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        header_report = Path(temporary.name) / "header-report.json"
        header_report.write_text("{}\n", encoding="utf-8")
        envelope = {
            "current_selecting_source": {"matches_retained": True, "differences": []},
            "report": {},
        }
        account = {
            "selected_callable_declaration_status": "proved-with-explicit-boundaries",
            "groups": [group(profile="c11-gnu")],
        }
        with mock.patch.object(ABI.declaration_inventory, "validate_report") as header_replay, \
             mock.patch.object(ABI, "_header_tool_envelope", return_value={
                 "clang": {"path": "/tools/clang", "sha256": "a" * 64, "size": 1},
                 "resource_headers": [], "resource_include": "/tools/resource",
             }), \
             mock.patch.object(ABI, "_callable_partition", return_value=(
                 ["foo"], {}, [], {"partition": "fixture"},
             )), \
             mock.patch.object(ABI, "_matrix_projection", return_value=(
                 {"schema": "fixture"}, {"matrix": "fixture"},
             )), \
             mock.patch.object(ABI.callable_declarations, "account_declarations", return_value=account):
            derived, plans, _source, tools = ABI.derive_callable_plan(
                header_report,
                header_envelope=envelope,
            )
        header_replay.assert_not_called()
        self.assertEqual(derived, account)
        self.assertEqual(plans[0]["names"], ["foo"])
        self.assertEqual(tools["clang"]["path"], "/tools/clang")

    def test_replayed_header_envelope_rejects_historical_source_drift(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        header_report = Path(temporary.name) / "header-report.json"
        header_report.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "historical source drift"):
            ABI.derive_callable_plan(
                header_report,
                header_envelope={
                    "current_selecting_source": {
                        "matches_retained": False,
                        "differences": [{"path": "include/demo.h"}],
                    },
                    "report": {},
                },
            )

    def test_checked_layout_projection_keeps_only_the_two_selected_record_facts(self) -> None:
        report = ABI.read_json_object(ROOT / "compat" / "x86_64" / "generated" / "header_record_layout_matrix" / "report.json", "layout report")
        projection = ABI.project_checked_record_layout(report)
        self.assertEqual([item["record"] for item in projection["records"]], ["_ns_flagdata", "in6_addr"])
        self.assertEqual(projection["limits"]["_ns_flagdata_array_extent"], "not-proved-by-record-layout")
        self.assertEqual(projection["limits"]["FILE"], "opaque-or-incomplete-not-proved")

        changed = copy.deepcopy(report)
        for row in changed["rows"]:
            if row["header"] == "netinet/in.h" and row["profile"] == "c11-gnu":
                for record in row["candidate_records"]:
                    if record["name"] == "in6_addr":
                        record["size"] = 32
        with self.assertRaises(ABI.NativeDeclarationAbiError):
            ABI.project_checked_record_layout(changed)

    def test_pointer_initializer_requires_exact_relocation_and_local_holder(self) -> None:
        temporary, output, plan, _tools, _job = self._ordinary_job_fixture()
        self.addCleanup(temporary.cleanup)
        directory = output / "raw" / "candidate" / "demo.h" / "c11-gnu"
        symbols = ABI.parse_symbol_table((directory / "symbols.stdout").read_text(encoding="utf-8"))
        relocations = ABI.parse_relocations((directory / "relocations.stdout").read_text(encoding="utf-8"))
        self.assertEqual(
            relocations,
            [{
                "addend": 0, "offset": 0, "section": ".rela.data.crabc_native_declaration_abi_reference_0",
                "symbol": "foo", "symbol_index": 2, "type": "R_X86_64_64",
            }],
        )
        self.assertEqual(ABI.evaluate_object_linkage(plan, symbols, relocations)[0]["status"], "ordinary-undefined-reference")
        for field, value, message in (
            ("type", "R_X86_64_NONE", "type"),
            ("addend", 8, "addend"),
            ("offset", 8, "offset"),
            ("symbol_index", 1, "symbol index"),
        ):
            changed = copy.deepcopy(relocations)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ABI.NativeDeclarationAbiError, message):
                ABI.evaluate_object_linkage(plan, symbols, changed)
        wrong_holder = copy.deepcopy(symbols)
        wrong_holder[1]["size"] = 4
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "holder metadata"):
            ABI.evaluate_object_linkage(plan, wrong_holder, relocations)

    def test_tool_replay_authenticates_header_clang_and_retained_missing_tool_bytes(self) -> None:
        temporary, output, collector_output, tools, header_tools = self._tool_fixture()
        self.addCleanup(temporary.cleanup)
        normalized = ABI._validate_tools(output, tools, collector_output, 1.0, header_tools=header_tools)
        self.assertEqual(normalized["clang"]["identity"]["sha256"], "a" * 64)
        changed_clang = copy.deepcopy(tools)
        changed_clang["clang"]["identity"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "public-header compiler envelope"):
            ABI._validate_tools(output, changed_clang, collector_output, 1.0, header_tools=header_tools)
        changed_resource = copy.deepcopy(tools)
        changed_resource["clang"]["resource_include"]["records"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "resource tree file.*bytes differ"):
            ABI._validate_tools(output, changed_resource, collector_output, 1.0, header_tools=header_tools)
        retained_readelf = output / "inputs" / "tools" / "readelf"
        retained_readelf.write_bytes(b"substituted readelf\n")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "readelf executable bytes differ"):
            ABI._validate_tools(output, tools, collector_output, 1.0, header_tools=header_tools)

    def test_declared_symbol_table_rows_cannot_be_silently_dropped(self) -> None:
        truncated = """Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
"""
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "truncated|missing"):
            ABI.parse_symbol_table(truncated)

    def test_retained_object_replay_requires_the_exact_symbol_and_relocation_observation(self) -> None:
        temporary, output, plan, tools, job = self._ordinary_job_fixture()
        self.addCleanup(temporary.cleanup)
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        profiles = ABI._profile_records()
        replayed = ABI._validate_job(
            output, collector_output, job, plan, 0,
            tools=tools, profiles=profiles, resource_include="/tools/resource",
        )
        self.assertEqual(replayed["observations"][0]["symbol"], "foo")

        relocation_stdout = output / job["raw"]["relocations"]["stdout"]["path"]
        relocation_stdout.write_text("There are no relocations in this file.\n", encoding="utf-8")
        job["raw"]["relocations"]["stdout"] = ABI._artifact_identity(output, relocation_stdout, "changed relocation stdout")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "relocation"):
            ABI._validate_job(
                output, collector_output, job, plan, 0,
                tools=tools, profiles=profiles, resource_include="/tools/resource",
            )

    def test_cli_rejects_repeated_header_input_before_collection(self) -> None:
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "repeated"):
            ABI._parse_cli([
                "--collect", "--header-report", ".work/first.json", "--header-report", ".work/second.json",
                "--output", ".work/x86_64/native-declaration-abi/fresh",
            ])


if __name__ == "__main__":
    unittest.main()

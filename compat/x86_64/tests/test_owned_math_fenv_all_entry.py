#!/usr/bin/env python3
"""Contract checks for the bounded installed math/fenv all-entry component."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as catalog
import owned_math_fenv_all_entry_contract as contract
import owned_math_fenv_all_entry_evidence as evidence
import owned_math_fenv_all_entry_receipt as receipt
import validate_owned_math_fenv_all_entry as stream

RUNNER = ROOT / "compat/x86_64/run_owned_math_fenv_all_entry.sh"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"
CATALOG = ROOT / "compat/x86_64/owned_dynamic_qualification.py"
DRIVER = ROOT / "compat/x86_64/owned_math_fenv_all_entry_driver.c"


class OwnedMathFenvAllEntryTests(unittest.TestCase):
    def assert_usage(self, *arguments: str) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), *arguments], cwd=ROOT, capture_output=True,
            text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [[--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT]\n",
        )

    def test_exact_four_contract_roster_has_206_distinct_entries(self) -> None:
        roster = contract.load_roster(ROOT)
        self.assertEqual(
            {name: len(symbols) for name, symbols in roster.items()},
            {
                "math.elementary-long-double": 35,
                "math.elementary-fenv-sensitive": 15,
                "math.special": 90,
                "math.complex": 66,
            },
        )
        all_symbols = tuple(symbol for symbols in roster.values() for symbol in symbols)
        self.assertEqual(len(all_symbols), 206)
        self.assertEqual(len(set(all_symbols)), 206)
        self.assertIn("sqrtl", roster["math.elementary-long-double"])
        self.assertNotIn("sqrt", all_symbols)
        self.assertNotIn("sqrtf", all_symbols)
        self.assertTrue({"csqrt", "csqrtf", "csqrtl"}.issubset(roster["math.complex"]))

    def test_object_roster_reuses_the_complete_existing_observations(self) -> None:
        self.assertEqual(
            contract.OBJECT_ROLES,
            (
                ("driver", "compat/x86_64/owned_math_fenv_all_entry_driver.c", None),
                ("elementary-long-double", "compat/x86_64/libc_math_elementary_long_double_probe.c", "CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING"),
                ("fenv-sensitive-aggregate", "compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c", None),
                ("fenv-rounding", "compat/x86_64/libc_fenv_rounding_probe.c", "CRABC_FENV_ROUNDING_FREESTANDING"),
                ("fdim", "compat/x86_64/libc_fdim_probe.c", "CRABC_FDIM_FREESTANDING"),
                ("exp10", "compat/x86_64/libc_math_exp10_probe.c", "CRABC_MATH_EXP10_FREESTANDING"),
                ("exp10f", "compat/x86_64/libc_math_exp10f_probe.c", "CRABC_MATH_EXP10F_FREESTANDING"),
                ("long-double-completion", "compat/x86_64/libc_math_long_double_completion_probe.c", "CRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING"),
                ("special", "compat/x86_64/libc_math_special_probe.c", "CRABC_MATH_SPECIAL_FREESTANDING"),
                ("complex", "compat/x86_64/libc_math_complex_complete_probe.c", "CRABC_MATH_COMPLEX_COMPLETE_FREESTANDING"),
                ("abi-boundary", "compat/x86_64/libc_math_abi_boundary_probe.c", "CRABC_MATH_ABI_BOUNDARY_FREESTANDING"),
            ),
        )
        for _, relative, _ in contract.OBJECT_ROLES:
            self.assertTrue((ROOT / relative).is_file(), relative)

        for relative, accessor in (
            ("compat/x86_64/libc_math_exp10_probe.c", "crabc_x86_64_math_exp10_record_data"),
            ("compat/x86_64/libc_math_exp10f_probe.c", "crabc_x86_64_math_exp10f_record_data"),
        ):
            self.assertIn(accessor, (ROOT / relative).read_text(encoding="utf-8"))

    def test_driver_composes_every_existing_probe_and_distinguishes_sqrt_boundary(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        for callable_name in (
            "crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe",
            "crabc_x86_64_fenv_rounding_probe",
            "crabc_x86_64_fdim_probe",
            "crabc_x86_64_math_exp10_probe",
            "crabc_x86_64_math_exp10f_probe",
            "crabc_x86_64_math_long_double_completion_probe",
            "crabc_x86_64_math_special_probe",
            "crabc_x86_64_math_complex_complete_probe",
            "crabc_x86_64_math_elementary_long_double_probe",
            "crabc_x86_64_math_abi_boundary_probe",
        ):
            self.assertIn(callable_name, source)

    def test_driver_reads_each_producer_extent_after_its_accessor_returns(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        # The initial installed oracle run reached exp10, then emitted stage
        # status -1 because the compositor loaded its zero-initialized extent
        # before calling the accessor. Keep the returned pointer and extent
        # together at the producer boundary.
        self.assertIn("emit_record_data_from_accessor", source)
        for accessor in (
            "crabc_x86_64_math_exp10_record_data",
            "crabc_x86_64_math_exp10f_record_data",
        ):
            self.assertIn(f"emit_record_data_from_accessor({accessor})", source)

    def test_stream_validator_requires_the_fixed_stage_order_and_size(self) -> None:
        pieces = []
        for stage, _, body_size in stream.STAGES:
            pieces.append(stream.FRAME.pack(
                stream.MAGIC, stage, 1, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
            pieces.append(b"\0" * body_size)
            pieces.append(stream.FRAME.pack(
                stream.MAGIC, stage, 2, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
        records = b"".join(pieces)
        self.assertEqual(len(records), stream.EXPECTED_SIZE)
        stream.validate_bytes(records)
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(records[:-1])

        # A begin frame records the driver's pre-call boundary and must be
        # clean just as the post-restoration frame is.  This guards a probe
        # that reports a failure before it can alter its caller environment.
        begin_failure = bytearray(records)
        begin_failure[8] = 7
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(begin_failure))

        # Equal begin/end environments alone do not prove the driver installed
        # its specified FE_UPWARD + DIVBYZERO|INEXACT caller boundary.
        coherent_wrong_environment = bytearray(records)
        offset = 0
        for _, _, body_size in stream.STAGES:
            for frame_offset in (offset, offset + stream.FRAME.size + body_size):
                stream.FRAME.pack_into(
                    coherent_wrong_environment, frame_offset, stream.MAGIC,
                    stream.FRAME.unpack_from(coherent_wrong_environment, frame_offset)[1],
                    stream.FRAME.unpack_from(coherent_wrong_environment, frame_offset)[2],
                    0, 0, 0,
                )
            offset += 2 * stream.FRAME.size + body_size
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(coherent_wrong_environment))

        wrong_stage = bytearray(records)
        stream.FRAME.pack_into(
            wrong_stage, 0, stream.MAGIC, 2, 1, 0,
            stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
        )
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(wrong_stage))

        altered = bytearray(records)
        altered[stream.FRAME.size - 1] ^= 1
        with self.assertRaises(stream.ValidationError):
            stream.validate_bytes(bytes(altered))

    def test_runner_usage_and_path_boundary(self) -> None:
        for arguments in (
            ("--static-sysroot",), ("--static-sysroot", ""), ("--static-sysroot", "/one"),
            ("--static-sysroot", "-x"), ("",), ("-x",),
            ("--static-sysroot", "/one", "--static-sysroot", "/two"),
            ("/one", "/two"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_usage(*arguments)

        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-math-fenv-path.", dir=scratch) as temporary:
            base = Path(temporary)
            product = base / "product"
            product.mkdir()
            alias = base / "product-alias"
            alias.symlink_to(product, target_is_directory=True)
            parent = base / "parent"
            parent.mkdir()
            for argument in (alias, parent / ".." / "product", ROOT):
                with self.subTest(argument=argument):
                    result = subprocess.run(
                        ["bash", str(RUNNER), str(argument)], cwd=ROOT,
                        env={**os.environ, "TMPDIR": str(base)}, capture_output=True,
                        text=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("owned math/fenv all-entry dynamic product", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(set(base.iterdir()), {product, alias, parent})

    def test_dynamic_catalog_registers_the_exact_component(self) -> None:
        self.assertEqual(catalog.CASES["math-fenv-all-entry"],
                         ("run_owned_math_fenv_all_entry.sh", None))

    def test_binary_provider_reader_binds_all_selected_imports_and_definitions(self) -> None:
        symbols = tuple(symbol for group in contract.load_roster(ROOT).values() for symbol in group)
        aliases = {"pow10": "exp10", "pow10f": "exp10f", "pow10l": "exp10l"}
        imports = "\n".join(f"{name} U" for name in symbols) + "\n"
        dynamic = "\n".join(
            f"{index}: {index if name not in aliases else symbols.index(aliases[name]) + 1:016x} "
            f"0 FUNC {'WEAK' if name in aliases else 'GLOBAL'} DEFAULT 1 {name}"
            for index, name in enumerate(symbols, start=1)
        ) + "\n"
        static = "\n".join(
            f"libc.a:owner-{index}.o: {name} T 0 1"
            for index, name in enumerate(symbols, start=1)
        ) + "\n"
        record = evidence.validate(ROOT, imports, dynamic, static)
        self.assertEqual(record["et_rel_imports"], sorted(symbols))
        self.assertEqual(set(record["dynamic_providers"]), set(symbols))
        self.assertEqual(set(record["static_provider_members"]), set(symbols))

        missing_sqrtl = dynamic.replace(
            next(line for line in dynamic.splitlines() if line.endswith(" sqrtl")) + "\n", "",
        )
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate(ROOT, imports, missing_sqrtl, static)

    def test_binary_provider_reader_rejects_role_argv_and_ambient_header_drift(self) -> None:
        dynamic = ROOT / ".work/x86_64/provider-fixture/dynamic"
        work = ROOT / ".work/x86_64/provider-fixture/work"
        compiler = Path("/sealed/fixed-image-gcc")
        work.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(work.parent, ignore_errors=True))
        (dynamic / "share/crabc").mkdir(parents=True, exist_ok=True)
        (dynamic / "share/crabc/crabc_cc_static.py").write_text("HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n", encoding="utf-8")
        trace = "".join(f". {dynamic / 'usr/include' / header}\n"
                        for header in evidence.INSTALLED_HEADERS)
        for role, relative, define in contract.OBJECT_ROLES:
            (work / f"compile-{role}.argv.json").write_text(
                json.dumps(evidence.compile_argv(ROOT, work, dynamic, role, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.argv.json").write_text(
                json.dumps(evidence.header_argv(ROOT, dynamic, compiler, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.stderr").write_text(trace, encoding="utf-8")
        evidence.validate_invocations(ROOT, work, dynamic, compiler)
        (work / "header-driver.stderr").write_text(". /usr/include/math.h\n", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_invocations(ROOT, work, dynamic, compiler)
        (work / "header-driver.stderr").write_text(trace, encoding="utf-8")
        path = work / "compile-exp10.argv.json"
        command = json.loads(path.read_text(encoding="utf-8"))
        command.remove("-DCRABC_MATH_EXP10_FREESTANDING")
        path.write_text(json.dumps(command), encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_invocations(ROOT, work, dynamic, compiler)

    def test_receipt_rejects_rehashed_provider_text_that_disagrees_with_artifacts(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-provider-replay-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        static = root / "static"
        dynamic = root / "dynamic"
        work.mkdir()
        (static / "usr/lib").mkdir(parents=True)
        (dynamic / "usr/include").mkdir(parents=True)
        (dynamic / "usr/lib").mkdir(parents=True)
        (dynamic / "bin").mkdir(parents=True)
        (dynamic / "share/crabc").mkdir(parents=True)

        # These physical inputs stand in for the independently authenticated
        # ET_REL object, DSO, and archive. The old receipt reader never reads
        # them while accepting a fully coherent, rehashed provider claim.
        (work / "workload.o").write_bytes(b"actual workload artifact")
        (dynamic / "usr/lib/libc.so").write_bytes(b"actual dynamic artifact")
        (static / "usr/lib/libc.a").write_bytes(b"actual static artifact")
        compiler = dynamic / "bin/fixed-image-gcc"
        compiler.write_bytes(b"fixed image compiler")
        (dynamic / "share/crabc/crabc_cc_static.py").write_text(
            f"HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\ndef compiler():\n    return {str(compiler)!r}\n", encoding="utf-8"
        )

        trace = "".join(f". {dynamic / 'usr/include' / header}\n"
                        for header in evidence.INSTALLED_HEADERS)
        for role, relative, define in contract.OBJECT_ROLES:
            (work / f"compile-{role}.argv.json").write_text(
                json.dumps(evidence.compile_argv(ROOT, work, dynamic, role, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.argv.json").write_text(
                json.dumps(evidence.header_argv(ROOT, dynamic, compiler, relative, define)),
                encoding="utf-8",
            )
            (work / f"header-{role}.stderr").write_text(trace, encoding="utf-8")

        symbols = tuple(symbol for group in contract.load_roster(ROOT).values() for symbol in group)
        aliases = {"pow10": "exp10", "pow10f": "exp10f", "pow10l": "exp10l"}
        imports = "\n".join(f"{symbol} U" for symbol in symbols) + "\n"
        static_definitions = "\n".join(
            f"libc.a:owner-{index}.o: {symbol} T 0 1"
            for index, symbol in enumerate(symbols, start=1)
        ) + "\n"

        def dynamic_definitions(offset: int) -> str:
            values = {symbol: index + offset for index, symbol in enumerate(symbols, start=1)}
            for alias, target in aliases.items():
                values[alias] = values[target]
            return "\n".join(
                f"{index}: {values[symbol]:016x} 0 FUNC "
                f"{'WEAK' if symbol in aliases else 'GLOBAL'} DEFAULT 1 {symbol}"
                for index, symbol in enumerate(symbols, start=1)
            ) + "\n"

        def identity(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        retained_dynamic = dynamic_definitions(0x1000)
        actual_dynamic = dynamic_definitions(0)
        result = evidence.validate(
            ROOT, imports, retained_dynamic, static_definitions, work, dynamic,
        )
        provider = work / "provider.json"
        provider.write_text(json.dumps(result), encoding="utf-8")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        command_paths = {}
        for stem, output in (
            ("workload-imports", imports),
            ("dynamic-provider-symbols", retained_dynamic),
            ("static-provider-symbols", static_definitions),
            ("component-preflight", encoded),
            ("component-collector", encoded),
        ):
            path = work / f"{stem}.stdout"
            path.write_text(output, encoding="utf-8")
            command_paths[stem] = {"stdout": path}

        def completed(stdout: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess([], 0, stdout.encode("utf-8"), b"")

        # The positive control proves that the reader accepts its retained
        # projection when the independently observed three views match it.
        with mock.patch.object(receipt.subprocess, "run", side_effect=[
            completed(imports), completed(retained_dynamic), completed(static_definitions),
        ]) as positive_replay:
            self.assertEqual(
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                ),
                provider,
            )

        # Rehashing the retained symbol text and provider JSON can keep all
        # parser, roster, and alias-address checks coherent. It cannot make
        # the retained dynamic address projection true of the actual DSO.
        forged_dynamic = dynamic_definitions(0x2000)
        result = evidence.validate(ROOT, imports, forged_dynamic, static_definitions, work, dynamic)
        provider.write_text(json.dumps(result), encoding="utf-8")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        command_paths["dynamic-provider-symbols"]["stdout"].write_text(forged_dynamic, encoding="utf-8")
        for stem in ("component-preflight", "component-collector"):
            command_paths[stem]["stdout"].write_text(encoded, encoding="utf-8")
        with mock.patch.object(receipt.subprocess, "run", side_effect=[
            completed(imports), completed(actual_dynamic), completed(static_definitions),
        ]):
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )
        self.assertEqual(
            [call.args[0] for call in positive_replay.call_args_list],
            [
                ["/usr/bin/nm", "--undefined-only", "--format=posix", str(work / "workload.o")],
                ["/usr/bin/readelf", "--dyn-syms", "-W", str(dynamic / "usr/lib/libc.so")],
                ["/usr/bin/nm", "-A", "-g", "--defined-only", "--format=posix", str(static / "usr/lib/libc.a")],
            ],
        )
        with mock.patch.object(receipt.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 7, b"partial output", b"inspection failed",
        )):
            with self.assertRaisesRegex(receipt.ReceiptError, "exited with status 7"):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )
        with mock.patch.object(receipt.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, imports.encode("utf-8"), b"unexpected diagnostic",
        )):
            with self.assertRaisesRegex(receipt.ReceiptError, "wrote stderr"):
                receipt.validate_provider_record(
                    ROOT, identity(provider), command_paths, work, dynamic, static,
                )

    def test_receipt_output_reader_requires_a_valid_pinned_oracle_stream(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-stream-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))

        records = bytearray()
        for stage, _name, body_size in stream.STAGES:
            records.extend(stream.FRAME.pack(
                stream.MAGIC, stage, 1, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
            records.extend(b"\0" * body_size)
            records.extend(stream.FRAME.pack(
                stream.MAGIC, stage, 2, 0,
                stream.CALLER_ROUNDING, stream.CALLER_EXCEPTIONS,
            ))
        expected = bytes(records)
        self.assertEqual(len(expected), stream.EXPECTED_SIZE)

        def result_paths(prefix: str, stdout: bytes) -> dict[str, Path]:
            paths = {
                "stdout": root / f"{prefix}.stdout",
                "stderr": root / f"{prefix}.stderr",
                "status": root / f"{prefix}.status",
            }
            paths["stdout"].write_bytes(stdout)
            paths["stderr"].write_bytes(b"")
            paths["status"].write_bytes(b"0\n")
            return paths

        oracle = result_paths("oracle", expected)
        receipt.output_matches_oracle(result_paths("matching", expected), "matching", oracle)
        changed = bytearray(expected)
        # The first three stages have no body. Change exp10's retained raw
        # record after its begin frame so the stream framing remains valid and
        # the rejection below proves byte-for-byte oracle comparison.
        first_nonempty_body = sum(
            2 * stream.FRAME.size + body_size
            for _stage, _label, body_size in stream.STAGES[:3]
        ) + stream.FRAME.size
        changed[first_nonempty_body] ^= 1
        stream.validate_bytes(bytes(changed))
        with self.assertRaises(receipt.ReceiptError):
            receipt.output_matches_oracle(result_paths("changed", bytes(changed)), "changed", oracle)

    def test_receipt_replays_link_semantics_after_a_link_record_is_rehashed(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-link-receipt-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        link = work / "static.product-link.json"
        link.write_text(json.dumps({"linkage": "static", "product": "forged"}), encoding="utf-8")
        data = link.read_bytes()
        identity = {
            "path": link.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        expected = {"linkage": "static", "product": "replayed"}
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected):
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_link(ROOT, {}, {"static": identity}, work, static, dynamic, "static")

    def test_receipt_replays_link_validate_stdout_after_identity_rehash(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-link-validate-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        expected = {"linkage": "static", "product": "replayed"}
        link = work / "static.product-link.json"
        link.write_text(json.dumps(expected, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        def identity(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        validate_stdout = work / "static-validate.stdout"
        validate_stdout.write_text(
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        paths = {"static-validate": {"stdout": validate_stdout}}
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected):
            receipt.validate_link(ROOT, paths, {"static": identity(link)}, work, static, dynamic, "static")

            # The report's command identity can be recomputed over changed
            # bytes, but that cannot replace replay of the public reader.
            altered = {"linkage": "static", "product": "altered"}
            validate_stdout.write_text(
                json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            self.assertEqual(
                receipt.validate_identity(ROOT, identity(validate_stdout), "static validate stdout"),
                validate_stdout,
            )
            with self.assertRaises(receipt.ReceiptError):
                receipt.validate_link(ROOT, paths, {"static": identity(link)}, work, static, dynamic, "static")

    def test_receipt_maps_dynamic_report_linkages_to_the_public_reader(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-dynamic-linkage-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        work = root / "work"
        work.mkdir()
        static, dynamic = root / "static", root / "dynamic"
        static.mkdir()
        dynamic.mkdir()
        link = work / "dynamic-pie.crabc-link.json"
        expected = {"linkage": "pie", "product": "replayed"}
        link.write_text(json.dumps(expected), encoding="utf-8")
        data = link.read_bytes()
        identity = {
            "path": link.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        validate_stdout = work / "dynamic-pie-validate.stdout"
        validate_stdout.write_text(
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        with mock.patch.object(receipt.product_evidence, "validate_link", return_value=expected) as validate:
            receipt.validate_link(
                ROOT, {"dynamic-pie-validate": {"stdout": validate_stdout}},
                {"dynamic-pie": identity}, work, static, dynamic, "dynamic-pie",
            )
        validate.assert_called_once_with(
            dynamic, work / "workload.o", work / "dynamic-pie",
            Path(str(work / "dynamic-pie") + ".crabc-link.json"), "pie",
        )

    def test_receipt_rejects_final_and_intermediate_identity_symlink_hops(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-symlink-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        target = root / "target.json"
        target.write_text("{}", encoding="utf-8")
        final_link = root / "final.json"
        final_link.symlink_to(target.name)
        nested = root / "nested"
        nested.mkdir()
        (nested / "value.json").write_text("{}", encoding="utf-8")
        intermediate = root / "intermediate"
        intermediate.symlink_to(nested.name, target_is_directory=True)
        with self.assertRaises(receipt.ReceiptError):
            receipt.physical(ROOT, final_link.relative_to(ROOT).as_posix())
        with self.assertRaises(receipt.ReceiptError):
            receipt.physical(ROOT, (intermediate / "value.json").relative_to(ROOT).as_posix())

    def test_provider_header_trace_rejects_an_ambient_include(self) -> None:
        root = ROOT / ".work/x86_64/owned-math-fenv-header-trace-fixture"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        dynamic = root / "dynamic"
        work = root / "work"
        work.mkdir()
        include = dynamic / "usr/include"
        valid_trace = "".join(f". {include / header}\n" for header in evidence.INSTALLED_HEADERS)
        for role, _relative, _define in contract.OBJECT_ROLES:
            (work / f"header-{role}.stderr").write_text(valid_trace, encoding="utf-8")
        evidence.validate_header_traces(work, dynamic)
        (work / "header-driver.stderr").write_text(". /usr/include/math.h\n", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_header_traces(work, dynamic)

    def test_runner_remains_shell_syntax_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

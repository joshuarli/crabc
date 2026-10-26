"""Mold traces retain every ordered object and archive member input."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import mold_link_trace as trace
import consumer_rust_std_lto as consumer


def archive(*names: str) -> bytes:
    data = b"!<arch>\n"
    for name in names:
        body = b"member"
        data += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode() + body
    return data


class MoldLinkTraceTests(unittest.TestCase):
    def test_archive_argument_dedup_preserves_duplicate_member_occurrences(self) -> None:
        data = archive("one.o", "one.o")
        trace.validate_trace(
            ["trace: /crt.o", "trace: /lib.a(one.o)", "trace: /lib.a(one.o)", "trace: /end.o"],
            initial_objects=["/crt.o"], archives=[("/lib.a", data), ("/empty.a", archive()), ("/lib.a", data)],
            final_objects=["/end.o"],
        )
        with self.assertRaisesRegex(ValueError, "archive identity"):
            trace.validate_trace([], initial_objects=[], archives=[("/lib.a", data), ("/lib.a", archive())],
                                 final_objects=[])

    def test_missing_extra_reordered_and_foreign_members_remain_rejected(self) -> None:
        valid = ["trace: /crt.o", "trace: /lib.a(one.o)", "trace: /lib.a(two.o)", "trace: /end.o"]
        variants = (
            valid[:1] + valid[2:], valid[:2] + valid[1:], valid[:1] + valid[2:3] + valid[1:2] + valid[3:],
            valid + ["trace: /foreign.o"],
            [line.replace("two.o", "foreign.o") for line in valid],
            valid[1:], [line.removeprefix("trace: ") if index != 1 else "trace: " + line
                        for index, line in enumerate(valid)],
        )
        for changed in variants:
            with self.subTest(trace=changed), self.assertRaisesRegex(ValueError, "linker trace"):
                trace.validate_trace(changed, initial_objects=["/crt.o"],
                                     archives=[("/lib.a", archive("one.o", "two.o"))], final_objects=["/end.o"])

    @unittest.skipUnless(consumer.ORACLE_CC.is_file(), "requires the pinned native oracle compiler")
    def test_actual_mold_oracle_control_and_resealed_trace_mutations(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            lane = output / "gates/lto/A"
            lane.mkdir(parents=True)
            retained = consumer.Retained(output)
            inputs = consumer._oracle_static_inputs()
            steps = []
            for index, command in enumerate(consumer._oracle_static_commands(lane)):
                result = consumer.run(command, env=consumer.tool_environment(), cwd=lane)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                steps.append({"command": command, "returncode": result.returncode,
                              "stdout": retained.write(f"gates/lto/A/step{index}.stdout", result.stdout)})
            report = {"steps": steps, "object": retained.record(lane / "static.o"),
                      "executable": retained.record(lane / "musl-static"),
                      "oracle_inputs": {name: retained.record(path) for name, path in inputs.items()}}
            consumer._validate_oracle_static_lane(report, lane)
            result = subprocess.run([lane / "musl-static"], capture_output=True, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, consumer.EXPECTED_STDOUT["lto-c"], b""))
            raw = lane / "step1.stdout"
            lines = raw.read_text().splitlines()
            member = next(index for index, line in enumerate(lines) if "libc.a(" in line)
            variants = (lines + ["trace: /foreign.o"], lines[:member] + lines[member + 1:],
                        [line.replace("libc.a(", "libc.a(foreign-") if index == member else line
                         for index, line in enumerate(lines)])
            for changed in variants:
                raw.write_text("\n".join(changed) + "\n")
                report["steps"][1]["stdout"] = retained.record(raw)
                with self.assertRaisesRegex(consumer.GateError, "linker trace"):
                    consumer._validate_oracle_static_lane(report, lane)

import tempfile
import unittest
from pathlib import Path

import report


class MissingSymbolReportTests(unittest.TestCase):
    def test_extracts_linker_forms_and_ignores_missing_libraries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = Path(directory) / "link.err"
            diagnostic.write_text(
                "\n".join(
                    (
                        "/usr/bin/ld: undefined reference to `quoted_symbol'",
                        "/usr/bin/ld: undefined reference to 'single_quoted'",
                        "/usr/bin/ld: undefined reference to unquoted_symbol",
                        "/usr/bin/ld: undefined symbol: runtime_symbol",
                        "/usr/bin/ld: relocation R_AARCH64 against undefined symbol 'reloc_symbol'",
                        "/usr/bin/ld: cannot find -lnot_a_symbol",
                        "/usr/bin/ld: undefined reference to `quoted_symbol'",
                    )
                )
                + "\n"
            )

            self.assertEqual(
                report.missing_symbols(str(diagnostic)),
                [
                    "quoted_symbol",
                    "reloc_symbol",
                    "runtime_symbol",
                    "single_quoted",
                    "unquoted_symbol",
                ],
            )

    def test_link_event_is_attributed_to_each_missing_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = root / "link.err"
            diagnostic.write_text("undefined reference to `first'\nundefined symbol: second\n")
            events = root / "events.tsv"
            events.write_text(f"functional\talpha\tBUILDERROR\tlink\tlink_error\t{diagnostic}\n")

            result = report.read_events(events)[0]

            self.assertEqual(result["reason"], "missing_symbols")
            self.assertEqual(result["missing_symbols"], ["first", "second"])


if __name__ == "__main__":
    unittest.main()

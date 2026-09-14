#!/usr/bin/env python3
"""Source-level guards for the native locale/time alias ABI contract."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "compat/x86_64/locale_alias_contract.json"
PROBE = ROOT / "compat/x86_64/locale_alias_contract_probe.c"
RUNNER = ROOT / "compat/x86_64/run_locale_alias_contract.sh"
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import locale_alias_contract_symbols as symbols
SOURCES = {
    "narrow": ROOT / "libc/src/c_abi/x86_64/locale_narrow.rs",
    "objects": ROOT / "libc/src/c_abi/x86_64/locale_objects.rs",
    "gmtime": ROOT / "libc/src/c_abi/x86_64/gmtime_r.rs",
    "calendar": ROOT / "libc/src/c_abi/x86_64/owned_calendar.rs",
    "strftime": ROOT / "libc/src/c_abi/x86_64/owned_strftime.rs",
    "timezone": ROOT / "libc/src/c_abi/x86_64/owned_timezone.rs",
}


class LocaleAliasContractTests(unittest.TestCase):
    def load_contract(self) -> dict[str, object]:
        return json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_keeps_the_complete_non_promoting_musl_alias_roster(self) -> None:
        contract = self.load_contract()
        self.assertEqual(
            set(contract),
            {
                "schema",
                "oracle",
                "visible_aliases",
                "hidden_aliases",
                "file_local_aliases",
                "reverse_visible_aliases",
                "non_alias_locale_entries",
                "family_completion",
                "promotion_ready",
                "public_support",
            },
        )
        self.assertEqual(contract["schema"], "crabc.x86_64-locale-alias-contract/v1")
        self.assertEqual(
            contract["oracle"],
            {
                "release": "musl-1.2.6",
                "revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            },
        )
        visible = contract["visible_aliases"]
        hidden = contract["hidden_aliases"]
        reverse = contract["reverse_visible_aliases"]
        self.assertIsInstance(visible, dict)
        self.assertIsInstance(hidden, dict)
        self.assertIsInstance(reverse, dict)
        self.assertEqual(len(visible), 43)
        self.assertEqual(len(hidden), 4)
        self.assertFalse(set(visible) & set(hidden))
        for public, internal in {**visible, **hidden}.items():
            self.assertEqual(internal, "__" + public)
        self.assertEqual(contract["file_local_aliases"], {"tzset": "__tzset"})
        self.assertEqual(reverse, {"freelocale": "__freelocale"})
        self.assertEqual(
            contract["non_alias_locale_entries"],
            ["wcscasecmp_l", "wcsncasecmp_l"],
        )
        self.assertEqual(
            (contract["family_completion"], contract["promotion_ready"], contract["public_support"]),
            (False, False, False),
        )

    def test_source_pairs_public_weak_symbols_with_their_actual_internal_bodies(self) -> None:
        contract = self.load_contract()
        source = "\n".join(path.read_text(encoding="utf-8") for path in SOURCES.values())
        for public, internal in contract["visible_aliases"].items():
            with self.subTest(public=public):
                self.assertIn(f'".weak {public}", ".set {public}, {internal}"', source)
                self.assertTrue(
                    f'#[export_name = "{internal}"]' in source
                    or f'{public}, "{internal}"' in source,
                    f"{public} lacks its internal implementation export",
                )
        for public, internal in contract["hidden_aliases"].items():
            with self.subTest(public=public):
                self.assertIn(f'".hidden {internal}"', source)
                self.assertIn(f'".weak {public}",', source)
                self.assertIn(f'".set {public}, {internal}"', source)
                self.assertIn(f'#[export_name = "{internal}"]', source)
        timezone = SOURCES["timezone"].read_text(encoding="utf-8")
        objects = SOURCES["objects"].read_text(encoding="utf-8")
        self.assertIn('".weak __freelocale", ".set __freelocale, freelocale"', objects)
        self.assertIn("#[no_mangle]\npub unsafe extern \"C\" fn freelocale", objects)
        self.assertIn("#[linkage = \"weak\"]\npub extern \"C\" fn tzset()", timezone)
        self.assertIn("fn refresh_tzset()", timezone)
        self.assertNotIn('export_name = "__tzset"', timezone)

    def test_internal_locale_time_calls_do_not_reenter_public_override_symbols(self) -> None:
        calendar = SOURCES["calendar"].read_text(encoding="utf-8")
        strftime = SOURCES["strftime"].read_text(encoding="utf-8")
        self.assertIn("locale_objects::fixed_c_locale()", calendar)
        self.assertIn("locale_objects::nl_langinfo_l(", calendar)
        self.assertNotIn("fn nl_langinfo(item", calendar)
        self.assertIn("locale_objects::nl_langinfo_l(item, locale)", strftime)
        self.assertIn("locale_objects::nl_langinfo(item)", strftime)
        self.assertNotIn("fn nl_langinfo_l(item", strftime)

    def test_interposition_probe_exercises_public_overrides_and_internal_high_level_calls(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for definition in (
            "locale_t newlocale",
            "locale_t duplocale",
            "locale_t uselocale",
            "char *nl_langinfo",
            "int isalpha_l",
            "int iswalpha_l",
            "int strcoll_l",
            "int wcscoll_l",
            "size_t strftime_l",
            "struct tm *gmtime_r",
            "struct tm *localtime_r",
            "char *asctime_r",
            "void tzset",
        ):
            with self.subTest(definition=definition):
                self.assertIn(definition, source)
        for internal_call in ("asctime(&value)", "gmtime(&epoch)", "localtime(&epoch)", "strftime(text"):
            with self.subTest(internal_call=internal_call):
                self.assertIn(internal_call, source)
        for locale_internal in (
            "__newlocale(LC_ALL_MASK, \"C\", NULL)",
            "__newlocale(LC_ALL_MASK, \"POSIX\", NULL)",
            "__newlocale(LC_ALL_MASK, \"C.UTF-8\", NULL)",
            "__duplocale(utf8)",
            "__uselocale(utf8)",
            "__nl_langinfo_l(CODESET, c_locale)",
            "__isalpha_l('A', utf8)",
            "__iswalpha_l(L'A', utf8)",
            "__strcoll_l(\"a\", \"b\", utf8)",
            "__wcscoll_l(L\"a\", L\"b\", utf8)",
        ):
            with self.subTest(locale_internal=locale_internal):
                self.assertIn(locale_internal, source)
        for valid_override_argument in (
            'locale_t override_locale = __newlocale(LC_ALL_MASK, "C.UTF-8", NULL)',
            "duplocale(override_locale)",
            "nl_langinfo_l(CODESET, override_locale)",
            "isalpha_l('A', override_locale)",
            "iswalpha_l(L'A', override_locale)",
            "strcasecmp_l(\"A\", \"a\", override_locale)",
            "strcoll_l(\"a\", \"b\", override_locale)",
            "strxfrm_l(transformed, \"a\", sizeof(transformed), override_locale)",
            "wcscoll_l(L\"a\", L\"b\", override_locale)",
            "wcsxfrm_l(wide_transformed, L\"a\",",
            "strftime_l(text, sizeof(text), \"%a\", &value, override_locale)",
            "extern void __freelocale(locale_t)",
            "__freelocale(override_locale)",
            "freelocale(release_locale)",
        ):
            with self.subTest(valid_override_argument=valid_override_argument):
                self.assertIn(valid_override_argument, source)

    def test_runner_is_parseable_and_binds_one_probe_contract(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('readonly PROBE="$ROOT/compat/x86_64/locale_alias_contract_probe.c"', source)
        self.assertIn('readonly CONTRACT="$ROOT/compat/x86_64/locale_alias_contract.json"', source)
        self.assertIn('readonly SYMBOLS="$ROOT/compat/x86_64/locale_alias_contract_symbols.py"', source)
        self.assertIn('candidate-static-link', source)
        self.assertIn('candidate-static-pie-link', source)
        self.assertIn('for mode in pie non-pie; do', source)
        self.assertIn('"--dynamic-$mode"', source)
        self.assertIn('"candidate-dynamic-$mode-$entry"', source)
        self.assertIn('require_elf_type candidate-static-pie DYN', source)
        self.assertIn('require_elf_type candidate-dynamic-non-pie EXEC', source)
        self.assertIn(
            'capture oracle-static-link "$ORACLE_CC" -static -no-pie "$work/probe.o"',
            source,
        )
        self.assertIn(
            'capture candidate-static-link "$static_product/bin/crabc-cc" -static',
            source,
        )
        self.assertIn(
            'capture candidate-static-pie-link "$static_product/bin/crabc-cc" -static-pie',
            source,
        )
        self.assertNotIn(
            'capture candidate-static-link "$static_product/bin/crabc-cc" -static -no-pie',
            source,
        )
        self.assertIn('readelf -Ws "$static_product/usr/lib/libc.a"', source)
        self.assertIn('readelf --dyn-syms -W "$dynamic_product/usr/lib/libc.so"', source)
        self.assertIn('capture oracle-shared-symbols /usr/bin/readelf -Ws /opt/musl-1.2.6/lib/libc.so', source)
        self.assertIn('capture candidate-shared-symbols /usr/bin/readelf -Ws "$dynamic_product/usr/lib/libc.so"', source)
        self.assertIn('capture oracle-static-symbols /usr/bin/readelf -Ws /opt/musl-1.2.6/lib/libc.a', source)
        self.assertIn(
            'capture oracle-dynamic-symbols /usr/bin/readelf --dyn-syms -W /opt/musl-1.2.6/lib/libc.so',
            source,
        )

    def test_symbol_parser_keeps_symtab_and_dynsym_observations_separate(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000040    12 FUNC    WEAK   DEFAULT    9 gmtime_r
Symbol table '.symtab' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000040    12 FUNC    LOCAL  HIDDEN     9 __gmtime_r
     2: 0000000000000040    12 FUNC    WEAK   DEFAULT    9 gmtime_r
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "symbols.txt"
            path.write_text(raw, encoding="utf-8")
            dynsym = symbols.parse_symbols(path, archive=False, table=".dynsym")
            symtab = symbols.parse_symbols(path, archive=False, table=".symtab")
        self.assertEqual([record["name"] for record in dynsym], ["", "gmtime_r"])
        self.assertEqual(
            [record["name"] for record in symtab],
            ["", "__gmtime_r", "gmtime_r"],
        )
        symbols.validate_shared_hidden_pair(symtab, "gmtime_r", "__gmtime_r", "candidate")

    def test_symbol_parser_rejects_a_truncated_selected_symbol_table(self) -> None:
        raw = """\
Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "symbols.txt"
            path.write_text(raw, encoding="utf-8")
            with self.assertRaises(symbols.LocaleAliasError):
                symbols.parse_symbols(path, archive=False, table=".symtab")

    def test_shared_time_pair_keeps_oracle_and_candidate_localization_distinct(self) -> None:
        public = {
            "file": "",
            "table": ".symtab",
            "index": "1",
            "value": "0000000000000040",
            "size": "12",
            "type": "FUNC",
            "binding": "WEAK",
            "visibility": "DEFAULT",
            "section": "9",
            "name": "gmtime_r",
        }
        oracle_internal = {**public, "index": "2", "binding": "LOCAL", "name": "__gmtime_r"}
        candidate_internal = {**oracle_internal, "visibility": "HIDDEN"}
        symbols.validate_shared_hidden_pair([public, oracle_internal], "gmtime_r", "__gmtime_r", "oracle")
        symbols.validate_shared_hidden_pair([public, candidate_internal], "gmtime_r", "__gmtime_r", "candidate")
        with self.assertRaises(symbols.LocaleAliasError):
            symbols.validate_shared_hidden_pair(
                [public, oracle_internal], "gmtime_r", "__gmtime_r", "candidate"
            )


if __name__ == "__main__":
    unittest.main()

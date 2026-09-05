"""Linkage-specific x86 entry selection without changing static defaults."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

spec = importlib.util.spec_from_file_location("crabc_x86_dynamic_modes_builder", Path(__file__).resolve().parents[1] / "build_x86_64.py")
builder = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = builder
spec.loader.exec_module(builder)


class DynamicEntryModes(unittest.TestCase):
    def test_default_and_legacy_private_modes_keep_static_crt1(self):
        for private in (False, True):
            args = SimpleNamespace(dynamic_main_thread_runtime_v1=private,
                                   general_dynamic_lifecycle=private, owned_dynamic_sysroot=False)
            selected = {item.name: item for item in builder.selected_objects(args)}
            self.assertEqual(selected["crt1.o"], builder.OBJECTS[0])
            if not private:
                self.assertEqual(tuple(selected.values()), builder.OBJECTS)

    def test_owned_dynamic_entries_share_handoff_source_but_not_relocation_model(self):
        args = SimpleNamespace(dynamic_main_thread_runtime_v1=False,
                               general_dynamic_lifecycle=False, owned_dynamic_sysroot=True)
        selected = {item.name: item for item in builder.selected_objects(args)}
        executable, pie = selected["crt1.o"], selected["Scrt1.o"]
        self.assertEqual(executable.source_name, pie.source_name)
        self.assertEqual(executable.relocation_model, "static")
        self.assertEqual(pie.relocation_model, "pic")
        self.assertEqual(executable.entry_contract, "owned-dynamic-exec-entry")
        self.assertEqual(pie.entry_contract, "owned-dynamic-pie-entry")
        self.assertEqual(executable.undefined_symbols, pie.undefined_symbols)
        self.assertNotIn("__crabc_x86_static_tls_bootstrap", executable.undefined_symbols)
        for name in ("rcrt1.o", "crti.o", "crtn.o"):
            self.assertEqual(selected[name], next(item for item in builder.OBJECTS if item.name == name))


if __name__ == "__main__":
    unittest.main()

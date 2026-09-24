"""Linkage-specific x86 entry selection: one crt1.o, mode-specific Scrt1.o."""
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
    def test_every_mode_selects_the_one_conventional_crt1(self):
        # The static and dynamic products each install this crt1.o; the
        # combined-sysroot leaf proves the installed bytes are identical.
        conventional = builder.OBJECTS[0]
        self.assertEqual(conventional.name, "crt1.o")
        for private in (False, True):
            for owned in (False, True):
                args = SimpleNamespace(dynamic_main_thread_runtime_v1=private,
                                       general_dynamic_lifecycle=private, owned_dynamic_sysroot=owned)
                selected = {item.name: item for item in builder.selected_objects(args)}
                self.assertEqual(selected["crt1.o"], conventional)
                for name in ("rcrt1.o", "crti.o", "crtn.o"):
                    self.assertEqual(selected[name], next(item for item in builder.OBJECTS if item.name == name))
        self.assertEqual(conventional.undefined_symbols, builder.CONVENTIONAL_EXEC_BOUNDARIES)

    def test_owned_dynamic_pie_entry_leaves_main_lifecycle_to_the_loader(self):
        args = SimpleNamespace(dynamic_main_thread_runtime_v1=False,
                               general_dynamic_lifecycle=False, owned_dynamic_sysroot=True)
        pie = next(item for item in builder.selected_objects(args) if item.name == "Scrt1.o")
        self.assertEqual(pie.relocation_model, "pic")
        self.assertEqual(pie.entry_contract, "owned-dynamic-pie-entry")
        # The installed owned loader constructs and finalizes the main image;
        # this entry dispatches only preinit and never calls _init/_fini.
        self.assertEqual(pie.undefined_symbols, builder.OWNED_DYNAMIC_RUNTIME_BOUNDARIES)

    def test_private_lifecycle_modes_keep_the_crt_owned_main_array_walk(self):
        for dynamic_main_thread, general in ((True, False), (False, True)):
            args = SimpleNamespace(dynamic_main_thread_runtime_v1=dynamic_main_thread,
                                   general_dynamic_lifecycle=general, owned_dynamic_sysroot=False)
            pie = next(item for item in builder.selected_objects(args) if item.name == "Scrt1.o")
            self.assertTrue({"_init", "_fini"}.issubset(pie.undefined_symbols))


if __name__ == "__main__":
    unittest.main()

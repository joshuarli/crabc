"""Run the shared dynamic-driver checks alongside their native ARM peers."""
from pathlib import Path
import sys
import unittest

import test_owned_dynamic_driver as reference

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
import test_aarch64_dynamic_non_pie as native

NATIVE_EQUIVALENTS = {
    "test_combined_driver_rejects_resealed_mixed_profiles": ("test_combined_native_product_validates_and_links_all_dynamic_modes",),
    "test_combined_sysroot_links_every_dynamic_mode_through_the_embedded_product": ("test_combined_native_product_validates_and_links_all_dynamic_modes",),
    "test_combined_sysroot_rejects_drift_from_its_roster_or_embedded_product": ("test_combined_native_product_validates_and_links_all_dynamic_modes",),
    "test_current_driver_receipt_is_schema_two_and_current_posix_reader_accepts_default": ("test_posix_link_reader_rejects_tampered_native_receipt",),
    "test_every_link_output_is_inspected_before_its_receipt_and_rejections_remove_it": ("test_nonconforming_native_outputs_are_not_published", "test_dynamic_driver_regression"),
    "test_executable_weak_data_import_keeps_its_dynamic_got_relocation": ("test_weak_data_import_keeps_native_dynamic_got_relocation",),
    "test_installed_driver_rejects_real_nonconforming_outputs_before_they_exist": ("test_nonconforming_native_outputs_are_not_published",),
    "test_libc_test_receipt_reader_retains_mold_trace_and_rejects_foreign_inputs": ("test_posix_link_reader_rejects_tampered_native_receipt",),
    "test_package_is_deterministic_and_extracted_payload_is_identical": ("test_native_package_round_trip_and_malformed_archives",),
    "test_producer_failure_keeps_partial_payload_private": ("test_native_builder_rejects_existing_output_before_tool_resolution",),
    "test_producer_final_validation_failure_and_competing_publication_preserve_destination": ("test_native_builder_rejects_existing_output_before_tool_resolution",),
    "test_relinking_a_moved_output_names_the_stale_sidecar_not_an_unsafe_alias": ("test_relink_detects_old_sidecars_without_aliasing_prospective_output",),
    "test_shared_libc_keeps_the_bounded_helper_archive_local": ("test_native_shared_libc_keeps_helper_and_errno_policies_private",),
    "test_shared_libc_link_keeps_musl_exceptions_and_errno_private_alias": ("test_native_shared_libc_keeps_helper_and_errno_policies_private", "test_errno_alias_regression"),
    "test_transitive_application_dso_closure_keeps_leaf_out_of_executable_link": ("test_transitive_application_dso_is_validation_only",),
}


def load_tests(loader, tests, pattern):
    reference_names = set(loader.getTestCaseNames(reference.InstalledDynamicDriverTests))
    native_names = set(loader.getTestCaseNames(native.Aarch64DynamicNonPieTest))
    if not set(NATIVE_EQUIVALENTS) <= reference_names or any(
        not replacements or not set(replacements) <= native_names for replacements in NATIVE_EQUIVALENTS.values()
    ):
        raise RuntimeError("native dynamic driver equivalence roster differs")
    if any(getattr(getattr(native.Aarch64DynamicNonPieTest, name), "__unittest_skip__", False)
           for replacements in NATIVE_EQUIVALENTS.values() for name in replacements):
        raise RuntimeError("native dynamic driver equivalent is skipped")
    return unittest.TestSuite(reference.InstalledDynamicDriverTests(name)
                              for name in sorted(reference_names - set(NATIVE_EQUIVALENTS)))

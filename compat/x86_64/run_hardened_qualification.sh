#!/usr/bin/env bash
set -euo pipefail
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
case "${TMPDIR:-}" in "$root"/.work/*) ;; *) exit 2;; esac
readonly compatibility="$1"
case "$compatibility" in "$root"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/hardened-qualification.XXXXXX")"
readonly static="$work/static"
readonly dynamic="$work/dynamic"

python3 -B - "$root" "$compatibility" <<'PYTHON'
from pathlib import Path
import sys

root, product = map(Path, sys.argv[1:])
if product.resolve(strict=True) != product:
    raise SystemExit("compatibility product path is not physical")
sys.path.insert(0, str(root / "compat/x86_64"))
import owned_dynamic_qualification as qualification
qualification.product_identity(product)
PYTHON

if ! python3 -B "$root/scripts/build_x86_64_owned_sysroot.py" --profile release --hardening-profile hardened \
    --output "$static" >"$work/static.log" 2>&1; then
    cat "$work/static.log" >&2
    exit 1
fi
if ! python3 -B "$root/scripts/build_x86_64_owned_dynamic_sysroot.py" --profile release --hardening-profile hardened \
    --output "$dynamic" >"$work/dynamic.log" 2>&1; then
    cat "$work/dynamic.log" >&2
    exit 1
fi

verify_products() {
    python3 -B - "$root" "$static" "$dynamic" "$compatibility" <<'PYTHON'
import json
from pathlib import Path
import sys

root, static, dynamic, compatibility = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / "compat/x86_64"))
import owned_dynamic_qualification as qualification
import owned_posix_product_evidence as evidence

source = qualification.source_digest()
qualification.product_identity(compatibility)
for product, validate in ((static, evidence._validate_static_product), (dynamic, evidence._validate_dynamic_product)):
    validate(product)
    manifest = json.loads((product / "share/crabc/manifest.json").read_text())
    if manifest.get("hardening_profile") != "hardened" or manifest.get("build_profile") != "release":
        raise SystemExit("hardened release product identity differs")
    if product == static and manifest.get("source_sha256") != source:
        raise SystemExit("hardened static product source differs")
evidence.validate_dynamic_product_source(dynamic, source)
products = {}
for name, product in (("static", static), ("dynamic", dynamic), ("compatibility", compatibility)):
    manifest = product / "share/crabc/manifest.json"
    products[name] = {"manifest": manifest.relative_to(root).as_posix(), "sha256": qualification.digest(manifest)}
print(json.dumps(products, sort_keys=True))
PYTHON
}

verify_products >/dev/null
if ! CRABC_CRT_X86_64_EVIDENCE=native CRABC_CRT_X86_64_EVIDENCE_SLICE=static-pie python3 -B -m unittest \
    crt.tests.test_x86_64_static_pie.X86_64StaticPieTests.test_hardened_static_pie_rejects_executable_or_missing_stack_and_wx_load \
    crt.tests.test_x86_64_static_pie.X86_64StaticPieTests.test_hardened_static_pie_bootstrap_executes_and_rejects_unknown_relocations \
    crt.tests.test_x86_64_static_pie.X86_64StaticPieTests.test_static_pie_bootstrap_executes_and_rejects_unknown_relocations \
    >"$work/static-pie-tests.log" 2>&1; then
    cat "$work/static-pie-tests.log" >&2
    exit 1
fi
"$root/compat/x86_64/run_hardened_entry.sh" "$dynamic" "$static" "$compatibility"
verify_products
printf 'hardened runtime: PASS\n'

#!/usr/bin/env bash
# Build the explicit selected x86 crabc-libc archive consumed by the
# same-object ABI differential.  Construction remains outside the comparator
# so the compared object and the candidate runtime input stay independently
# identifiable.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    printf 'ERROR: x86 same-object static C ABI differential: %s\n' "$*" >&2
    exit 1
}

require_physical_checkout_work_directory() {
    local path="$1"

    case "$path" in
        "$ROOT_DIR"/.work/*) ;;
        *) return 1 ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] && [ "$(realpath "$path")" = "$path" ]
}

temporary_root="${TMPDIR:-}"
require_physical_checkout_work_directory "$temporary_root" ||
    fail "same-object TMPDIR must be a physical checkout .work directory"

artifact_directory="${CRABC_QUALIFICATION_ARTIFACT_DIR:-}"
comparison_arguments=()
if [ -n "$artifact_directory" ]; then
    # The private admission receipt owns this fresh directory. Retain both the
    # archive-producing Cargo output and comparator products below it so one
    # receipt can bind the exact same workload object, oracle, and candidate.
    require_physical_checkout_work_directory "$artifact_directory" ||
        fail "same-object artifact directory must be a physical checkout .work directory"
    [ -z "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -print -quit)" ] ||
        fail "same-object artifact directory must be empty"
    work_dir="$artifact_directory"
    comparison_arguments=(--artifact-directory "$artifact_directory/comparison")
else
    work_dir="$(mktemp -d "$temporary_root/crabc-x86-64-same-object-static-c-abi-build.XXXXXX")"
    trap 'rm -rf -- "$work_dir"' EXIT
fi
archive="$work_dir/cargo-target/x86_64-unknown-linux-musl/debug/libc.a"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$work_dir/cargo-target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the explicit x86 static libc archive"

bash "$ROOT_DIR/compat/x86_64/run_same_object_static_c_abi_differential.sh" \
    --archive "$archive" \
    "${comparison_arguments[@]}"

if [ -n "$artifact_directory" ]; then
    # The receipt validator snapshots this exact directory after the runtime
    # checks above. Do not follow a fixture symlink or normalize its target.
    find "$artifact_directory" -type d -exec chmod a+rx {} +
    find "$artifact_directory" -type f -exec chmod a+r {} +
fi

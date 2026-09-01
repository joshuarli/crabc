#!/usr/bin/env bash
# Native Linux/x86-64 aggregate evidence for the frozen process.signal ABI.
#
# This gate composes the independently bounded default and opt-in x86 signal
# artifacts.  It neither changes any component's scope nor treats the default
# archive as the complete historical C signal surface: the combined archive
# may add only the two signal.c aliases, four SysV helpers, and psignal pair.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly FEATURES="x86-signal-legacy-aliases x86-signal-sysv-helpers x86-signal-reporting"
readonly EXPECTED_ADDITIONS=(
    __sysv_signal
    bsd_signal
    psiginfo
    psignal
    sighold
    sigignore
    sigrelse
    sigset
)

fail() {
    printf 'ERROR: x86 static libc process.signal aggregate: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

assert_combined_feature_closure() {
    local work_dir="$1"
    local baseline_target="$work_dir/baseline-target"
    local featured_target="$work_dir/featured-target"
    local baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
    local featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
    local baseline_surface="$work_dir/baseline-surface"
    local featured_surface="$work_dir/featured-surface"
    local expected_surface="$work_dir/expected-surface"
    local removed="$work_dir/removed-baseline-symbols"
    local additions="$work_dir/feature-additions"
    local expected_additions="$work_dir/expected-additions"

    CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
        --target x86_64-unknown-linux-musl -- \
        -C relocation-model=static -C code-model=small -C panic=abort
    [ -f "$baseline_archive" ] || fail "cargo did not emit the frozen baseline archive"
    collect_global_surface "$baseline_archive" "$baseline_surface" "$work_dir/baseline-members"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
    if ! cmp -s "$expected_surface" "$baseline_surface"; then
        diff -u "$expected_surface" "$baseline_surface" >&2 || true
        fail "default selected-static C ABI surface drifted"
    fi

    CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
        --features "$FEATURES" --target x86_64-unknown-linux-musl -- \
        -C relocation-model=static -C code-model=small -C panic=abort
    [ -f "$featured_archive" ] || fail "cargo did not emit the combined signal archive"
    collect_global_surface "$featured_archive" "$featured_surface" "$work_dir/featured-members"

    comm -23 "$baseline_surface" "$featured_surface" >"$removed"
    if [ -s "$removed" ]; then
        sed 's/^/missing frozen baseline export: /' "$removed" >&2
        fail "combined signal features remove a default C ABI export"
    fi
    comm -13 "$baseline_surface" "$featured_surface" >"$additions"
    printf '%s\n' "${EXPECTED_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
    if ! cmp -s "$expected_additions" "$additions"; then
        diff -u "$expected_additions" "$additions" >&2 || true
        fail "combined signal features change more than the frozen eight-symbol closure"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm rustup sed sort uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"

# Each component retains its own focused musl differential, header matrix,
# static closure, and deliberate exclusions. Do not replace these calls with
# a broad archive-only check.
for runner in \
    run_libc_sigrtmax.sh \
    run_libc_sigrtmin.sh \
    run_libc_signal_legacy_aliases.sh \
    run_libc_signal_execution.sh \
    run_libc_signal_control.sh \
    run_libc_sigaddset_sigdelset_sigfillset.sh \
    run_libc_signal_altstack.sh \
    run_libc_sigandset_sigorset.sh \
    run_libc_signal_sysv_helpers.sh \
    run_libc_siginterrupt.sh \
    run_libc_sigisemptyset.sh \
    run_libc_sigpause.sh \
    run_libc_sigpending.sh \
    run_libc_signalfd.sh \
    run_libc_readiness_waits.sh \
    run_libc_psignal.sh; do
    bash "$ROOT_DIR/compat/x86_64/$runner"
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-process-signal.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cd "$ROOT_DIR"
assert_combined_feature_closure "$work_dir"

printf 'x86 static crabc-libc process.signal aggregate: PASS\n'

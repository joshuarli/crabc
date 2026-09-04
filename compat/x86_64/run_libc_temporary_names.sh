#!/usr/bin/env bash
# Native Linux/x86-64 opt-in crabc-libc temporary-name evidence.
#
# Pinned musl 1.2.6 first executes the project-header tmpnam/tempnam fixture.
# The candidate then composes the x86-temporary-names object over the already
# verified x86-allocator-string-duplication closure.  This deliberately is a
# mixed-runtime differential: pinned musl retains startup and process support
# outside the staged runtime, but it must not supply a pinned-musl
# temporary-name implementation, strdup/strndup, or allocator object to the
# candidate link.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-temporary-names
readonly BASELINE_FEATURES=x86-allocator-runtime,x86-allocator-string-duplication
readonly TMPDIR_PROBE=/tmp/crabc-temporary-names-must-be-ignored

fail() {
    printf 'ERROR: x86 libc temporary names: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        LC_ALL=C sort -u
}

archive_member_for_demangled_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only --demangle "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        LC_ALL=C sort -u
}

collect_public_callable_surface() {
    local archive_path="$1"
    local output_path="$2"
    local members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '
        $2 ~ /^[TWDVBR]$/ &&
        $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.|__crabc_x86_)/ &&
        $1 != "crabc_x86_64_signal_restorer" &&
        $1 != "__crabc_x86_pthread_clone" { print $1 }
    ' | LC_ALL=C sort -u >"$output_path"
}

assert_feature_delta() {
    local baseline_symbols="$1"
    local featured_symbols="$2"
    local additions="$3"
    local removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "$FEATURE removes a baseline C callable"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'tempnam\ntmpnam\n') "$additions"; then
        diff -u <(printf 'tempnam\ntmpnam\n') "$additions" >&2 || true
        fail "$FEATURE changes more than tmpnam/tempnam"
    fi
}

# Rust can either inline the private suffix helper into tmpnam/tempnam or
# retain it as a separately selected codegen unit. Likewise, inline(always)
# on the generic raw syscall leaf is not a stable archive-codegen guarantee.
# Follow the exact named call when a leaf remains out of line; never let an
# unrelated syscall elsewhere in the final candidate satisfy this evidence.
raw_syscall_helper_symbol() {
    local candidate_path="$1"
    local helper_leaf="$2"
    local -a helper_symbols

    mapfile -t helper_symbols < <(
        nm --defined-only --format=posix "$candidate_path" |
            awk -v helper_leaf="$helper_leaf" \
                '$1 ~ ("raw_syscall8" helper_leaf) && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#helper_symbols[@]}" -eq 1 ] ||
        fail "expected one raw syscall helper for $helper_leaf, found ${#helper_symbols[@]}"
    printf '%s\n' "${helper_symbols[0]}"
}

temporary_name_random_symbol() {
    local candidate_path="$1"
    local -a helper_symbols

    mapfile -t helper_symbols < <(
        nm --defined-only --format=posix "$candidate_path" |
            awk '$1 ~ /temp_name_random.*randomize_suffix/ && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#helper_symbols[@]}" -eq 1 ] ||
        fail "expected one temporary-name randomize_suffix helper, found ${#helper_symbols[@]}"
    printf '%s\n' "${helper_symbols[0]}"
}

temporary_name_absence_symbol() {
    local candidate_path="$1"
    local -a helper_symbols

    mapfile -t helper_symbols < <(
        nm --defined-only --format=posix "$candidate_path" |
            awk '$1 ~ /temporary_names.*pathname_is_absent/ && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#helper_symbols[@]}" -eq 1 ] ||
        fail "expected one temporary-name pathname_is_absent helper, found ${#helper_symbols[@]}"
    printf '%s\n' "${helper_symbols[0]}"
}

assert_named_call() {
    local caller_disassembly="$1"
    local caller_symbol="$2"
    local callee_symbol="$3"

    awk -v callee_symbol="$callee_symbol" '
        index($0, "<" callee_symbol ">") && $0 ~ /call/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$caller_disassembly" ||
        fail "$caller_symbol does not call expected helper $callee_symbol"
}

assert_direct_or_bound_syscall_path() {
    local caller_symbol="$1"
    local syscall_name="$2"
    local syscall_word="$3"
    local helper_leaf="$4"
    local caller_disassembly="$work_dir/${caller_symbol}-${syscall_name}-disassembly"
    local helper_symbol
    local helper_disassembly

    objdump -d --disassemble="$caller_symbol" "$candidate" >"$caller_disassembly"
    if grep -Eq '\$'"${syscall_word}"',%[er]?ax' "$caller_disassembly" && \
        grep -Eq '\<syscall\>' "$caller_disassembly"; then
        return
    fi

    grep -Eq '\$'"${syscall_word}"',%[er]?di' "$caller_disassembly" ||
        fail "$caller_symbol lacks Linux x86-64 $syscall_name"
    helper_symbol="$(raw_syscall_helper_symbol "$candidate" "$helper_leaf")"
    assert_named_call "$caller_disassembly" "$caller_symbol" "$helper_symbol"
    helper_disassembly="$work_dir/${caller_symbol}-${syscall_name}-${helper_leaf}-disassembly"
    objdump -d --disassemble="$helper_symbol" "$candidate" >"$helper_disassembly"
    grep -Eq '\<syscall\>' "$helper_disassembly" ||
        fail "$caller_symbol's $syscall_name helper lacks the Linux syscall instruction"
}

assert_temporary_name_syscall_path() {
    local entry_symbol="$1"
    local syscall_name="$2"
    local syscall_word="$3"
    local helper_leaf="$4"
    local entry_disassembly="$work_dir/${entry_symbol}-temporary-name-disassembly"
    local random_symbol

    objdump -d --disassemble="$entry_symbol" "$candidate" >"$entry_disassembly"
    if grep -Eq '\$'"${syscall_word}"',%[er]?(ax|di)' "$entry_disassembly"; then
        assert_direct_or_bound_syscall_path "$entry_symbol" "$syscall_name" \
            "$syscall_word" "$helper_leaf"
        return
    fi

    random_symbol="$(temporary_name_random_symbol "$candidate")"
    assert_named_call "$entry_disassembly" "$entry_symbol" "$random_symbol"
    assert_direct_or_bound_syscall_path "$random_symbol" "$syscall_name" \
        "$syscall_word" "$helper_leaf"
}

assert_raw_enoent_retry_branch() {
    local symbol="$1"
    local disassembly="$work_dir/${symbol}-enoent-retry-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    # Do not require one branch opcode or a fixed instruction layout. The
    # raw -ENOENT comparison and its nearby conditional branch are the
    # emitted equivalent of musl's "== -ENOENT" success test; every other
    # raw readlink result reaches the bounded retry path.
    awk '
        /\$(0xfffffffffffffffe|0xfffffffe|-0x2|-2),%[er]?ax/ {
            comparison_window = 8
            saw_comparison = 1
            next
        }
        comparison_window > 0 {
            if ($0 ~ /[[:space:]]j(a|b|c|e|g|l|n|o|p|r|s|z)[[:alnum:]]*[[:space:]]/)
                saw_branch = 1
            --comparison_window
        }
        END { exit(saw_comparison && saw_branch ? 0 : 1) }
    ' "$disassembly" ||
        fail "$symbol lacks the raw -ENOENT comparison and retry branch"
}

assert_readlink_retry_path() {
    local entry_symbol="$1"
    local entry_disassembly="$work_dir/${entry_symbol}-readlink-entry-disassembly"
    local absence_symbol
    local absence_disassembly

    objdump -d --disassemble="$entry_symbol" "$candidate" >"$entry_disassembly"
    if grep -Eq '\$0x59,%[er]?(ax|di)' "$entry_disassembly"; then
        assert_direct_or_bound_syscall_path "$entry_symbol" readlink=89 0x59 syscall3
        assert_raw_enoent_retry_branch "$entry_symbol"
        return
    fi

    absence_symbol="$(temporary_name_absence_symbol "$candidate")"
    assert_named_call "$entry_disassembly" "$entry_symbol" "$absence_symbol"
    assert_direct_or_bound_syscall_path "$absence_symbol" readlink=89 0x59 syscall3
    absence_disassembly="$work_dir/${absence_symbol}-enoent-comparison-disassembly"
    objdump -d --disassemble="$absence_symbol" "$candidate" >"$absence_disassembly"
    grep -Eq '\$(0xfffffffffffffffe|0xfffffffe|-0x2|-2),%[er]?ax' \
        "$absence_disassembly" ||
        fail "$absence_symbol lacks the raw -ENOENT comparison"
    awk -v absence_symbol="$absence_symbol" '
        index($0, "<" absence_symbol ">") && $0 ~ /call/ {
            branch_window = 8
            next
        }
        branch_window > 0 {
            if ($0 ~ /[[:space:]]j(a|b|c|e|g|l|n|o|p|r|s|z)[[:alnum:]]*[[:space:]]/)
                saw_branch = 1
            --branch_window
        }
        END { exit(saw_branch ? 0 : 1) }
    ' "$entry_disassembly" ||
        fail "$entry_symbol does not branch on its pathname absence helper result"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in ar awk cargo cmp comm diff env grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_temporary_names_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-temporary-names.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-temporary-names.a"
reference="$work_dir/musl-temporary-names-reference"
candidate="$work_dir/crabc-temporary-names-candidate"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-public-callables"
featured_symbols="$work_dir/featured-public-callables"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
archive_symbols="$work_dir/archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_temporary_names_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stddef.h stdint.h stdio.h stdlib.h sys/prctl.h \
    sys/syscall.h features.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_temporary_names_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC TMPDIR="$TMPDIR_PROBE" "$reference" ||
    fail "pinned-musl temporary-name reference failed"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$BASELINE_FEATURES" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
for archive in "$baseline_archive" "$featured_archive"; do
    [ -f "$archive" ] || fail "cargo did not emit a temporary-name archive"
done

collect_public_callable_surface "$baseline_archive" "$baseline_symbols" \
    "$work_dir/baseline-members"
collect_public_callable_surface "$featured_archive" "$featured_symbols" \
    "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" \
    "$feature_additions" "$feature_removed"

nm -A --defined-only "$baseline_archive" >"$work_dir/baseline-archive-symbols"
if grep -Eq '[[:space:]][TW][[:space:]](tmpnam|tempnam|__crabc_x86_temporary_names_v1)$' \
    "$work_dir/baseline-archive-symbols"; then
    fail "allocator string-duplication baseline unexpectedly owns temporary names"
fi
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in __crabc_x86_temporary_names_v1 tmpnam tempnam strdup strndup \
    __crabc_x86_allocator_string_duplication_v1 \
    __crabc_x86_allocator_runtime_v1 __errno_location; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define $symbol"
done

mapfile -t temporary_name_members < <(
    archive_member_for_symbol "$featured_archive" __crabc_x86_temporary_names_v1
)
mapfile -t tmpnam_members < <(archive_member_for_symbol "$featured_archive" tmpnam)
mapfile -t tempnam_members < <(archive_member_for_symbol "$featured_archive" tempnam)
mapfile -t temp_name_random_members < <(
    archive_member_for_demangled_symbol "$featured_archive" \
        c::x86_64_static_c_abi::temp_name_random::randomize_suffix
)
mapfile -t raw_syscall_members < <(
    archive_member_for_demangled_symbol "$featured_archive" \
        c::x86_64_static_c_abi::raw_syscall::syscall3
)
mapfile -t duplication_members < <(
    archive_member_for_symbol "$featured_archive" \
        __crabc_x86_allocator_string_duplication_v1
)
mapfile -t strdup_members < <(archive_member_for_symbol "$featured_archive" strdup)
mapfile -t strndup_members < <(archive_member_for_symbol "$featured_archive" strndup)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$featured_archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(archive_member_for_symbol "$featured_archive" __errno_location)
mapfile -t memcpy_members < <(archive_member_for_symbol "$featured_archive" memcpy)
mapfile -t memset_members < <(archive_member_for_symbol "$featured_archive" memset)
mapfile -t strlen_members < <(archive_member_for_symbol "$featured_archive" strlen)
mapfile -t backend_members < <(ar t "$featured_archive" | grep -- '-static\.o$')

[ "${#temporary_name_members[@]}" -eq 1 ] ||
    fail "temporary-name witness must have exactly one crate object owner"
[ "${#tmpnam_members[@]}" -eq 1 ] && [ "${#tempnam_members[@]}" -eq 1 ] ||
    fail "each temporary-name entry must have exactly one crate object owner"
[ "${temporary_name_members[0]}" = "${tmpnam_members[0]}" ] && \
    [ "${temporary_name_members[0]}" = "${tempnam_members[0]}" ] ||
    fail "temporary-name witness, tmpnam, and tempnam must share one owner"
[ "${#temp_name_random_members[@]}" -eq 1 ] ||
    fail "temporary-name suffix helper must have exactly one crate object owner"
[ "${#raw_syscall_members[@]}" -eq 1 ] ||
    fail "temporary-name raw readlink helper must have exactly one crate object owner"
[ "${#duplication_members[@]}" -eq 1 ] && [ "${#strdup_members[@]}" -eq 1 ] && \
    [ "${#strndup_members[@]}" -eq 1 ] ||
    fail "allocator string-duplication closure has ambiguous ownership"
[ "${duplication_members[0]}" = "${strdup_members[0]}" ] && \
    [ "${duplication_members[0]}" = "${strndup_members[0]}" ] ||
    fail "strdup/strndup must share their existing allocation-client owner"
[ "${#allocator_members[@]}" -eq 1 ] ||
    fail "allocator wrapper must have exactly one crate object owner"
[ "${#errno_members[@]}" -eq 1 ] ||
    fail "errno must have exactly one crate object owner"
[ "${#memcpy_members[@]}" -eq 1 ] && [ "${#memset_members[@]}" -eq 1 ] ||
    fail "temporary-name byte-copy dependencies must have singular crate ownership"
[ "${memcpy_members[0]}" = "${memset_members[0]}" ] ||
    fail "memcpy and memset must retain their existing common crate owner"
[ "${#strlen_members[@]}" -eq 1 ] ||
    fail "temporary-name string-length dependency must have one crate object owner"
[ "${#backend_members[@]}" -eq 1 ] ||
    fail "allocator backend must have exactly one bundled static object"
for dependency_member in "${temp_name_random_members[0]}" \
    "${raw_syscall_members[0]}" "${duplication_members[0]}" \
    "${allocator_members[0]}" "${errno_members[0]}"; do
    [ "${temporary_name_members[0]}" != "$dependency_member" ] ||
        fail "temporary-name owner unexpectedly shares a closure dependency object"
done

mkdir "$work_dir/selected-members"
(
    cd "$work_dir/selected-members"
    ar x "$featured_archive" "${temporary_name_members[0]}" \
        "${temp_name_random_members[0]}" "${raw_syscall_members[0]}" \
        "${duplication_members[0]}" "${allocator_members[0]}" \
        "${errno_members[0]}" "${memcpy_members[0]}" \
        "${strlen_members[0]}" "${backend_members[0]}"
    ar crs "$selected_archive" "${temporary_name_members[0]}" \
        "${temp_name_random_members[0]}" "${raw_syscall_members[0]}" \
        "${duplication_members[0]}" "${allocator_members[0]}" \
        "${errno_members[0]}" "${memcpy_members[0]}" \
        "${strlen_members[0]}" "${backend_members[0]}"
)

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TEMPORARY_NAMES_CANDIDATE \
    -I"$ROOT_DIR/include" -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -Wl,-Map,"$link_map" \
    compat/x86_64/libc_temporary_names_probe.c "$selected_archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __crabc_x86_temporary_names_v1 tmpnam tempnam strdup strndup \
    malloc free __errno_location; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks temporary-name closure symbol $symbol"
done
for symbol in tmpnam tempnam; do
    awk -v symbol="$symbol" '
        $4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$candidate_symbols" ||
        fail "candidate $symbol is not a strong global function"
done
for member in "${temporary_name_members[0]}" "${raw_syscall_members[0]}" \
    "${duplication_members[0]}" \
    "${allocator_members[0]}" "${errno_members[0]}" "${memcpy_members[0]}" \
    "${strlen_members[0]}" "${backend_members[0]}"; do
    grep -Fq "$selected_archive($member)" "$link_map" ||
        fail "candidate did not select required closure member $member"
done
if grep -Eq 'libc\.a\((tmpnam|tempnam|__randname|strdup|strndup|aligned_alloc|calloc|free|malloc|memalign|posix_memalign|realloc|reallocarray|valloc)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl temporary-name implementation or allocator"
fi
if grep -Eq 'libc\.a\((memcpy|memset|strlen)\.lo\)' "$link_map"; then
    fail "candidate selected a pinned-musl byte-string implementation"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the allocator and errno static TLS image"
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' "$candidate_program_headers" \
    "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi

# Bind each public temporary-name entry to its raw absence probe and the
# shared musl suffix source. The candidate must pass readlink=89,
# clock_gettime=228, and gettid=186 through either its own direct syscall
# instruction or the exact selected raw-syscall helper. The readlink check
# also proves the raw -ENOENT comparison takes the retry decision rather than
# translating another raw failure through errno.
for temporary_name_entry in tmpnam tempnam; do
    assert_readlink_retry_path "$temporary_name_entry"
    assert_temporary_name_syscall_path "$temporary_name_entry" clock_gettime=228 0xe4 syscall2
    assert_temporary_name_syscall_path "$temporary_name_entry" gettid=186 0xba syscall0
done

env -i LC_ALL=C TZ=UTC TMPDIR="$TMPDIR_PROBE" "$candidate" ||
    fail "crabc temporary-name candidate failed"

printf 'x86 libc temporary names: PASS\n'

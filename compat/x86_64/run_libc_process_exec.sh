#!/usr/bin/env bash
# Native Linux/x86-64 opt-in process-image replacement evidence.
#
# Pinned musl 1.2.6 is the behavior oracle for the public declarations and
# normal exec-family behavior. The featured candidate is deliberately a
# mixed-runtime static executable: pinned musl retains CRT/startup and every
# process facility outside this small slice, while extracted crabc objects own
# each selected exec entry. This is ordinary archive extraction without --gc-sections,
# not a `-nostdlib -static` freestanding construction that
# could hide an accidental dependency behind a custom start object.
#
# The audited archive deliberately pins `-C lto=off -C codegen-units=256`.
# The workspace release profile normally coalesces codegen more aggressively;
# this gate proves the isolated candidate/member topology rather than making
# an unsupported claim about arbitrary release feature builds.
# Its link-map assertions name each environment closure, including the narrow
# default environment artifact, and its child fixture carries stack-spilled
# variadic words past the AMD64 register argument area.
# Its `check_fexecve_enosys` child installs seccomp and proves the Linux-5.10
# no-procfd exception: `fexecve` exposes `ENOSYS` from direct execveat with
# `AT_EMPTY_PATH`, while the pinned-musl reference separately takes procfd.
# The child probe covers PATH empty-component slash behavior and its NAME_MAX
# bound, reports EACCES precedence, and proves ENOEXEC is terminal (no shell
# fallback).
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-process-exec
readonly DEFAULT_PATH='/usr/local/bin:/bin:/usr/bin'

fail() {
    printf 'ERROR: x86 libc process exec: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A -g --defined-only "$archive_path" |
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

archive_member_for_fragment() {
    local archive_path="$1"
    local fragment="$2"

    nm -A --defined-only "$archive_path" |
        awk -v fragment="$fragment" '
            $NF ~ fragment {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        LC_ALL=C sort -u
}

require_one_member() {
    local label="$1"
    shift
    local -a members=("$@")

    [ "${#members[@]}" -eq 1 ] ||
        fail "$label must have one archive member owner, found ${#members[@]}"
    printf '%s\n' "${members[0]}"
}

collect_public_callable_surface() {
    local archive_path="$1"
    local output_path="$2"
    local members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '
        $2 ~ /^[TWDVBRW]$/ &&
        $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.|__crabc_x86_)/ { print $1 }
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
        fail "$FEATURE removes a default static callable"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf '%s\n' \
        __execvpe execl execle execlp execv execve execvp execvpe fexecve | LC_ALL=C sort) \
        "$additions"; then
        diff -u <(printf '%s\n' \
            __execvpe execl execle execlp execv execve execvp execvpe fexecve | LC_ALL=C sort) \
            "$additions" >&2 || true
        fail "$FEATURE changes more than the selected exec callable surface"
    fi
}

map_mentions_member() {
    local map_path="$1"
    local member="$2"

    grep -Fq "$archive($member)" "$map_path"
}

assert_map_selects() {
    local map_path="$1"
    local label="$2"
    local member="$3"

    map_mentions_member "$map_path" "$member" ||
        fail "$label ordinary archive extraction did not select $member"
}

assert_map_omits() {
    local map_path="$1"
    local label="$2"
    local member="$3"

    if map_mentions_member "$map_path" "$member"; then
        fail "$label ordinary archive extraction unexpectedly selected $member"
    fi
}

# `ld -r -u` preserves normal static archive member selection while stopping
# before CRT resolution. It deliberately has no --gc-sections option, so its
# map is direct evidence for the ordinary consumer closure below.
extract_archive_closure() {
    local label="$1"
    shift
    local map_path="$work_dir/$label.archive.map"
    local object_path="$work_dir/$label.archive.o"
    local -a linker_args=(-r -Map="$map_path" -o "$object_path")
    local symbol

    for symbol in "$@"; do
        linker_args+=(-u "$symbol")
    done
    ld "${linker_args[@]}" "$archive"
    [ -s "$object_path" ] || fail "$label archive extraction emitted no object"
    printf '%s\n' "$object_path"
}

assert_direct_member_undefined_closure() {
    local member_path="$1"
    local undefined_path="$2"

    nm --undefined-only --format=posix "$member_path" >"$undefined_path"
    # The raw syscall generic inlines into this direct member under the
    # audited release settings; its sole external closure is the selected
    # errno TLS object, not a public __errno_location call.
    grep -Eq '(errno5ERRNO|__errno_location)' "$undefined_path" ||
        fail "direct exec member lost its selected errno dependency"
    if grep -Eq '(__environ|getenv|process_exec_(env|path|variadic)|SYS_MMAP)' \
        "$undefined_path"; then
        fail "direct exec member acquired environment, PATH, variadic, or mmap closure"
    fi
}

raw_syscall_helper_symbol() {
    local candidate_path="$1"
    local helper_leaf="$2"
    local -a symbols

    mapfile -t symbols < <(
        nm --defined-only --format=posix "$candidate_path" |
            awk -v helper_leaf="$helper_leaf" \
                '$1 ~ ("raw_syscall8" helper_leaf) && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#symbols[@]}" -eq 1 ] ||
        fail "expected one selected raw syscall helper for $helper_leaf"
    printf '%s\n' "${symbols[0]}"
}

execve_result_symbol() {
    local candidate_path="$1"
    local -a symbols

    mapfile -t symbols < <(
        nm --defined-only --format=posix "$candidate_path" |
            awk '$1 ~ /process_exec.*execve_result/ && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#symbols[@]}" -eq 1 ] ||
        fail "expected one selected direct execve_result helper"
    printf '%s\n' "${symbols[0]}"
}

assert_named_transfer() {
    local disassembly="$1"
    local caller="$2"
    local callee="$3"

    awk -v callee="$callee" '
        index($0, "<" callee ">") && $0 ~ /(call|jmp)/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$disassembly" || fail "$caller does not transfer to $callee"
}

assert_direct_or_bound_syscall_path() {
    local executable="$1"
    local entry_symbol="$2"
    local syscall_name="$3"
    local syscall_word="$4"
    local helper_leaf="$5"
    local entry_disassembly="$work_dir/${entry_symbol}-${syscall_name}.disassembly"
    local helper_symbol
    local helper_disassembly

    objdump -d --disassemble="$entry_symbol" "$executable" >"$entry_disassembly"
    if grep -Eq '\$'"${syscall_word}"',%[er]?ax' "$entry_disassembly" && \
        grep -Eq '\<syscall\>' "$entry_disassembly"; then
        return
    fi
    grep -Eq '\$'"${syscall_word}"',%[er]?di' "$entry_disassembly" ||
        fail "$entry_symbol lacks Linux x86-64 $syscall_name"
    helper_symbol="$(raw_syscall_helper_symbol "$executable" "$helper_leaf")"
    assert_named_transfer "$entry_disassembly" "$entry_symbol" "$helper_symbol"
    helper_disassembly="$work_dir/${entry_symbol}-${syscall_name}-${helper_leaf}.disassembly"
    objdump -d --disassemble="$helper_symbol" "$executable" >"$helper_disassembly"
    grep -Eq '\<syscall\>' "$helper_disassembly" ||
        fail "$entry_symbol's selected $syscall_name helper lacks syscall"
}

assert_execve_syscall_path() {
    local executable="$1"
    local entry_disassembly="$work_dir/execve-entry.disassembly"
    local result_symbol

    objdump -d --disassemble=execve "$executable" >"$entry_disassembly"
    if grep -Eq '\$0x3b,%[er]?(ax|di)' "$entry_disassembly"; then
        assert_direct_or_bound_syscall_path "$executable" execve execve=59 0x3b syscall3
        return
    fi
    result_symbol="$(execve_result_symbol "$executable")"
    assert_named_transfer "$entry_disassembly" execve "$result_symbol"
    assert_direct_or_bound_syscall_path "$executable" "$result_symbol" execve=59 \
        0x3b syscall3
}

assert_fexecve_syscall_path() {
    local executable="$1"
    local disassembly="$work_dir/fexecve-entry.disassembly"

    assert_direct_or_bound_syscall_path "$executable" fexecve execveat=322 0x142 syscall5
    objdump -d --disassemble=fexecve "$executable" >"$disassembly"
    grep -Eq '\$0x1000' "$disassembly" ||
        fail "fexecve does not materialize AT_EMPTY_PATH=0x1000"
}

symbol_value() {
    local symbols_path="$1"
    local symbol="$2"

    awk -v symbol="$symbol" '$7 != "UND" && $8 == symbol { print $2; exit }' \
        "$symbols_path"
}

assert_function_binding() {
    local symbols_path="$1"
    local symbol="$2"
    local binding="$3"

    awk -v symbol="$symbol" -v binding="$binding" '
        $4 == "FUNC" && $5 == binding && $7 != "UND" && $8 == symbol { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$symbols_path" || fail "$symbol is not a $binding function"
}

assert_default_path_rodata() {
    local executable="$1"
    local strings_path="$work_dir/default-path-rodata"

    # readelf's string dump reports NUL-terminated printable sequences. This
    # binds exact DEFAULT_PATH rodata, not an ambient-path runtime success.
    readelf --string-dump=.rodata "$executable" >"$strings_path"
    grep -Fq "$DEFAULT_PATH" "$strings_path" ||
        fail "candidate lacks NUL-terminated DEFAULT_PATH rodata"
}

assert_static_candidate_shape() {
    local executable="$1"
    local label="$2"
    local symbols_path="$work_dir/$label.symbols"
    local headers_path="$work_dir/$label.program-headers"
    local dynamic_path="$work_dir/$label.dynamic"
    local relocations_path="$work_dir/$label.relocations"

    readelf --symbols --wide "$executable" >"$symbols_path"
    readelf --program-headers --wide "$executable" >"$headers_path"
    readelf --dynamic --wide "$executable" >"$dynamic_path" || true
    readelf --relocs --wide "$executable" >"$relocations_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "$label has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
        "$headers_path" "$dynamic_path"; then
        fail "$label is not a static executable"
    fi
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocations_path" "$symbols_path"; then
        fail "$label retains a dynamic TLS model"
    fi
    if grep -Eqi 'glibc|ld-linux|libc\.so\.6' "$headers_path" "$dynamic_path"; then
        fail "$label selected glibc"
    fi
}

prepare_runtime_tree() {
    local executable="$1"
    local runtime_dir="$2"

    mkdir -p "$runtime_dir/process-exec-eacces" \
        "$runtime_dir/process-exec-enoent" \
        "$runtime_dir/process-exec-enoexec-dir"
    ln "$executable" "$runtime_dir/process-exec-fixture"
    ln "$runtime_dir/process-exec-fixture" "$runtime_dir/process-exec-helper"
    printf 'exit 77\n' >"$runtime_dir/process-exec-enoexec"
    chmod 755 "$runtime_dir/process-exec-enoexec"
    : >"$runtime_dir/process-exec-enotdir"
    printf 'not executable\n' \
        >"$runtime_dir/process-exec-eacces/process-exec-eacces-candidate"
    chmod 644 "$runtime_dir/process-exec-eacces/process-exec-eacces-candidate"
    printf 'exit 76\n' \
        >"$runtime_dir/process-exec-enoexec-dir/process-exec-eacces-candidate"
    chmod 755 "$runtime_dir/process-exec-enoexec-dir/process-exec-eacces-candidate"
}

run_runtime_tree() {
    local runtime_dir="$1"
    local label="$2"

    (
        cd "$runtime_dir"
        env -i LC_ALL=C PATH=. ./process-exec-fixture
    ) || fail "$label process-exec fixture failed"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in ar awk cargo chmod cmp comm cp diff env grep ld ln mkdir mktemp nm \
    objdump readelf rustup sort strings; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_process_exec_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-process-exec.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/release/libc.a"
archive="$featured_target/x86_64-unknown-linux-musl/release/libc.a"
selected_archive="$work_dir/libcrabc-process-exec.a"
reference="$work_dir/musl-process-exec-reference"
candidate="$work_dir/crabc-process-exec-candidate"
override_candidate="$work_dir/crabc-process-exec-strong-override"
baseline_symbols="$work_dir/baseline-public-callables"
featured_symbols="$work_dir/featured-public-callables"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
header_trace="$work_dir/header-trace"
candidate_map="$work_dir/candidate.map"
override_map="$work_dir/strong-override.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_process_exec_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stdint.h sys/prctl.h sys/syscall.h unistd.h \
    features.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_process_exec_probe.c -o "$reference"
prepare_runtime_tree "$reference" "$work_dir/reference-runtime"
run_runtime_tree "$work_dir/reference-runtime" "pinned-musl reference"

# Keep the feature topology observable despite the workspace release profile.
for target_dir in "$baseline_target" "$featured_target"; do
    feature_args=()
    if [ "$target_dir" = "$featured_target" ]; then
        feature_args=(--features "$FEATURE")
    fi
    CARGO_TARGET_DIR="$target_dir" cargo rustc --release --locked -p crabc-libc --lib \
        "${feature_args[@]}" --target x86_64-unknown-linux-musl -- \
        -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
        -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=static -C code-model=small -C panic=abort \
        -C link-dead-code=no -C lto=off -C codegen-units=256
done
[ -f "$baseline_archive" ] || fail "cargo did not emit baseline archive"
[ -f "$archive" ] || fail "cargo did not emit $FEATURE archive"

collect_public_callable_surface "$baseline_archive" "$baseline_symbols" \
    "$work_dir/baseline-members"
collect_public_callable_surface "$archive" "$featured_symbols" \
    "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" \
    "$feature_additions" "$feature_removed"

mapfile -t direct_members < <(archive_member_for_symbol "$archive" execve)
direct_member="$(require_one_member 'execve' "${direct_members[@]}")"
mapfile -t fexecve_members < <(archive_member_for_symbol "$archive" fexecve)
fexecve_member="$(require_one_member 'fexecve' "${fexecve_members[@]}")"
mapfile -t env_wrapper_members < <(archive_member_for_symbol "$archive" execv)
env_wrapper_member="$(require_one_member 'execv' "${env_wrapper_members[@]}")"
mapfile -t path_members < <(archive_member_for_symbol "$archive" execvp)
path_member="$(require_one_member 'execvp' "${path_members[@]}")"
mapfile -t internal_path_members < <(archive_member_for_symbol "$archive" __execvpe)
internal_path_member="$(require_one_member '__execvpe' "${internal_path_members[@]}")"
mapfile -t weak_path_members < <(archive_member_for_symbol "$archive" execvpe)
weak_path_member="$(require_one_member 'weak execvpe' "${weak_path_members[@]}")"
mapfile -t execl_members < <(archive_member_for_symbol "$archive" execl)
execl_member="$(require_one_member 'execl' "${execl_members[@]}")"
mapfile -t execle_members < <(archive_member_for_symbol "$archive" execle)
execle_member="$(require_one_member 'execle' "${execle_members[@]}")"
mapfile -t execlp_members < <(archive_member_for_symbol "$archive" execlp)
execlp_member="$(require_one_member 'execlp' "${execlp_members[@]}")"
mapfile -t variadic_members < <(
    archive_member_for_fragment "$archive" 'process_exec_variadic.*variadic_argv'
)
variadic_member="$(require_one_member 'variadic argv helper' "${variadic_members[@]}")"
mapfile -t environment_members < <(archive_member_for_symbol "$archive" __environ)
environment_member="$(require_one_member 'default environment' "${environment_members[@]}")"
mapfile -t getenv_members < <(archive_member_for_symbol "$archive" getenv)
getenv_member="$(require_one_member 'getenv' "${getenv_members[@]}")"
mapfile -t errno_members < <(archive_member_for_symbol "$archive" __errno_location)
errno_member="$(require_one_member 'errno' "${errno_members[@]}")"
mapfile -t raw3_members < <(
    archive_member_for_fragment "$archive" 'raw_syscall8syscall3'
)
raw3_member="$(require_one_member 'raw syscall3' "${raw3_members[@]}")"
mapfile -t raw5_members < <(
    archive_member_for_fragment "$archive" 'raw_syscall8syscall5'
)
raw5_member="$(require_one_member 'raw syscall5' "${raw5_members[@]}")"

[ "$direct_member" = "$fexecve_member" ] ||
    fail "execve and fexecve must share direct process_exec"
[ "$path_member" = "$internal_path_member" ] && \
    [ "$path_member" = "$weak_path_member" ] ||
    fail "execvp, __execvpe, and weak execvpe must share process_exec_path"
[ "$environment_member" = "$getenv_member" ] ||
    fail "default environment global and getenv must share one owner"
[ "$raw3_member" = "$raw5_member" ] ||
    fail "direct exec raw syscall helpers must share one owner"
for separate_member in "$env_wrapper_member" "$path_member" "$variadic_member" \
    "$execl_member" "$execle_member" "$execlp_member" "$environment_member" \
    "$errno_member" "$raw3_member"; do
    [ "$direct_member" != "$separate_member" ] ||
        fail "direct process_exec unexpectedly merged with $separate_member"
done
for pair in \
    "$env_wrapper_member:$path_member" \
    "$env_wrapper_member:$variadic_member" \
    "$path_member:$variadic_member" \
    "$execl_member:$execle_member" \
    "$execl_member:$execlp_member" \
    "$execle_member:$execlp_member"; do
    [ "${pair%%:*}" != "${pair#*:}" ] ||
        fail "process-exec source modules unexpectedly share one archive member"
done

mkdir "$work_dir/direct-member"
(
    cd "$work_dir/direct-member"
    ar x "$archive" "$direct_member"
)
assert_direct_member_undefined_closure \
    "$work_dir/direct-member/$direct_member" "$work_dir/direct-member.undefined"

execve_closure="$(extract_archive_closure execve-only execve)"
fexecve_closure="$(extract_archive_closure fexecve-only fexecve)"
execv_closure="$(extract_archive_closure execv-only execv)"
execvp_closure="$(extract_archive_closure execvp-only execvp)"
execvpe_closure="$(extract_archive_closure execvpe-only execvpe)"
execl_closure="$(extract_archive_closure execl-only execl)"
execle_closure="$(extract_archive_closure execle-only execle)"
execlp_closure="$(extract_archive_closure execlp-only execlp)"
full_closure="$(extract_archive_closure process-exec-full \
    execl execle execlp execv execve execvp execvpe fexecve)"

for label in execve-only fexecve-only; do
    map_path="$work_dir/$label.archive.map"
    assert_map_selects "$map_path" "$label" "$direct_member"
    for excluded_member in "$env_wrapper_member" "$path_member" "$variadic_member" \
        "$execl_member" "$execle_member" "$execlp_member" "$environment_member"; do
        assert_map_omits "$map_path" "$label" "$excluded_member"
    done
done

map_path="$work_dir/execv-only.archive.map"
assert_map_selects "$map_path" execv-only "$direct_member"
assert_map_selects "$map_path" execv-only "$env_wrapper_member"
assert_map_selects "$map_path" execv-only "$environment_member"
for excluded_member in "$path_member" "$variadic_member" "$execl_member" \
    "$execle_member" "$execlp_member"; do
    assert_map_omits "$map_path" execv-only "$excluded_member"
done

for label in execvp-only execvpe-only; do
    map_path="$work_dir/$label.archive.map"
    assert_map_selects "$map_path" "$label" "$direct_member"
    assert_map_selects "$map_path" "$label" "$path_member"
    assert_map_selects "$map_path" "$label" "$environment_member"
    for excluded_member in "$env_wrapper_member" "$variadic_member" "$execl_member" \
        "$execle_member" "$execlp_member"; do
        assert_map_omits "$map_path" "$label" "$excluded_member"
    done
done

for label in execl-only execle-only execlp-only; do
    map_path="$work_dir/$label.archive.map"
    assert_map_selects "$map_path" "$label" "$direct_member"
    assert_map_selects "$map_path" "$label" "$variadic_member"
done
assert_map_selects "$work_dir/execl-only.archive.map" execl-only "$execl_member"
assert_map_selects "$work_dir/execl-only.archive.map" execl-only "$environment_member"
assert_map_omits "$work_dir/execl-only.archive.map" execl-only "$path_member"
assert_map_omits "$work_dir/execl-only.archive.map" execl-only "$execle_member"
assert_map_omits "$work_dir/execl-only.archive.map" execl-only "$execlp_member"
assert_map_selects "$work_dir/execle-only.archive.map" execle-only "$execle_member"
assert_map_omits "$work_dir/execle-only.archive.map" execle-only "$environment_member"
assert_map_omits "$work_dir/execle-only.archive.map" execle-only "$path_member"
assert_map_selects "$work_dir/execlp-only.archive.map" execlp-only "$execlp_member"
assert_map_selects "$work_dir/execlp-only.archive.map" execlp-only "$path_member"
assert_map_selects "$work_dir/execlp-only.archive.map" execlp-only "$environment_member"

# The default environment is intentionally dependency-free `environment.rs`:
# execv forwards its selected __environ pointer directly, while PATH-searching
# execvp/execvpe use its 1,048,576-entry `getenv` lookup. All three observe
# its bounded mutation contract. This gate claims ordinary finite forwarding,
# not unrestricted musl environment parity.
grep -Fq '1,048,576-entry `getenv` lookup' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/process_exec_env.rs" ||
    fail "process-exec forwarding lost its bounded environment contract"
grep -Fq 'ENVIRONMENT_LOOKUP_LIMIT: usize = 1 << 20' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/environment.rs" ||
    fail "default environment owner lost its 1,048,576-entry lookup limit"
grep -Fq 'ENVIRONMENT_ENTRY_CAPACITY: usize = 128' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/environment.rs" ||
    fail "default environment owner lost its bounded mutation contract"

mkdir "$work_dir/selected-archive"
(
    cd "$work_dir/selected-archive"
    cp "$full_closure" process-exec-closure.o
    ar crs "$selected_archive" process-exec-closure.o
)

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PROCESS_EXEC_EXECVE_ONLY \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" -Wl,-Map,"$work_dir/execve-only.map" \
    compat/x86_64/libc_process_exec_probe.c "$execve_closure" \
    -o "$work_dir/execve-only"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PROCESS_EXEC_FEXECVE_ONLY \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" -Wl,-Map,"$work_dir/fexecve-only.map" \
    compat/x86_64/libc_process_exec_probe.c "$fexecve_closure" \
    -o "$work_dir/fexecve-only"
env -i LC_ALL=C "$work_dir/execve-only" ||
    fail "execve-only ordinary static consumer failed"
env -i LC_ALL=C "$work_dir/fexecve-only" ||
    fail "fexecve-only ordinary static consumer failed"
assert_static_candidate_shape "$work_dir/execve-only" execve-only
assert_static_candidate_shape "$work_dir/fexecve-only" fexecve-only

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PROCESS_EXEC_CANDIDATE \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" -Wl,-Map,"$candidate_map" \
    compat/x86_64/libc_process_exec_probe.c "$selected_archive" -o "$candidate"
assert_static_candidate_shape "$candidate" candidate
readelf --symbols --wide "$candidate" >"$work_dir/candidate.symbols"
for symbol in execl execle execlp execv execve execvp __execvpe execvpe fexecve; do
    grep -Eq "[[:space:]]${symbol}$" "$work_dir/candidate.symbols" ||
        fail "candidate lacks $symbol"
done
for symbol in execl execle execlp execv execve execvp __execvpe fexecve; do
    assert_function_binding "$work_dir/candidate.symbols" "$symbol" GLOBAL
done
assert_function_binding "$work_dir/candidate.symbols" execvpe WEAK
execvpe_value="$(symbol_value "$work_dir/candidate.symbols" execvpe)"
internal_execvpe_value="$(symbol_value "$work_dir/candidate.symbols" __execvpe)"
[ -n "$execvpe_value" ] && [ "$execvpe_value" = "$internal_execvpe_value" ] ||
    fail "weak execvpe is not the same-address __execvpe alias"
grep -Fq "$selected_archive(process-exec-closure.o)" "$candidate_map" ||
    fail "candidate did not use the selected process-exec archive"
if grep -Eq 'libc\.a\((execve|execv|execvp|execvpe|execl|execle|execlp|fexecve)\.lo\)' \
    "$candidate_map"; then
    fail "candidate selected a pinned-musl exec-family implementation"
fi
if strings -a "$full_closure" | grep -Fq '/proc/self/fd'; then
    fail "selected fexecve closure contains a forbidden procfd fallback"
fi
assert_execve_syscall_path "$candidate"
assert_fexecve_syscall_path "$candidate"
assert_default_path_rodata "$candidate"
prepare_runtime_tree "$candidate" "$work_dir/candidate-runtime"
run_runtime_tree "$work_dir/candidate-runtime" "crabc candidate"

# A consumer strong execvpe override replaces only the weak public alias. The
# runtime probe proves execvp continues through strong internal __execvpe.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PROCESS_EXEC_STRONG_OVERRIDE \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" -Wl,-Map,"$override_map" \
    compat/x86_64/libc_process_exec_probe.c "$selected_archive" \
    -o "$override_candidate"
assert_static_candidate_shape "$override_candidate" strong-override
readelf --symbols --wide "$override_candidate" >"$work_dir/strong-override.symbols"
assert_function_binding "$work_dir/strong-override.symbols" execvpe GLOBAL
assert_function_binding "$work_dir/strong-override.symbols" __execvpe GLOBAL
override_execvpe_value="$(symbol_value "$work_dir/strong-override.symbols" execvpe)"
override_internal_value="$(symbol_value "$work_dir/strong-override.symbols" __execvpe)"
[ -n "$override_execvpe_value" ] && \
    [ "$override_execvpe_value" != "$override_internal_value" ] ||
    fail "strong execvpe override did not replace only the public weak alias"
env -i LC_ALL=C PATH=. "$override_candidate" ||
    fail "strong execvpe override or internal execvp route failed"

printf 'x86 libc process exec: PASS\n'

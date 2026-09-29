#!/usr/bin/env bash
# Native Linux/x86-64 private POSIX spawn file-actions lifecycle evidence.
#
# This is deliberately a mixed-runtime differential. The pinned-musl
# reference and the candidate exercise only the caller-owned action-record
# lifecycle, including the list order later consumed by a spawn executor.
# The candidate owns the opt-in action provider plus the selected
# allocator wrapper, errno owner, and bundled mimalloc object; pinned musl
# supplies startup and the process primitives still outside the staged x86
# runtime. No spawn execution path or pinned-musl action/allocator object is
# selected.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 static libc spawn file-actions: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
archive_member_for_symbol() {
    local archive_path="$1" symbol="$2"
    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '$NF == symbol { member=$1; sub(/^.*\.a:/, "", member); sub(/:.*/, "", member); print member }' |
        sort -u
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"

bash "$ROOT_DIR/compat/x86_64/run_posix_spawn_file_actions_header_abi.sh"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/libc-posix-spawn-file-actions.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
report_dir="$ROOT_DIR/.work/x86_64/reports/libc-posix-spawn-file-actions"
mkdir -p "$report_dir"
reference_stdout="$report_dir/reference.stdout"
reference_stderr="$report_dir/reference.stderr"
reference_status="$report_dir/reference.status"
candidate_stdout="$report_dir/candidate.stdout"
candidate_stderr="$report_dir/candidate.stderr"
candidate_status="$report_dir/candidate.status"
expected_stdout="$report_dir/expected.stdout"
rm -f "$reference_stdout" "$reference_stderr" "$reference_status" \
    "$candidate_stdout" "$candidate_stderr" "$candidate_status"
cat >"$expected_stdout" <<'EOF'
action 2 3 11 0 0 -
action 1 3 0 0 0 -
action 3 3 0 577 384 /tmp/crabc-spawn-first
action 2 1 3 0 0 -
action 1 3 0 0 0 -
action 3 3 0 0 0 /tmp/crabc-spawn-second
action 2 2 3 0 0 -
EOF
target_dir="$work_dir/cargo-target"
full_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-posix-spawn-file-actions.a"
reference="$work_dir/musl-spawn-file-actions-reference"
candidate="$work_dir/crabc-spawn-file-actions-candidate"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_spawn_file_actions_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference" >"$reference_stdout" 2>"$reference_stderr"; then
    printf '0\n' >"$reference_status"
else
    result=$?
    printf '%s\n' "$result" >"$reference_status"
    fail "pinned-musl reference failed (status $result)"
fi
cmp -s "$expected_stdout" "$reference_stdout" \
    || fail "pinned-musl reference action records differ from expected bytes"
[ ! -s "$reference_stderr" ] || fail "pinned-musl reference wrote stderr"

build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a" \
    --features x86-posix-spawn-file-actions
[ -f "$full_archive" ] || fail "cargo did not emit the feature archive"

mapfile -t action_members < <(
    archive_member_for_symbol "$full_archive" __crabc_x86_posix_spawn_file_actions_v1
)
mapfile -t init_members < <(
    archive_member_for_symbol "$full_archive" posix_spawn_file_actions_init
)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$full_archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(
    archive_member_for_symbol "$full_archive" __errno_location
)
mapfile -t backend_members < <(ar t "$full_archive" | grep -- '-static\.o$')
[ "${#action_members[@]}" -eq 1 ] || fail "provider witness has ambiguous ownership"
[ "${#init_members[@]}" -eq 1 ] || fail "file-actions init has ambiguous ownership"
[ "${#allocator_members[@]}" -eq 1 ] || fail "allocator wrapper has ambiguous ownership"
[ "${#errno_members[@]}" -eq 1 ] || fail "errno has ambiguous ownership"
[ "${#backend_members[@]}" -eq 1 ] || fail "allocator backend has ambiguous ownership"
[ "${action_members[0]}" != "${init_members[0]}" ] \
    || fail "action provider and init unexpectedly share one object"
[ "${action_members[0]}" != "${allocator_members[0]}" ] \
    || fail "action provider and allocator unexpectedly share one object"
[ "${action_members[0]}" != "${errno_members[0]}" ] \
    || fail "action provider and errno unexpectedly share one object"
[ "${init_members[0]}" != "${allocator_members[0]}" ] \
    || fail "file-actions init and allocator unexpectedly share one object"
[ "${init_members[0]}" != "${errno_members[0]}" ] \
    || fail "file-actions init and errno unexpectedly share one object"
[ "${allocator_members[0]}" != "${errno_members[0]}" ] \
    || fail "allocator and errno unexpectedly share one object"

mkdir "$work_dir/selected-members"
(
    cd "$work_dir/selected-members"
    ar x "$full_archive" "${action_members[0]}" "${init_members[0]}" \
        "${allocator_members[0]}" "${errno_members[0]}" "${backend_members[0]}"
    ar crs "$selected_archive" "${action_members[0]}" "${init_members[0]}" \
        "${allocator_members[0]}" "${errno_members[0]}" "${backend_members[0]}"
)
mapfile -t selected_members < <(ar t "$selected_archive")
if [ "${selected_members[*]}" != "${action_members[0]} ${init_members[0]} ${allocator_members[0]} ${errno_members[0]} ${backend_members[0]}" ]; then
    fail "selected archive member set drifted during extraction"
fi

mapfile -t action_symbols < <(
    nm -g --defined-only --format=posix \
        "$work_dir/selected-members/${action_members[0]}" |
        awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_action_symbols=(
    __crabc_x86_posix_spawn_file_actions_v1
    posix_spawn_file_actions_addchdir_np
    posix_spawn_file_actions_addclose
    posix_spawn_file_actions_adddup2
    posix_spawn_file_actions_addfchdir_np
    posix_spawn_file_actions_addopen
    posix_spawn_file_actions_destroy
)
if [ "${action_symbols[*]}" != "${expected_action_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_action_symbols[*]}" \
        "${action_symbols[*]}" >&2
    fail "provider object export surface drifted"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -I"$ROOT_DIR/include" -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -Wl,-Map,"$link_map" \
    compat/x86_64/libc_posix_spawn_file_actions_probe.c "$selected_archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in posix_spawn_file_actions_init posix_spawn_file_actions_destroy \
    posix_spawn_file_actions_addclose posix_spawn_file_actions_adddup2 \
    posix_spawn_file_actions_addopen posix_spawn_file_actions_addchdir_np \
    posix_spawn_file_actions_addfchdir_np; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks $symbol"
done
if grep -Eq 'libc\.a\((aligned_alloc|calloc|free|libc_calloc|lite_malloc|malloc|malloc_usable_size|memalign|posix_memalign|realloc|reallocarray|replaced|valloc)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl allocator implementation"
fi
if grep -Eq 'libc\.a\(posix_spawn_file_actions_(init|addclose|adddup2|addopen|addchdir|addfchdir|destroy)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl file-actions implementation"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep . >/dev/null; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks the selected allocator and errno static TLS image"
if grep -Eq 'crabc_core|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if grep -Eq '[[:space:]](posix_spawn|posix_spawnp|fork|vfork|clone|execve|posix_spawnattr_setflags)$' \
    "$candidate_symbols"; then
    fail "candidate leaked an execution or separately owned spawn entry"
fi
if env -i LC_ALL=C TZ=UTC "$candidate" >"$candidate_stdout" 2>"$candidate_stderr"; then
    printf '0\n' >"$candidate_status"
else
    result=$?
    printf '%s\n' "$result" >"$candidate_status"
    fail "mixed-runtime candidate failed (status $result)"
fi
cmp -s "$expected_stdout" "$candidate_stdout" \
    || fail "mixed-runtime candidate action records differ from expected bytes"
cmp -s "$reference_stdout" "$candidate_stdout" \
    || fail "mixed-runtime candidate action records differ from pinned musl"
cmp -s "$reference_stderr" "$candidate_stderr" \
    || fail "mixed-runtime candidate stderr differs from pinned musl"
printf 'x86 static libc spawn file-actions lifecycle: PASS\n'

#!/usr/bin/env bash
# Native Linux/x86-64 private POSIX spawn file-actions lifecycle evidence.
#
# The pinned-musl reference and the freestanding candidate exercise only the
# caller-owned action-record lifecycle.  The candidate links the opt-in
# x86-posix-spawn-file-actions archive, whose six allocating functions compose
# the existing x86 allocator wrapper.  No spawn execution path is selected.
set -euo pipefail
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
for tool in ar awk cargo grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"

bash "$ROOT_DIR/compat/x86_64/run_posix_spawn_file_actions_header_abi.sh"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-spawn-file-actions.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-spawn-file-actions-reference"
candidate="$work_dir/crabc-spawn-file-actions-candidate"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_spawn_file_actions_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" || fail "pinned-musl reference failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-posix-spawn-file-actions \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the feature archive"

mapfile -t action_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_posix_spawn_file_actions_v1
)
[ "${#action_members[@]}" -eq 1 ] || fail "provider witness has ambiguous ownership"
action_member="${action_members[0]}"
mkdir "$work_dir/action-owner"
( cd "$work_dir/action-owner" && ar x "$archive" "$action_member" )
mapfile -t action_symbols < <(
    nm -g --defined-only --format=posix \
        "$work_dir/action-owner/$action_member" |
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
    -DCRABC_POSIX_SPAWN_FILE_ACTIONS_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_posix_spawn_file_actions_probe.c \
    compat/x86_64/libc_posix_spawn_file_actions_start.S "$archive" \
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
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
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
if grep -Eq 'crabc_core|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if grep -Eq '[[:space:]](posix_spawn|posix_spawnp|fork|vfork|clone|execve|posix_spawnattr_setflags)$' \
    "$candidate_symbols"; then
    fail "candidate leaked an execution or separately owned spawn entry"
fi
env -i LC_ALL=C TZ=UTC "$candidate" || fail "freestanding candidate failed"
printf 'x86 static libc spawn file-actions lifecycle: PASS\n'

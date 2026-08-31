#!/usr/bin/env bash
# Private installed Linux/x86-64 static sysroot and pthread/TLS consumer gate.
#
# Two clean builds must produce byte-identical regular-file trees. The actual
# consumer compiles with -nostdinc against only the installed project headers,
# links with direct LLD against only installed Rust CRT/libc/builtins inputs,
# executes the existing initialized/TBSS/high-alignment TLS lifecycle, and
# forces __udivti3 out of the owned helper archive. There is intentionally no
# loader, libc.so, compiler driver, dynamic mode, distribution claim, family
# completion, x86 promotion, or public-support claim here.
set -euo pipefail
export LC_ALL=C
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH \
    COMPILER_PATH GCC_EXEC_PREFIX LD_LIBRARY_PATH LD_PRELOAD || true

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py"
readonly ELF64_PROGRAM_HEADER_SIZE=56
readonly ELF64_PROGRAM_HEADER_COUNT_OFFSET=56
readonly ELF64_PROGRAM_HEADER_OFFSET=32
readonly ELF64_P_FILESZ_OFFSET=32

fail() {
    printf 'ERROR: x86 owned static sysroot: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

write_tree_manifest() {
    local root="$1"
    local destination="$2"

    (
        cd "$root"
        find . -type f -print0 | sort -z | xargs -0 sha256sum
    ) >"$destination"
}

audit_installed_tree() {
    local root="$1"
    local path

    [ -f "$root/share/crabc/manifest.json" ] || fail "installed manifest is missing"
    [ -f "$root/usr/lib/crt1.o" ] || fail "installed crt1.o is missing"
    [ -f "$root/usr/lib/libc.a" ] || fail "installed libc.a is missing"
    [ -f "$root/usr/lib/libcrabc-builtins.a" ] || fail "installed builtins are missing"
    [ ! -e "$root/usr/lib/libc.so" ] || fail "private static slice installed libc.so"
    [ ! -e "$root/lib" ] || fail "private static slice installed a loader directory"
    [ ! -e "$root/bin" ] || fail "private static slice installed an unproved compiler driver"
    while IFS= read -r path; do
        fail "installed tree contains a symlink: ${path#"$root"/}"
    done < <(find "$root" -type l -print)
    python3 - "$root/share/crabc/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest.get("format") != "crabc-x86-64-owned-static-sysroot-v1":
    raise SystemExit("unexpected installed format")
if manifest.get("target") != "x86_64-unknown-linux-musl":
    raise SystemExit("unexpected installed target")
scope = manifest.get("scope", "")
for phrase in ("private-static-pthread-tls-consumer-slice", "not-family-completion", "not-public-support"):
    if phrase not in scope:
        raise SystemExit(f"manifest scope omits {phrase}")
not_selected = set(manifest.get("not_selected", []))
for item in (
    "compiler driver",
    "shared libc",
    "dynamic loader or PT_INTERP",
    "complete compiler-helper closure",
    "sysroot.static-tls family completion",
    "sysroot.owned-artifact family completion",
    "x86-64 promotion or public support",
):
    if item not in not_selected:
        raise SystemExit(f"manifest non-selection omits {item}")
PY
}

audit_header_dependencies() {
    local dependency_file="$1"
    local installed_root="$2"
    local source_file="$3"

    python3 - "$dependency_file" "$installed_root/usr/include" "$source_file" <<'PY'
import sys
from pathlib import Path

dependency_file, include_root, source_file = map(Path, sys.argv[1:])
text = dependency_file.read_text(encoding="utf-8").replace("\\\n", " ")
try:
    dependencies = text.split(":", 1)[1].split()
except IndexError as error:
    raise SystemExit("dependency trace lacks a target separator") from error
include_root = include_root.resolve()
source_file = source_file.resolve()
for dependency in dependencies:
    path = Path(dependency)
    if not path.is_absolute():
        raise SystemExit(f"dependency trace contains a relative input: {dependency}")
    resolved = path.resolve()
    if resolved == source_file:
        continue
    try:
        resolved.relative_to(include_root)
    except ValueError as error:
        raise SystemExit(f"dependency trace contains an ambient input: {resolved}") from error
PY
}

audit_link_trace() {
    local trace="$1"
    local installed_root="$2"
    local consumer_root="$3"
    local line
    local saw_crt1=0
    local saw_crti=0
    local saw_crtn=0
    local saw_libc=0
    local saw_builtins=0
    local saw_builtins_member=0

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            "$installed_root/usr/lib/crt1.o") saw_crt1=1 ;;
            "$installed_root/usr/lib/crti.o") saw_crti=1 ;;
            "$installed_root/usr/lib/crtn.o") saw_crtn=1 ;;
            "$installed_root/usr/lib/libc.a"*) saw_libc=1 ;;
            "$installed_root/usr/lib/libcrabc-builtins.a"*) saw_builtins=1 ;;
            "$consumer_root/probe.o"|"$consumer_root/peer.o"|"$consumer_root/builtins.o") ;;
            *) fail "resolved final-link input escapes the owned set: $line" ;;
        esac
        case "$line" in
            *'libcrabc-builtins.a(crabc-builtins.o)'*) saw_builtins_member=1 ;;
        esac
    done <"$trace"
    [ "$saw_crt1" = 1 ] || fail "final-link trace did not consume installed crt1.o"
    [ "$saw_crti" = 1 ] || fail "final-link trace did not consume installed crti.o"
    [ "$saw_crtn" = 1 ] || fail "final-link trace did not consume installed crtn.o"
    [ "$saw_libc" = 1 ] || fail "final-link trace did not consume installed libc.a"
    [ "$saw_builtins" = 1 ] || fail "final-link trace did not consume installed builtins archive"
    [ "$saw_builtins_member" = 1 ] || fail "final-link trace did not extract owned crabc-builtins.o"
}

assert_final_static_executable() {
    local candidate="$1"
    local file_header="$2"
    local program_headers="$3"
    local dynamic="$4"
    local symbols="$5"
    local relocations="$6"
    local tls_count tls_filesz tls_memsz tls_alignment unresolved

    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' "$file_header" ||
        fail "candidate is not EM_X86_64"
    grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$file_header" ||
        fail "candidate is not ET_EXEC"
    if grep -Eq 'Requesting program interpreter|INTERP' "$program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$dynamic"; then
        fail "candidate selected an interpreter, dynamic dependency, or PLT"
    fi
    awk '$1 == "GNU_RELRO" { count += 1 } END { exit count != 1 }' "$program_headers" ||
        fail "candidate must have exactly one GNU_RELRO segment"
    awk '$1 == "GNU_STACK" { count += 1; if ($7 ~ /E/) executable = 1 }
        END { exit count != 1 || executable }' "$program_headers" ||
        fail "candidate must have one non-executable GNU_STACK segment"
    tls_count="$(awk '$1 == "TLS" { count += 1 } END { print count + 0 }' "$program_headers")"
    [ "$tls_count" = 1 ] || fail "candidate must have exactly one PT_TLS segment"
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate PT_TLS line is not parseable"
    if (( tls_filesz == 0 || tls_memsz <= tls_filesz )); then
        fail "candidate TLS lacks initialized and TBSS content"
    fi
    if (( tls_alignment < 4096 || (tls_alignment & (tls_alignment - 1)) != 0 )); then
        fail "candidate TLS lost the fixture's 4096-byte alignment"
    fi
    unresolved="$(awk '$7 == "UND" && NF >= 8 { print }' "$symbols")"
    [ -z "$unresolved" ] || fail "candidate retains unresolved symbols: $unresolved"
    grep -Eq '[[:space:]]__udivti3$' "$symbols" || fail "candidate lacks the owned __udivti3 helper"
    if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)' \
        "$relocations" "$symbols"; then
        fail "candidate retains a dynamic relocation or dynamic TLS form"
    fi
    [ -x "$candidate" ] || chmod 755 "$candidate"
}

expect_bootstrap_rejection() {
    local malformed="$1"
    local status

    if "$malformed" >/dev/null 2>&1; then
        fail "malformed PT_TLS candidate unexpectedly completed"
    else
        status=$?
    fi
    [ "$status" = 127 ] || fail "malformed PT_TLS candidate exited $status, not 127"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in ar awk cmp cp dd env find gcc grep nm objdump od python3 readelf rustup sha256sum sort tr xargs; do
    require_tool "$tool"
done
[ -f "$BUILDER" ] || fail "missing x86 owned-sysroot builder"
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_root="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
    link_editor="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    [ -x "$link_editor" ] || fail "requires ld.lld"
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
python3 "$ROOT_DIR/scripts/tests/test_build_x86_64_owned_sysroot.py"

work_dir="$(mktemp -d /tmp/crabc-x86-64-owned-static-sysroot.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
primary="$work_dir/primary"
reproduction="$work_dir/reproduction"
python3 "$BUILDER" --output "$primary" >"$work_dir/primary-build.json"
python3 "$BUILDER" --output "$reproduction" >"$work_dir/reproduction-build.json"
audit_installed_tree "$primary"
audit_installed_tree "$reproduction"
write_tree_manifest "$primary" "$work_dir/primary-tree.sha256"
write_tree_manifest "$reproduction" "$work_dir/reproduction-tree.sha256"
cmp "$work_dir/primary-tree.sha256" "$work_dir/reproduction-tree.sha256" ||
    fail "two clean installed trees are not byte-identical"

consumer="$work_dir/consumer"
mkdir "$consumer"
probe_object="$consumer/probe.o"
peer_object="$consumer/peer.o"
builtins_object="$consumer/builtins.o"
dependency_file="$consumer/probe.d"
peer_dependency_file="$consumer/peer.d"
builtins_dependency_file="$consumer/builtins.d"
candidate="$consumer/owned-static-tls"
trace="$consumer/link.trace"
map="$consumer/link.map"
forged_trace="$consumer/forged.trace"
forged_dependency="$consumer/forged.d"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_MUSL_REFERENCE \
    -pthread -fno-builtin -fno-stack-protector -ftls-model=local-exec \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c" \
    -o "$consumer/reference"
reference_output="$(env -i "$consumer/reference")" || fail "pinned-musl reference failed"
[ "$reference_output" = PIMBCAF ] || fail "pinned-musl reference output drifted: $reference_output"

common_compile=(
    gcc -std=c11 -D_GNU_SOURCE -fno-pie -ffreestanding -fno-builtin
    -fno-stack-protector -ftls-model=local-exec -nostdinc
    -isystem "$primary/usr/include"
)
"${common_compile[@]}" -DCRABC_CRT_STATIC_TLS_CANDIDATE -MD -MF "$dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" -o "$probe_object"
"${common_compile[@]}" -MD -MF "$peer_dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c" -o "$peer_object"
"${common_compile[@]}" -MD -MF "$builtins_dependency_file" \
    -c "$ROOT_DIR/compat/x86_64/owned_static_sysroot_builtins.c" -o "$builtins_object"
audit_header_dependencies "$dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c"
audit_header_dependencies "$peer_dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_peer.c"
audit_header_dependencies "$builtins_dependency_file" "$primary" \
    "$ROOT_DIR/compat/x86_64/owned_static_sysroot_builtins.c"
grep -Fq "$primary/usr/include/errno.h" "$dependency_file" ||
    fail "consumer dependency trace did not resolve installed errno.h"
grep -Fq "$primary/usr/include/pthread.h" "$dependency_file" ||
    fail "consumer dependency trace did not resolve installed pthread.h"
printf '%s: %s %s %s\n' "$probe_object" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c" \
    "$primary/usr/include/errno.h" /usr/include/stdint.h >"$forged_dependency"
if (audit_header_dependencies "$forged_dependency" "$primary" \
    "$ROOT_DIR/compat/x86_64/libc_crt_static_tls_probe.c") >/dev/null 2>&1; then
    fail "header audit admitted an ambient target header"
fi
nm -u "$builtins_object" | grep -Eq '[[:space:]]U[[:space:]]+__udivti3$' ||
    fail "compiler-helper consumer did not retain an undefined __udivti3 boundary"

if "$link_editor" -static --no-dynamic-linker --no-undefined -e _start \
    "$primary/usr/lib/crt1.o" "$primary/usr/lib/crti.o" \
    "$probe_object" "$peer_object" "$builtins_object" \
    "$primary/usr/lib/libc.a" "$primary/usr/lib/crtn.o" \
    -o "$consumer/without-builtins" >"$consumer/without-builtins.stdout" \
    2>"$consumer/without-builtins.stderr"; then
    fail "consumer unexpectedly linked without installed compiler helpers"
fi
grep -Fq '__udivti3' "$consumer/without-builtins.stderr" ||
    fail "missing-builtins link did not fail at the selected helper boundary"

"$link_editor" -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    --trace -Map="$map" \
    "$primary/usr/lib/crt1.o" "$primary/usr/lib/crti.o" \
    "$probe_object" "$peer_object" "$builtins_object" \
    "$primary/usr/lib/libc.a" "$primary/usr/lib/libcrabc-builtins.a" \
    "$primary/usr/lib/crtn.o" -o "$candidate" >"$trace"
audit_link_trace "$trace" "$primary" "$consumer"
for forbidden_input in \
    /usr/lib/crt1.o \
    /opt/musl-x86_64/lib/libc.a \
    /usr/lib/gcc/x86_64-linux-gnu/libgcc.a \
    /lib/ld-musl-x86_64.so.1; do
    printf '%s\n' "$forbidden_input" >"$forged_trace"
    if (audit_link_trace "$forged_trace" "$primary" "$consumer") >/dev/null 2>&1; then
        fail "final-link trace audit admitted ambient input: $forbidden_input"
    fi
done
if grep -Eqi '(/opt/musl-|/usr/lib/(gcc|clang)|/lib/ld-|crt(begin|end)|lib(gcc|ssp|atomic)|compiler-rt|libc\.so)' \
    "$trace" "$map"; then
    fail "final-link evidence contains an ambient target runtime input"
fi

readelf --file-header --wide "$candidate" >"$consumer/file-header"
readelf --program-headers --wide "$candidate" >"$consumer/program-headers"
readelf --dynamic --wide "$candidate" >"$consumer/dynamic" || true
readelf --symbols --wide "$candidate" >"$consumer/symbols"
readelf --relocs --wide "$candidate" >"$consumer/relocations"
assert_final_static_executable "$candidate" "$consumer/file-header" \
    "$consumer/program-headers" "$consumer/dynamic" "$consumer/symbols" \
    "$consumer/relocations"

candidate_output="$(env -i "$candidate")" || fail "owned installed candidate failed"
[ "$candidate_output" = PIMBCAF ] || fail "owned candidate output drifted: $candidate_output"

candidate_phoff="$(od -An -tu8 -j "$ELF64_PROGRAM_HEADER_OFFSET" -N 8 "$candidate" | tr -d '[:space:]')"
candidate_phnum="$(od -An -tu2 -j "$ELF64_PROGRAM_HEADER_COUNT_OFFSET" -N 2 "$candidate" | tr -d '[:space:]')"
[ -n "$candidate_phoff" ] && [ -n "$candidate_phnum" ] || fail "candidate ELF metadata is unreadable"
tls_header_index=''
for ((header_index = 0; header_index < candidate_phnum; header_index += 1)); do
    header_offset=$((candidate_phoff + header_index * ELF64_PROGRAM_HEADER_SIZE))
    header_type="$(od -An -tu4 -j "$header_offset" -N 4 "$candidate" | tr -d '[:space:]')"
    if [ "$header_type" = 7 ]; then
        tls_header_index="$header_index"
        break
    fi
done
[ -n "$tls_header_index" ] || fail "candidate has no PT_TLS program header to mutate"
tls_filesz_offset=$((candidate_phoff + tls_header_index * ELF64_PROGRAM_HEADER_SIZE + ELF64_P_FILESZ_OFFSET))
malformed="$consumer/owned-static-tls-bad-filesz"
cp "$candidate" "$malformed"
printf '\377\377\377\377\377\377\377\377' | dd of="$malformed" bs=1 \
    seek="$tls_filesz_offset" conv=notrunc status=none
expect_bootstrap_rejection "$malformed"

printf 'x86 owned static sysroot + pthread/TLS consumer: PASS\n'

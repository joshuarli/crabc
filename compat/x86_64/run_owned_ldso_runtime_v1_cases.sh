#!/usr/bin/env bash
# Installed-product evidence for the loader/libc initial-TLS RuntimeV1 wire.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/native_build_environment.sh"
readonly PRODUCT="${1:?usage: $0 DYNAMIC-SYSROOT}"
readonly CONSUMER_SOURCE_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs"
readonly MAIN="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_main.c"
readonly STATIC_MAIN="$ROOT_DIR/compat/x86_64/loader_libc_tls_runtime_v1_static_main.c"
readonly LEFT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_left.c"
readonly RIGHT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_right.c"
readonly SHARED="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_shared.c"
readonly TRACE="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_trace.c"
readonly STRONG_MAIN_RECORD="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_strong_main_record.c"
readonly WEAK_DSO_RECORD="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_weak_dso_record.c"

fail() { printf 'ERROR: RuntimeV1 product: %s\n' "$*" >&2; exit 1; }
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: RuntimeV1 evidence requires native Linux/x86-64' >&2
    exit 2
fi
[ -d "$PRODUCT" ] || fail "installed product missing: $PRODUCT"
case "${TMPDIR:-}" in "$ROOT_DIR"/.work/*) ;; *) exit 2 ;; esac
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work="$(mktemp -d "$TMPDIR/runtime-v1-product.XXXXXX")"
printf 'evidence: %s\n' "$work"
root="$work/root"
fixtures="$root/fixtures"
cp -a "$PRODUCT" "$root"
mkdir -p "$fixtures"
loader="$root/lib/ld-crabc-x86_64.so.1"
record_name="__crabc_x86_64_loader_tls_runtime_v1"

python3 - "$loader" "$record_name" <<'PY'
import struct
import sys

path = sys.argv[1]
data = open(path, "rb").read()
def fail(message):
    raise SystemExit(f"ERROR: RuntimeV1 product: {message}: {path}")
if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
    fail("interpreter is not ELF64 little-endian")
(_ident, _type, _machine, _version, _entry, phoff, shoff, _flags,
 _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
if phentsize != 56 or shentsize != 64:
    fail("ELF table layout drifted")
if phoff + phentsize * phnum > len(data) or shoff + shentsize * shnum > len(data):
    fail("ELF table leaves the file")
sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
def section_name(index):
    if index >= len(sections) or shstrndx >= len(sections):
        fail("section index is invalid")
    name_offset = sections[index][0]
    string_section = sections[shstrndx]
    string_offset, string_size = string_section[4], string_section[5]
    if string_offset + string_size > len(data) or name_offset >= string_size:
        fail("section name table is invalid")
    start = string_offset + name_offset
    end = data.find(b"\0", start, string_offset + string_size)
    if end < 0:
        fail("section name is unterminated")
    return data[start:end].decode("ascii", "strict")
def symbol_name(section, name_offset):
    string_index = section[6]
    if string_index >= len(sections):
        fail("symbol string-table link is invalid")
    string_section = sections[string_index]
    string_offset, string_size = string_section[4], string_section[5]
    if string_offset + string_size > len(data) or name_offset >= string_size:
        fail("symbol name table is invalid")
    start = string_offset + name_offset
    end = data.find(b"\0", start, string_offset + string_size)
    if end < 0:
        fail("symbol name is unterminated")
    return data[start:end].decode("ascii", "strict")
regular = []
for section in sections:
    kind, offset, size, entry_size = section[1], section[4], section[5], section[9]
    if kind != 2:
        continue
    if entry_size != 24 or size % entry_size or offset + size > len(data):
        fail("SHT_SYMTAB layout drifted")
    for position in range(offset, offset + size, entry_size):
        name_offset, info, other, section_index, value, symbol_size = struct.unpack_from(
            "<IBBHQQ", data, position)
        if symbol_name(section, name_offset) == sys.argv[2]:
            regular.append((info, other, section_index, value, symbol_size))
if len(regular) != 1:
    fail("private RuntimeV1 record is not exactly one regular symbol")
info, other, section_index, record_value, record_size = regular[0]
if (info >> 4) != 0 or (info & 0x0F) != 1 or (other & 0x03) not in (0, 2):
    fail("private RuntimeV1 record is not a static local OBJECT")
if section_index == 0 or section_index >= len(sections) or record_size != 72:
    fail("private RuntimeV1 record layout drifted")
record_section = sections[section_index]
record_section_name = section_name(section_index)
if not record_section_name.startswith(".data") or record_section_name == ".data.rel.ro":
    fail("private RuntimeV1 record escaped its writable data placement")
if record_section[2] & 0x3 != 0x3:
    fail("private RuntimeV1 record section is not writable allocated data")
for section in sections:
    kind, offset, size, entry_size = section[1], section[4], section[5], section[9]
    if kind != 11:
        continue
    if entry_size != 24 or size % entry_size or offset + size > len(data):
        fail("SHT_DYNSYM layout drifted")
    for position in range(offset, offset + size, entry_size):
        name_offset = struct.unpack_from("<I", data, position)[0]
        if symbol_name(section, name_offset) == sys.argv[2]:
            fail("private RuntimeV1 record leaked into SHT_DYNSYM")
relro = []
for index in range(phnum):
    p_type, _flags, _offset, vaddr, _paddr, _filesz, memsz, _align = struct.unpack_from(
        "<IIQQQQQQ", data, phoff + index * phentsize)
    if p_type == 0x6474E552:
        relro.append((vaddr, memsz))
if len(relro) != 1:
    fail("interpreter does not have exactly one PT_GNU_RELRO")
relro_value, relro_size = relro[0]
page = 4096
relro_start = relro_value & -page
relro_end = (relro_value + relro_size + page - 1) & -page
if record_value < relro_end and record_value + record_size > relro_start:
    fail("private RuntimeV1 record overlaps page-rounded PT_GNU_RELRO")
PY

left_dir="$fixtures/left"; right_dir="$fixtures/right"; shared_dir="$fixtures/shared"
mkdir "$left_dir" "$right_dir" "$shared_dir"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so "$SHARED" -o "$shared_dir/libshared.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,/fixtures/shared \
    "$LEFT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so -o "$left_dir/libleft.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so -Wl,-rpath,/fixtures/shared \
    "$RIGHT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so -o "$right_dir/libright.so"
cc -fPIC -fno-stack-protector -ffreestanding -fno-asynchronous-unwind-tables \
    -c "$STRONG_MAIN_RECORD" -o "$work/strong-main-record.o"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,/fixtures/shared \
    "$LEFT" "$WEAK_DSO_RECORD" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$work/libleft-weak-record.so"

build_consumer() {
    local output="$1"; shift
    "${rustc_command[@]}" --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        "$@" "$CONSUMER_SOURCE_ROOT" -o "$output"
}
mapfile -d '' -t rustc_command < <(python3 -B "$ROOT_DIR/compat/x86_64/native_rustc.py")
build_consumer "$work/libconsumer-static.a" --cfg crabc_loader_libc_tls_runtime_v1_static_mode

# The product CRT owns _start; the fixture start object would conflict.  Use
# the ordinary CRT entry with the fixture's main instead.
build_main_crt() {
    local output="$1" mode="$2" extra="$3"
    local -a defines=() extra_args=()
    [ "$mode" = reject ] && defines+=(-DCRABC_GENERAL_RUNTIME_V1_REJECT)
    [ -n "$extra" ] && extra_args=("$extra")
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -ftls-model=global-dynamic -mtls-dialect=gnu \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--unresolved-symbols=ignore-all -Wl,--export-dynamic \
        -Wl,--dynamic-linker,/lib/ld-crabc-x86_64.so.1 \
        -Wl,-rpath,/fixtures/left:/fixtures/right:/fixtures/shared \
        -Wl,-rpath-link,"$left_dir" -Wl,-rpath-link,"$right_dir" -Wl,-rpath-link,"$shared_dir" \
        "${defines[@]}" "$PRODUCT/usr/lib/Scrt1.o" "$PRODUCT/usr/lib/crti.o" \
        "$MAIN" "${extra_args[@]}" "$PRODUCT/usr/lib/crabc-dynamic-attach.o" \
        -L"$PRODUCT/usr/lib" -lc "$PRODUCT/usr/lib/libcrabc-builtins.a" "$PRODUCT/usr/lib/crtn.o" \
        -L"$left_dir" -L"$right_dir" -L"$shared_dir" \
        -Wl,--no-as-needed -l:libleft.so -l:libright.so -l:libshared.so -o "$output"
}

build_main_crt "$fixtures/main-valid" accept ""
build_main_crt "$fixtures/main-reject" reject ""
build_main_crt "$fixtures/main-strong-record" accept "$work/strong-main-record.o"

if ! readelf -Ws "$fixtures/main-valid" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'consumer lost its exact weak loader record import'
fi
if ! readelf -rW "$fixtures/main-valid" | grep -E 'R_X86_64_GLOB_DAT.*__crabc_x86_64_loader_tls_runtime_v1' >/dev/null; then
    fail 'consumer lacks the checked RuntimeV1 record GOT relocation'
fi
for binary in "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    readelf -lW "$binary" | grep ' TLS ' >/dev/null || fail "graph fixture lacks PT_TLS: $binary"
    readelf -dW "$binary" | grep -E '\(INIT_ARRAY\)|\(INIT_ARRAYSZ\)' >/dev/null ||
        fail "dependency fixture lacks its DT_INIT_ARRAY pair: $binary"
done
readelf -lW "$fixtures/main-valid" | grep ' TLS ' >/dev/null || fail 'main fixture lacks PT_TLS'

chroot "$root" /fixtures/main-valid >/dev/null || fail 'main-valid failed'

# C8: malformed record metadata is injected into a disposable loader copy.
record_offset() {
    python3 - "$loader" "$record_name" <<'PY'
import struct, sys
path, name = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
(_ident, _type, _machine, _version, _entry, phoff, shoff, _flags,
 _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
def section_name(index):
    name_offset = sections[index][0]
    string_section = sections[shstrndx]
    start = string_section[4] + name_offset
    end = data.find(b"\0", start)
    return data[start:end].decode()
def symbol_name(section, offset):
    string_section = sections[section[6]]
    start = string_section[4] + offset
    end = data.find(b"\0", start)
    return data[start:end].decode()
for section in sections:
    if section[1] != 2:
        continue
    for position in range(section[4], section[4] + section[5], 24):
        name_offset, _info, _other, section_index, value, size = struct.unpack_from("<IBBHQQ", data, position)
        if symbol_name(section, name_offset) == name:
            record = sections[section_index]
            print(record[4] + value - record[3])
            raise SystemExit(0)
raise SystemExit(1)
PY
}
record_file_offset="$(record_offset)"
patch_u32() {
    local offset="$1" value="$2" byte escape
    { for ((index = 0; index < 4; index++)); do byte=$((value & 255));
        printf -v escape '\\%03o' "$byte"; printf '%b' "$escape"; value=$((value >> 8)); done; } |
        dd of="$loader" bs=1 seek="$offset" conv=notrunc status=none
}
patch_u64() {
    local offset="$1" value="$2" byte escape
    { for ((index = 0; index < 8; index++)); do byte=$((value & 255));
        printf -v escape '\\%03o' "$byte"; printf '%b' "$escape"; value=$((value >> 8)); done; } |
        dd of="$loader" bs=1 seek="$offset" conv=notrunc status=none
}
cp "$loader" "$work/loader-valid.so"
for mutation in magic version abi_size mode owner generation; do
    cp "$work/loader-valid.so" "$loader"
    case "$mutation" in
        magic) patch_u64 "$record_file_offset" 0 ;;
        version) patch_u32 $((record_file_offset + 8)) 2 ;;
        abi_size) patch_u32 $((record_file_offset + 12)) 0 ;;
        mode) patch_u32 $((record_file_offset + 16)) 1 ;;
        owner) patch_u32 $((record_file_offset + 20)) 2 ;;
        generation) patch_u64 $((record_file_offset + 64)) 2 ;;
    esac
    set +e
    chroot "$root" /fixtures/main-reject >"$work/rejected.stdout" 2>"$work/rejected.stderr"
    status=$?
    set -e
    [ ! -s "$work/rejected.stdout" ] || fail "malformed $mutation record reached main output"
    [ "$status" -eq 0 ] || [ "$status" -eq 127 ] ||
        fail "malformed $mutation record was not rejected (status $status)"
    cp "$work/loader-valid.so" "$loader"
done
cp "$work/loader-valid.so" "$loader"

cc -D_GNU_SOURCE -std=c11 -static "$TRACE" -o "$fixtures/no-arch-set-fs-trace"
expect_rejection_before_fs() {
    local binary="$1" label="$2" output status
    set +e
    output="$(chroot "$root" /fixtures/no-arch-set-fs-trace "$binary" 2>&1)"
    status=$?
    set -e
    [ "$status" -eq 0 ] || fail "$label did not reject before ARCH_SET_FS: $output"
}
expect_rejection_before_fs /fixtures/main-strong-record 'strong main record import'
mv "$left_dir/libleft.so" "$work/libleft-normal.so"
cp "$work/libleft-weak-record.so" "$left_dir/libleft.so"
expect_rejection_before_fs /fixtures/main-valid 'weak DSO record import'
mv "$work/libleft-normal.so" "$left_dir/libleft.so"

cc -nostdlib -no-pie -fno-stack-protector -ffreestanding \
    -fno-asynchronous-unwind-tables -Wl,-e,_start \
    "$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S" "$STATIC_MAIN" \
    "$work/libconsumer-static.a" -o "$work/main-static"
readelf -lW "$work/main-static" | grep 'Requesting program interpreter' >/dev/null &&
    fail 'static-mode negative fixture gained PT_INTERP'
if readelf -Ws "$work/main-static" | awk \
    '$7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'static-mode consumer retained a loader record import'
fi
"$work/main-static"
printf '%s\n' 'installed loader/libc TLS RuntimeV1: PASS (record layout, weak main handoff, malformed metadata/DSo rejection, static observer)'

#!/usr/bin/env bash
# Native evidence for the private x86 general-initial TLS RuntimeV1 wire.
#
# This is an arbitrary bounded initial dependency graph plus one loader-owned
# generation-one descriptor consumed by a freestanding libc observer. It is
# not a dynamic product, a CRT lifecycle handoff, dlfcn, runtime mapping or
# unload protocol, worker/new-thread TLS implementation, or DTV-growth proof.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly LOADER_SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs"
readonly CONSUMER_SOURCE_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_main.c"
readonly STATIC_MAIN="$ROOT_DIR/compat/x86_64/loader_libc_tls_runtime_v1_static_main.c"
readonly LEFT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_left.c"
readonly RIGHT="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_right.c"
readonly SHARED="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_shared.c"
readonly TRACE="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_trace.c"
readonly STRONG_MAIN_RECORD="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_strong_main_record.c"
readonly WEAK_DSO_RECORD="$ROOT_DIR/compat/x86_64/loader_libc_general_tls_runtime_v1_weak_dso_record.c"

fail() {
    printf 'ERROR: x86 general loader/libc TLS RuntimeV1: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

if [ "$(uname -s)" != Linux ]; then
    fail 'requires native Linux'
fi
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail 'requires native x86-64' ;;
esac
for tool in cc grep readelf rustc cargo awk python3; do
    require_tool "$tool"
done
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
# Preserve the established pinned-musl-vs-candidate general TLS diamond as
# the independent base proof. The descriptor-specific graph below cannot run
# under musl because its constructor intentionally observes the private
# crabc-only attachment before main.
bash "$ROOT_DIR/compat/x86_64/run_ldso_general_initial_tls.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-general-loader-libc-tls-runtime-v1.XXXXXX)"
if [ "${CRABC_LDSO_GENERAL_TLS_RUNTIME_V1_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained general RuntimeV1 work directory: $work_dir" >&2
else
    trap 'rm -rf -- "$work_dir"' EXIT
fi

# Exercise the paired-reservation state machine under the exact RuntimeV1 cfg
# before linking the native graph. The test root omits only freestanding entry
# glue; it retains the loader graph, sealed registry, descriptor atomics, and
# rollback transition that must all complete before ARCH_SET_FS.
rustc --edition=2021 --test \
    --cfg crabc_general_initial_graph \
    --cfg crabc_general_initial_tls_materialization_v1 \
    --cfg crabc_general_loader_libc_tls_runtime_v1 \
    "$LOADER_SOURCE_ROOT" -o "$work_dir/general-runtime-v1-state-tests"
env -i PATH=/usr/bin:/bin "$work_dir/general-runtime-v1-state-tests"

build_source_loader() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        --cfg crabc_general_initial_graph \
        --cfg crabc_general_initial_tls_materialization_v1 \
        --cfg crabc_general_loader_libc_tls_runtime_v1 \
        "$@" "$LOADER_SOURCE_ROOT" -o "$work_dir/general-loader.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/general-loader.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_cargo_loader() {
    local output="$1"
    local target_dir="$work_dir/ldso-target"
    CARGO_TARGET_DIR="$target_dir" \
    RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
        cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
            --no-default-features \
            --features x86_64-general-initial-tls-runtime-v1-interpreter
    cp "$target_dir/x86_64-unknown-linux-musl/debug/libldso.so" "$output"
}

build_consumer() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        "$@" "$CONSUMER_SOURCE_ROOT" -o "$output"
}

case "${CRABC_LDSO_GENERAL_TLS_RUNTIME_V1_ROOT:-source}" in
    source)
        build_source_loader "$work_dir/ld-general-runtime-v1.so"
        ;;
    crabc-target)
        build_cargo_loader "$work_dir/ld-general-runtime-v1.so"
        ;;
    *)
        fail 'unsupported general TLS RuntimeV1 root selection'
        ;;
esac

# Metadata negatives are direct-source variants. The target-root command
# therefore proves the Cargo positive graph independently while retaining the
# exact source-root malformed descriptor fixtures that isolate libc checks.
for malformed in magic version abi_size mode owner generation; do
    build_source_loader "$work_dir/ld-general-runtime-v1-bad-$malformed.so" \
        --cfg "crabc_general_loader_libc_tls_runtime_v1_bad_$malformed"
done
build_source_loader "$work_dir/ld-general-runtime-v1-poisoned-dtv.so" \
    --cfg crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv
build_consumer "$work_dir/libconsumer.a"
build_consumer "$work_dir/libconsumer-static.a" \
    --cfg crabc_loader_libc_tls_runtime_v1_static_mode

require_record_outside_page_rounded_relro() {
    local interpreter="$1"
    python3 - "$interpreter" <<'PY'
import struct
import sys

path = sys.argv[1]
data = open(path, "rb").read()

def fail(message: str) -> None:
    raise SystemExit(f"ERROR: x86 general loader/libc TLS RuntimeV1: {message}: {path}")

if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
    fail("interpreter is not ELF64 little-endian")

(
    _ident,
    _type,
    _machine,
    _version,
    _entry,
    phoff,
    shoff,
    _flags,
    _ehsize,
    phentsize,
    phnum,
    shentsize,
    shnum,
    shstrndx,
) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
if phentsize != 56 or shentsize != 64:
    fail("ELF table layout drifted")
if phoff + phentsize * phnum > len(data) or shoff + shentsize * shnum > len(data):
    fail("ELF table leaves the file")

sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
            for index in range(shnum)]

def section_name(index: int) -> str:
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

def symbol_name(section: tuple[int, ...], name_offset: int) -> str:
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

record_name = "__crabc_x86_64_loader_tls_runtime_v1"
regular = []
for section in sections:
    kind, offset, size, entry_size = section[1], section[4], section[5], section[9]
    if kind != 2:
        continue
    if entry_size != 24 or size % entry_size or offset + size > len(data):
        fail("SHT_SYMTAB layout drifted")
    for position in range(offset, offset + size, entry_size):
        name_offset, info, other, section_index, value, symbol_size = struct.unpack_from(
            "<IBBHQQ", data, position
        )
        if symbol_name(section, name_offset) == record_name:
            regular.append((info, other, section_index, value, symbol_size))
if len(regular) != 1:
    fail("private RuntimeV1 record is not exactly one regular symbol")
info, other, section_index, record_value, record_size = regular[0]
if (info >> 4) != 0 or (info & 0x0F) != 1 or (other & 0x03) != 0:
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
        if symbol_name(section, name_offset) == record_name:
            fail("private RuntimeV1 record leaked into SHT_DYNSYM")

relro = []
for index in range(phnum):
    p_type, _flags, _offset, vaddr, _paddr, _filesz, memsz, _align = struct.unpack_from(
        "<IIQQQQQQ", data, phoff + index * phentsize
    )
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
}

for interpreter in "$work_dir"/ld-general-runtime-v1*.so; do
    [ "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "interpreter is not ET_DYN: $interpreter"
    ! readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)' ||
        fail "interpreter selected an ambient runtime: $interpreter"
    ! readelf -lW "$interpreter" | grep -q ' TLS ' ||
        fail "interpreter selected its own PT_TLS: $interpreter"
    require_record_outside_page_rounded_relro "$interpreter"
done
if readelf --dyn-syms -W "$work_dir/ld-general-runtime-v1.so" | awk \
    '$8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'private RuntimeV1 record leaked into the interpreter dynamic symbol table'
fi

left_dir="$work_dir/left"
right_dir="$work_dir/right"
shared_dir="$work_dir/shared"
mkdir "$left_dir" "$right_dir" "$shared_dir"

cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libshared.so \
    "$SHARED" -o "$shared_dir/libshared.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" \
    "$LEFT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$left_dir/libleft.so"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libright.so -Wl,-rpath,"$shared_dir" \
    "$RIGHT" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$right_dir/libright.so"

# These two relocations make the private record's narrow resolver exception
# observable independently.  The consumer's exact weak main-image import is
# accepted; a strong main import and a weak DSO import both have to stop the
# loader before the sole ARCH_SET_FS transition.
cc -fPIC -fno-stack-protector -ffreestanding -fno-asynchronous-unwind-tables \
    -c "$STRONG_MAIN_RECORD" -o "$work_dir/strong-main-record.o"
cc -fPIC -shared -nostdlib -ftls-model=global-dynamic -mtls-dialect=gnu \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libleft.so -Wl,-rpath,"$shared_dir" \
    "$LEFT" "$WEAK_DSO_RECORD" -L"$shared_dir" -Wl,--no-as-needed -l:libshared.so \
    -o "$work_dir/libleft-weak-record.so"

build_main() {
    local interpreter="$1"
    local output="$2"
    local mode="$3"
    local -a defines=()
    if [ "$mode" = reject ]; then
        defines+=(-DCRABC_GENERAL_RUNTIME_V1_REJECT)
    fi
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -ftls-model=global-dynamic -mtls-dialect=gnu \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--unresolved-symbols=ignore-all \
        -Wl,--export-dynamic-symbol=general_runtime_v1_constructor_attach \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$left_dir:$right_dir:$shared_dir" \
        "${defines[@]}" "$START" "$MAIN" "$work_dir/libconsumer.a" \
        -L"$left_dir" -L"$right_dir" -L"$shared_dir" \
        -Wl,--no-as-needed -l:libleft.so -l:libright.so -l:libshared.so \
        -o "$output"
}

build_main_with_strong_record() {
    local interpreter="$1"
    local output="$2"
    # `-fPIC` on this one object forces a GOT data relocation rather than a
    # text relocation. The two narrowly exported dynamic symbols preserve the
    # constructor callback and deliberately unresolved strong record without
    # exporting the main image's TLS definitions, which would change their
    # relocation form away from the bounded GNU-Dynamic fixture profile.
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -ftls-model=global-dynamic -mtls-dialect=gnu \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--unresolved-symbols=ignore-all \
        -Wl,--export-dynamic-symbol=general_runtime_v1_constructor_attach \
        -Wl,--export-dynamic-symbol=__crabc_x86_64_loader_tls_runtime_v1 \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$left_dir:$right_dir:$shared_dir" \
        "$START" "$MAIN" "$work_dir/strong-main-record.o" "$work_dir/libconsumer.a" \
        -L"$left_dir" -L"$right_dir" -L"$shared_dir" \
        -Wl,--no-as-needed -l:libleft.so -l:libright.so -l:libshared.so \
        -o "$output"
}

build_main "$work_dir/ld-general-runtime-v1.so" "$work_dir/main-valid" accept
for malformed in magic version abi_size mode owner generation; do
    build_main "$work_dir/ld-general-runtime-v1-bad-$malformed.so" \
        "$work_dir/main-bad-$malformed" reject
done
build_main "$work_dir/ld-general-runtime-v1-poisoned-dtv.so" \
    "$work_dir/main-poisoned-dtv" reject
build_main_with_strong_record "$work_dir/ld-general-runtime-v1.so" \
    "$work_dir/main-strong-record"

if ! readelf -Ws "$work_dir/main-valid" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'general libc consumer lost its exact weak loader record import'
fi
if ! readelf -rW "$work_dir/main-valid" | grep -Eq \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_loader_tls_runtime_v1'; then
    fail 'general libc consumer lacks the checked RuntimeV1 record GOT relocation'
fi
if ! readelf -Ws "$work_dir/main-strong-record" | awk \
    '$5 == "GLOBAL" && $7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'strong main-image RuntimeV1 record import was not retained'
fi
if ! readelf -rW "$work_dir/main-strong-record" | grep -Eq \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_loader_tls_runtime_v1'; then
    fail 'strong main-image RuntimeV1 record import lacks its GOT relocation'
fi
if ! readelf -Ws "$work_dir/libleft-weak-record.so" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'weak DSO RuntimeV1 record import was not retained'
fi
if ! readelf -rW "$work_dir/libleft-weak-record.so" | grep -Eq \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_loader_tls_runtime_v1'; then
    fail 'weak DSO RuntimeV1 record import lacks its GOT relocation'
fi
for binary in "$work_dir/main-valid" "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    readelf -lW "$binary" | grep -q ' TLS ' || fail "graph fixture lacks PT_TLS: $binary"
done
for binary in "$left_dir/libleft.so" "$right_dir/libright.so" "$shared_dir/libshared.so"; do
    readelf -dW "$binary" | grep -Eq '\(INIT_ARRAY\)|\(INIT_ARRAYSZ\)' ||
        fail "dependency fixture lacks its DT_INIT_ARRAY pair: $binary"
done

env -i PATH=/usr/bin:/bin "$work_dir/main-valid"
for malformed in magic version abi_size mode owner generation; do
    env -i PATH=/usr/bin:/bin "$work_dir/main-bad-$malformed"
done
env -i PATH=/usr/bin:/bin "$work_dir/main-poisoned-dtv"

# The expected relocation failures are traced outside the candidate process:
# they prove neither forbidden record import reaches the initial TLS install.
cc -D_GNU_SOURCE -std=c11 "$TRACE" -o "$work_dir/no-arch-set-fs-trace"
expect_rejection_before_fs() {
    local binary="$1"
    local case_name="$2"
    local output status
    set +e
    output="$(cd "$work_dir" && env -i PATH=/usr/bin:/bin \
        "$work_dir/no-arch-set-fs-trace" "$binary" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        printf 'ERROR: general RuntimeV1 import rejection did not precede ARCH_SET_FS (%s)\n' \
            "$case_name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

expect_rejection_before_fs "$work_dir/main-strong-record" 'strong main record import'
mv "$left_dir/libleft.so" "$work_dir/libleft-normal.so"
mv "$work_dir/libleft-weak-record.so" "$left_dir/libleft.so"
expect_rejection_before_fs "$work_dir/main-valid" 'weak DSO record import'
mv "$left_dir/libleft.so" "$work_dir/libleft-weak-record.so"
mv "$work_dir/libleft-normal.so" "$left_dir/libleft.so"

# A no-PT_INTERP image must not acquire any general-loader descriptor or alter
# Static Initial TLS ownership. Its separately compiled observer stub has no
# weak record import and returns rejection before an FS observation.
cc -nostdlib -no-pie -fno-stack-protector -ffreestanding \
    -fno-asynchronous-unwind-tables -Wl,-e,_start "$START" "$STATIC_MAIN" \
    "$work_dir/libconsumer-static.a" -o "$work_dir/main-static"
if readelf -lW "$work_dir/main-static" | grep -q 'Requesting program interpreter'; then
    fail 'static-mode negative fixture unexpectedly gained PT_INTERP'
fi
if readelf -Ws "$work_dir/main-static" | awk \
    '$7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'static-mode consumer retained a loader record import'
fi
env -i PATH=/usr/bin:/bin "$work_dir/main-static"

printf '%s\n' 'x86 general loader/libc TLS RuntimeV1: PASS (paired pre-FS reservations; READY-last private descriptor; general TLS diamond)'

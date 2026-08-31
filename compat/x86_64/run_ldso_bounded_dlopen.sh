#!/usr/bin/env bash
# Native one-slot runtime mapping/search evidence over the x86 public bridge.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly BRIDGE_SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_public_dlfcn_start.S"
readonly PROBE="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_probe.c"
readonly FINI_PROBE="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_fini_probe.c"
readonly PLUGIN="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_plugin.c"
readonly PREINIT_PROBE="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_preinit_probe.c"
readonly PREINIT_PLUGIN="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_preinit_plugin.c"
readonly TLS_PLUGIN="$ROOT_DIR/compat/x86_64/ldso_bounded_dlopen_tls.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

fail() { printf 'ERROR: x86 bounded runtime dlopen: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

# GNU ld rejects `.preinit_array` in a DSO. Build an ordinary init-array
# fixture, then change the paired dynamic tags only. The target ELF remains a
# normal RELA-bearing ET_DYN image; the tag pair models the ABI's DSO-inert
# preinit metadata without manufacturing a nonstandard linker output.
rewrite_init_array_as_preinit() {
    local image="$1"
    local malformed_address="$2"
    python3 - "$image" "$malformed_address" <<'PY'
import struct
import sys

image, malformed_address = sys.argv[1:]
data = bytearray(open(image, "rb").read())

if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
    raise SystemExit("preinit fixture is not ELF64 little-endian")

program_headers = struct.unpack_from("<Q", data, 32)[0]
program_header_size = struct.unpack_from("<H", data, 54)[0]
program_header_count = struct.unpack_from("<H", data, 56)[0]
if program_header_size < 56:
    raise SystemExit("preinit fixture has an invalid ELF64 program-header size")

dynamic_offset = dynamic_size = None
for index in range(program_header_count):
    offset = program_headers + index * program_header_size
    if offset + 56 > len(data):
        raise SystemExit("preinit fixture program headers exceed its file")
    if struct.unpack_from("<I", data, offset)[0] == 2:  # PT_DYNAMIC
        if dynamic_offset is not None:
            raise SystemExit("preinit fixture has multiple PT_DYNAMIC segments")
        dynamic_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        dynamic_size = struct.unpack_from("<Q", data, offset + 32)[0]

if dynamic_offset is None or dynamic_size is None or dynamic_size % 16 != 0:
    raise SystemExit("preinit fixture lacks a valid PT_DYNAMIC table")
if dynamic_offset + dynamic_size > len(data):
    raise SystemExit("preinit fixture dynamic table exceeds its file")

replacement = {25: 32, 27: 33}  # DT_INIT_ARRAY[/SZ] -> DT_PREINIT_ARRAY[/SZ]
seen = set()
for index in range(dynamic_size // 16):
    offset = dynamic_offset + index * 16
    tag = struct.unpack_from("<q", data, offset)[0]
    if tag == 0:
        break
    if tag not in replacement:
        continue
    if tag in seen:
        raise SystemExit("preinit fixture duplicated an init-array dynamic tag")
    seen.add(tag)
    struct.pack_into("<q", data, offset, replacement[tag])
    if tag == 25 and malformed_address == "1":
        # Aligned but outside every load range; the candidate must reject this
        # metadata before it can publish the one available runtime slot.
        struct.pack_into("<Q", data, offset + 8, 0xffff_ffff_ffff_fff8)

if seen != set(replacement):
    raise SystemExit("preinit fixture is missing the paired init-array tags")

with open(image, "wb") as output:
    output.write(data)
PY
}

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
for tool in awk cc grep python3 readelf rustc; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl 1.2.6 compiler'
[ -x "$MUSL_LOADER" ] || fail 'missing pinned musl 1.2.6 loader'

work_dir="$(mktemp -d /tmp/crabc-x86-64-bounded-dlopen.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
interpreter="$work_dir/ld-crabc-x86_64-bounded-dlopen.so"
archive="$work_dir/libcrabc-bounded-dlopen.a"

rustc --edition=2021 --crate-type staticlib --cfg crabc_fixed_graph_dlfcn \
    --cfg crabc_bounded_runtime_dlopen -C panic=abort -C relocation-model=pic \
    "$SOURCE" -o "$work_dir/libbounded-dlopen-ldso.a"
cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
    -Wl,--whole-archive "$work_dir/libbounded-dlopen-ldso.a" -Wl,--no-whole-archive \
    -o "$interpreter"
rustc --edition=2021 --crate-type staticlib -C relocation-model=pic \
    -C code-model=small -C panic=abort "$BRIDGE_SOURCE" -o "$archive"

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs \
    -Wl,-soname,libleaf-bounded-dlopen.so "$LEAF" -o "$work_dir/libleaf-bounded-dlopen.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,-soname,libmid-bounded-dlopen.so -Wl,-rpath,"$work_dir" \
    "$MID" -L"$work_dir" -Wl,--no-as-needed -l:libleaf-bounded-dlopen.so \
    -o "$work_dir/libmid-bounded-dlopen.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,-soname,libmid-bounded-dlopen-init.so -Wl,-rpath,"$work_dir" \
    -Wl,-init,mid_value "$MID" -L"$work_dir" -Wl,--no-as-needed \
    -l:libleaf-bounded-dlopen.so -o "$work_dir/libmid-bounded-dlopen-init.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,-soname,libmid-bounded-dlopen-fini.so -Wl,-rpath,"$work_dir" \
    -Wl,-fini,mid_value "$MID" -L"$work_dir" -Wl,--no-as-needed \
    -l:libleaf-bounded-dlopen.so -o "$work_dir/libmid-bounded-dlopen-fini.so"
for name in libbounded-plugin.so libbounded-extra.so; do
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,"$name" \
        -Wl,-init,bounded_plugin_legacy_initialize \
        "$PLUGIN" -L"$work_dir" -Wl,--no-as-needed -l:libleaf-bounded-dlopen.so \
        -o "$work_dir/$name"
done
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libbounded-fini-plugin.so \
    -Wl,-init,bounded_plugin_legacy_initialize \
    -Wl,-fini,bounded_plugin_legacy_finalize \
    "$PLUGIN" -L"$work_dir" -Wl,--no-as-needed -l:libleaf-bounded-dlopen.so \
    -o "$work_dir/libbounded-fini-plugin.so"
cc -DCRABC_BOUNDED_PLUGIN_INVALID_INIT=1 -fPIC -shared -nostdlib \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libbounded-init-malformed.so \
    -Wl,-init,bounded_plugin_invalid_init "$PLUGIN" -L"$work_dir" \
    -Wl,--no-as-needed -l:libleaf-bounded-dlopen.so \
    -o "$work_dir/libbounded-init-malformed.so"
cc -DCRABC_BOUNDED_PLUGIN_INVALID_FINI=1 -fPIC -shared -nostdlib \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,-soname,libbounded-fini-malformed.so \
    -Wl,-fini,bounded_plugin_invalid_fini "$PLUGIN" -L"$work_dir" \
    -Wl,--no-as-needed -l:libleaf-bounded-dlopen.so \
    -o "$work_dir/libbounded-fini-malformed.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libbounded-tls.so "$TLS_PLUGIN" -o "$work_dir/libbounded-tls.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libbounded-unretained-dependency.so "$LEAF" \
    -o "$work_dir/libbounded-unretained-dependency.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libbounded-unretained.so "$PLUGIN" -L"$work_dir" \
    -Wl,--no-as-needed -l:libbounded-unretained-dependency.so \
    -o "$work_dir/libbounded-unretained.so"
for image in libbounded-preinit.so libbounded-preinit-malformed.so; do
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,"$image" "$PREINIT_PLUGIN" -o "$work_dir/$image"
done
rewrite_init_array_as_preinit "$work_dir/libbounded-preinit.so" 0
rewrite_init_array_as_preinit "$work_dir/libbounded-preinit-malformed.so" 1

"$ORACLE_CC" -std=c11 -fPIE -pie -fno-builtin \
    -Wl,--dynamic-linker,"$MUSL_LOADER" -Wl,-rpath,"$work_dir" \
    "$PROBE" -L"$work_dir" -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -pthread -ldl -o "$work_dir/main-musl-bounded-dlopen"
"$ORACLE_CC" -std=c11 -fPIE -pie -fno-builtin \
    -Wl,--dynamic-linker,"$MUSL_LOADER" -Wl,-rpath,"$work_dir" \
    "$FINI_PROBE" -L"$work_dir" -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -ldl -o "$work_dir/main-musl-bounded-dlopen-fini"
"$ORACLE_CC" -std=c11 -DCRABC_BOUNDED_DLFCN_FREESTANDING=1 \
    -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
    -Wl,-rpath,"$work_dir" "$START" "$PROBE" "$archive" -L"$work_dir" \
    -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -o "$work_dir/main-crabc-bounded-dlopen"
cc -DCRABC_BOUNDED_DLFCN_FREESTANDING=1 \
    -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
    -Wl,-rpath,"$work_dir" "$START" "$FINI_PROBE" "$archive" -L"$work_dir" \
    -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -o "$work_dir/main-crabc-bounded-dlopen-fini"
cc -DCRABC_BOUNDED_DLFCN_FREESTANDING=1 \
    -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
    -Wl,-rpath,"$work_dir" "$START" "$PROBE" "$archive" -L"$work_dir" \
    -Wl,--no-as-needed -l:libmid-bounded-dlopen-init.so \
    -o "$work_dir/main-crabc-bounded-dlopen-initial-init"
cc -DCRABC_BOUNDED_DLFCN_FREESTANDING=1 \
    -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
    -Wl,-rpath,"$work_dir" "$START" "$PROBE" "$archive" -L"$work_dir" \
    -Wl,--no-as-needed -l:libmid-bounded-dlopen-fini.so \
    -o "$work_dir/main-crabc-bounded-dlopen-initial-fini"
"$ORACLE_CC" -std=c11 -fPIE -pie -fno-builtin \
    -Wl,--dynamic-linker,"$MUSL_LOADER" -Wl,-rpath,"$work_dir" \
    "$PREINIT_PROBE" -L"$work_dir" -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -ldl -o "$work_dir/main-musl-bounded-preinit"
"$ORACLE_CC" -std=c11 -DCRABC_BOUNDED_DLFCN_FREESTANDING=1 \
    -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
    -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
    -Wl,-rpath,"$work_dir" "$START" "$PREINIT_PROBE" "$archive" -L"$work_dir" \
    -Wl,--no-as-needed -l:libmid-bounded-dlopen.so \
    -o "$work_dir/main-crabc-bounded-preinit"

[ "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN ] ||
    fail 'interpreter is not ET_DYN'
! readelf -dW "$interpreter" | grep -E '\(NEEDED\)|\(INTERP\)|\(RELR\)' >/dev/null ||
    fail 'interpreter selected an ambient runtime'
! readelf -lW "$interpreter" | grep -F ' TLS ' >/dev/null || fail 'interpreter selected PT_TLS'
readelf -Ws "$interpreter" | awk \
    '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" && $3 == 64 { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'interpreter lacks exact RuntimeV1-prefix record'

candidate="$work_dir/main-crabc-bounded-dlopen"
[ "$(readelf -h "$candidate" | awk '/Type:/{print $2}')" = DYN ] ||
    fail 'candidate main is not ET_DYN'
! readelf -dW "$candidate" | grep -E '\(NEEDED\).*(libc|libgcc|ld-linux)' >/dev/null ||
    fail 'candidate main selected an ambient runtime'
! readelf -lW "$candidate" | grep -F ' TLS ' >/dev/null || fail 'candidate main selected PT_TLS'
readelf -Ws "$candidate" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'candidate lost weak loader-record import'
readelf -rW "$candidate" | grep -E \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1' >/dev/null ||
    fail 'candidate lacks loader-record GLOB_DAT'
grep -Fq 'RTLD_NOLOAD' "$PROBE" ||
    fail 'runtime probe lacks RTLD_NOLOAD presence evidence'
grep -Fq 'RTLD_LAZY | RTLD_NOLOAD' "$PROBE" ||
    fail 'runtime probe lacks lazy RTLD_NOLOAD reference evidence'
grep -Fq 'RTLD_NODELETE' "$PROBE" ||
    fail 'runtime probe lacks bounded RTLD_NODELETE evidence'
grep -Fq 'RTLD_LAZY | RTLD_NOLOAD | RTLD_NODELETE' "$PROBE" ||
    fail 'runtime probe lacks lazy RTLD_NOLOAD|RTLD_NODELETE reference evidence'
grep -Fq 'libleaf-bounded-dlopen.so' "$PROBE" ||
    fail 'runtime probe lacks initial-object RTLD_NOLOAD rejection evidence'

for image in "$work_dir/libbounded-plugin.so" "$work_dir/libbounded-extra.so"; do
    [ "$(readelf -h "$image" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "runtime plugin is not ET_DYN: $image"
    ! readelf -lW "$image" | grep -F ' TLS ' >/dev/null || fail "positive plugin selected PT_TLS: $image"
    actual="$(readelf -dW "$image" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    [ "$actual" = libleaf-bounded-dlopen.so ] || fail "runtime plugin dependency drifted: $actual"
done
readelf -dW "$work_dir/libbounded-plugin.so" | grep -F '(INIT)' >/dev/null ||
    fail 'positive runtime plugin lacks DT_INIT evidence'
readelf -dW "$work_dir/libbounded-fini-plugin.so" | grep -F '(FINI)' >/dev/null ||
    fail 'positive runtime plugin lacks DT_FINI evidence'
if readelf -dW "$work_dir/libbounded-fini-plugin.so" | grep -F '(FINI_ARRAY)' >/dev/null; then
    fail 'positive runtime plugin selected DT_FINI_ARRAY'
fi
readelf -dW "$work_dir/libmid-bounded-dlopen-init.so" | grep -F '(INIT)' >/dev/null ||
    fail 'initial DSO DT_INIT rejection fixture drifted'
readelf -dW "$work_dir/libmid-bounded-dlopen-fini.so" | grep -F '(FINI)' >/dev/null ||
    fail 'initial DSO DT_FINI rejection fixture drifted'
readelf -Ws "$work_dir/libbounded-init-malformed.so" | awk \
    '$4 == "OBJECT" && $7 != "UND" && $8 == "bounded_plugin_invalid_init" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'malformed runtime plugin lacks non-executable DT_INIT target evidence'
readelf -Ws "$work_dir/libbounded-fini-malformed.so" | awk \
    '$4 == "OBJECT" && $7 != "UND" && $8 == "bounded_plugin_invalid_fini" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'malformed runtime plugin lacks non-executable DT_FINI target evidence'
readelf -lW "$work_dir/libbounded-tls.so" | grep -F ' TLS ' >/dev/null ||
    fail 'malformed runtime plugin lacks PT_TLS rejection evidence'
actual="$(readelf -dW "$work_dir/libbounded-unretained.so" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
[ "$actual" = libbounded-unretained-dependency.so ] ||
    fail "unretained-dependency fixture drifted: $actual"
for image in "$work_dir/libbounded-preinit.so" "$work_dir/libbounded-preinit-malformed.so"; do
    [ "$(readelf -h "$image" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "preinit runtime plugin is not ET_DYN: $image"
    ! readelf -lW "$image" | grep -F ' TLS ' >/dev/null ||
        fail "preinit runtime plugin selected PT_TLS: $image"
    readelf -dW "$image" | grep -F '(PREINIT_ARRAY)' >/dev/null ||
        fail "preinit runtime plugin lacks DT_PREINIT_ARRAY: $image"
    readelf -dW "$image" | grep -F '(PREINIT_ARRAYSZ)' >/dev/null ||
        fail "preinit runtime plugin lacks DT_PREINIT_ARRAYSZ: $image"
    ! readelf -dW "$image" | grep -E '\((INIT|FINI)(_ARRAY|_ARRAYSZ)?\)' >/dev/null ||
        fail "preinit runtime plugin retained an executable lifecycle tag: $image"
done

run_clean() { env -i PATH=/usr/bin:/bin "$1"; }
(cd "$work_dir" && run_clean "$work_dir/main-musl-bounded-dlopen") ||
    fail 'pinned-musl runtime dlopen differential failed'
(cd "$work_dir" && run_clean "$candidate") ||
    fail 'crabc bounded runtime dlopen behavior failed'
(cd "$work_dir" && run_clean "$work_dir/main-musl-bounded-dlopen-fini") ||
    fail 'pinned-musl legacy DT_FINI differential failed'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-bounded-dlopen-fini") ||
    fail 'crabc legacy DT_FINI behavior failed'
if (cd "$work_dir" && run_clean "$work_dir/main-crabc-bounded-dlopen-initial-init" >/dev/null 2>&1); then
    fail 'candidate accepted DT_INIT in an initial DSO'
else
    status=$?
    [ "$status" -eq 127 ] ||
        fail "candidate initial-DSO DT_INIT rejection status drifted: $status"
fi
if (cd "$work_dir" && run_clean "$work_dir/main-crabc-bounded-dlopen-initial-fini" >/dev/null 2>&1); then
    fail 'candidate accepted DT_FINI in an initial DSO'
else
    status=$?
    [ "$status" -eq 127 ] ||
        fail "candidate initial-DSO DT_FINI rejection status drifted: $status"
fi
(cd "$work_dir" && run_clean "$work_dir/main-musl-bounded-preinit") ||
    fail 'pinned-musl runtime DSO DT_PREINIT_ARRAY inertness differential failed'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-bounded-preinit") ||
    fail 'crabc runtime DSO DT_PREINIT_ARRAY inertness behavior failed'

printf '%s\n' 'x86 bounded runtime DSO DT_PREINIT_ARRAY inertness: PASS'
printf '%s\n' 'x86 bounded runtime dlopen search/mapping/concurrency: PASS'

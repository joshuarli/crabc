#!/usr/bin/env bash
# Source-only native x86-64 C errno/initial-TLS evidence.
#
# Invoke this from the pinned Linux/amd64 evidence image. It compiles only the
# standalone x86 errno module and links one native C executable; it never
# selects `crabc-libc` or its AArch64 crate root. This is an ABI proof, not a
# musl differential or compatibility-oracle gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

require_native_linux_x86_64_host() {
    if [ "$(uname -s)" != "Linux" ]; then
        printf 'ERROR: native x86 errno/TLS evidence requires Linux\n' >&2
        exit 2
    fi

    case "$(uname -m)" in
        x86_64|amd64) ;;
        *)
            printf 'ERROR: native x86 errno/TLS evidence refuses emulation\n' >&2
            exit 2
            ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'ERROR: x86 errno/TLS evidence requires %s\n' "$1" >&2
        exit 2
    }
}

require_native_linux_x86_64_host
require_tool cc
require_tool readelf
require_tool rustup
require_tool objdump

work_dir="$(mktemp -d /tmp/crabc-x86-64-errno-tls.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

errno_object="$work_dir/errno.o"
probe="$work_dir/errno-tls-probe"
header_trace="$work_dir/header-trace"
errno_disassembly="$work_dir/errno-disassembly"
errno_symbols="$work_dir/errno-symbols"
errno_relocations="$work_dir/errno-relocations"
errno_object_disassembly="$work_dir/errno-object-disassembly"
probe_program_headers="$work_dir/probe-program-headers"
probe_symbols="$work_dir/probe-symbols"
probe_dynamic_symbols="$work_dir/probe-dynamic-symbols"
probe_disassembly="$work_dir/probe-disassembly"

cd "$ROOT_DIR"
cc -E -H -I"$ROOT_DIR/include" compat/x86_64/libc_errno_tls_probe.c \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/errno.h" "$header_trace" || {
    printf 'ERROR: x86 errno/TLS probe did not use the project errno header\n' >&2
    exit 1
}

rustup run nightly-2026-07-24 rustc --edition=2021 \
    --target x86_64-unknown-linux-musl \
    --crate-type=lib \
    --emit=obj \
    -C relocation-model=static \
    -C code-model=small \
    -C panic=abort \
    compat/x86_64/libc_errno_tls_probe.rs \
    -o "$errno_object"

# Save evidence before searching it. With `pipefail`, a `grep -q` reader can
# close its pipe early and make readelf or objdump's harmless SIGPIPE look like
# a nondeterministic failed assertion.
readelf --symbols --wide "$errno_object" >"$errno_symbols"
readelf --relocs --wide "$errno_object" >"$errno_relocations"
objdump -dr "$errno_object" >"$errno_object_disassembly"

grep -Eq '[[:space:]]TLS[[:space:]]+LOCAL[[:space:]]' "$errno_symbols" || {
    printf 'ERROR: x86 errno object lacks its local TLS datum\n' >&2
    exit 1
}
grep -Eq 'R_X86_64_TPOFF(32|64)' "$errno_relocations" || {
    printf 'ERROR: x86 errno object lacks a static TLS TPOFF relocation\n' >&2
    exit 1
}
if grep -Eq 'TLSGD|TLSDESC|GOTTPOFF' "$errno_relocations"; then
    printf 'ERROR: x86 errno object selected dynamic TLS relocation\n' >&2
    exit 1
fi
if grep -Fq '__tls_get_addr' "$errno_object_disassembly"; then
    printf 'ERROR: x86 errno object calls __tls_get_addr\n' >&2
    exit 1
fi

# An executable owns its public `__errno_location` definition without
# colliding with the C runtime's dynamic definition. `-no-pie` keeps the
# source-only leaf in the executable's initial TLS block, which is what the
# object-level `R_X86_64_TPOFF*` gate and linked `%fs` code prove below.
cc -no-pie -pthread -I"$ROOT_DIR/include" \
    compat/x86_64/libc_errno_tls_probe.c "$errno_object" \
    -o "$probe"

readelf --program-headers --wide "$probe" >"$probe_program_headers"
readelf --symbols --wide "$probe" >"$probe_symbols"
readelf --dyn-syms --wide "$probe" >"$probe_dynamic_symbols"
objdump -d "$probe" >"$probe_disassembly"

grep -Eq '[[:space:]]TLS[[:space:]]' "$probe_program_headers" || {
    printf 'ERROR: x86 errno probe lacks a TLS program header\n' >&2
    exit 1
}
grep -Eq \
    '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+__errno_location$' \
    "$probe_symbols" || {
    printf 'ERROR: x86 errno probe does not define public __errno_location\n' >&2
    exit 1
}
if grep -Fq '__tls_get_addr' "$probe_dynamic_symbols"; then
    printf 'ERROR: x86 errno probe has dynamic __tls_get_addr\n' >&2
    exit 1
fi
if grep -Fq '__tls_get_addr' "$probe_disassembly"; then
    printf 'ERROR: static x86 errno probe calls __tls_get_addr\n' >&2
    exit 1
fi
objdump -d --disassemble=__errno_location "$probe" >"$errno_disassembly"
grep -Eq '%fs:0x0' "$errno_disassembly" || {
    printf 'ERROR: linked x86 __errno_location is not a direct fs TLS access\n' >&2
    exit 1
}

"$probe"
printf 'x86 errno/TLS source-only probe: PASS\n'

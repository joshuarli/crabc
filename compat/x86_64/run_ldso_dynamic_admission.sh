#!/usr/bin/env bash
# Execute bounded x86 loader fixtures and inspect their admitted ELF graphs.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly FIXTURE_DIR="$ROOT_DIR/compat/x86_64"
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: dynamic admission requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$MUSL_LOADER" ]; then
    printf '%s\n' 'ERROR: pinned musl 1.2.6 loader is unavailable' >&2
    exit 2
fi

# Child gates own the byte-level negative mutations and fail on a missed
# rejection. Retain the base graphs so this aggregate binds their execution
# to exact dependency, relocation, and TLS shapes.
mkdir -p "$ROOT_DIR/.work/tmp"
mkdir -p "$ROOT_DIR/.work/logs"
work_dir="$(mktemp -d "$ROOT_DIR/.work/tmp/ldso-dynamic-admission.XXXXXX")"
report_dir="$(mktemp -d "$ROOT_DIR/.work/logs/ldso-dynamic-admission.XXXXXX")"
chmod 755 "$report_dir"
trap 'rm -rf -- "$work_dir"' EXIT
export TMPDIR="$work_dir"

run_fixture() {
    local name="$1" runner="$2"
    shift 2
    local output="$report_dir/$name.log"
    if ! env "$@" bash "$FIXTURE_DIR/$runner" >"$output" 2>&1; then
        printf 'ERROR: %s admission failed\n' "$name" >&2
        cat "$output" >&2
        exit 1
    fi
}

retained_graph_dir() {
    local name="$1" label="$2" line
    line="$(sed -n "s/^retained $label work directory: //p" "$report_dir/$name.log")"
    if [ -z "$line" ] || [ ! -d "$line" ]; then
        printf 'ERROR: %s did not retain its admitted ELF objects\n' "$name" >&2
        exit 1
    fi
    printf '%s\n' "$line"
}

require_needed() {
    local image="$1" expected="$2" actual
    actual="$(readelf -dW "$image" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    if [ "$actual" != "$expected" ]; then
        printf 'ERROR: unexpected DT_NEEDED closure in %s: %s\n' "$image" "$actual" >&2
        exit 1
    fi
}

require_tls() {
    local image="$1" expected="$2" actual=absent
    if readelf -lW "$image" | grep -Eq '^[[:space:]]*TLS[[:space:]]'; then
        actual=present
    fi
    if [ "$actual" != "$expected" ]; then
        printf 'ERROR: unexpected PT_TLS presence in %s\n' "$image" >&2
        exit 1
    fi
}

require_relocations() {
    local image="$1" allowed="$2" actual
    actual="$(readelf -rW "$image" | awk '/R_X86_64_/ { print $3 }' | LC_ALL=C sort -u | paste -sd, -)"
    if [ "$actual" != "$allowed" ]; then
        printf 'ERROR: unexpected relocation set in %s: %s\n' "$image" "$actual" >&2
        exit 1
    fi
}

require_interpreter() {
    local image="$1" expected="$2" actual
    actual="$(readelf -lW "$image" | sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p')"
    if [ "$actual" != "$expected" ]; then
        printf 'ERROR: unexpected PT_INTERP in %s: %s\n' "$image" "$actual" >&2
        exit 1
    fi
}

replay_graph() {
    local name="$1" dir="$2" mid="$3" leaf="$4" tls="$5"
    local image basename
    for image in "$dir/main-musl" "$dir/main-crabc" "$dir/$mid" "$dir/$leaf"; do
        basename="$(basename "$image")"
        readelf -hW -lW -dW -rW --dyn-syms "$image" >"$report_dir/$name.$basename.elf.txt"
    done
    require_interpreter "$dir/main-musl" "$MUSL_LOADER"
    require_interpreter "$dir/main-crabc" "$dir/ld-crabc-x86_64-$name.so"
    require_needed "$dir/main-musl" "$mid"
    require_needed "$dir/main-crabc" "$mid"
    require_needed "$dir/$mid" "$leaf"
    require_needed "$dir/$leaf" ''
    require_tls "$dir/main-crabc" absent
    require_tls "$dir/$mid" "$tls"
    require_tls "$dir/$leaf" "$tls"
    if [ "$name" = initial-graph ]; then
        require_relocations "$dir/main-crabc" 'R_X86_64_JUMP_SLOT,R_X86_64_RELATIVE'
        require_relocations "$dir/$mid" 'R_X86_64_GLOB_DAT,R_X86_64_JUMP_SLOT,R_X86_64_RELATIVE'
        require_relocations "$dir/$leaf" 'R_X86_64_GLOB_DAT'
    else
        local relocations
        relocations="$(readelf -rW "$dir/main-crabc" "$dir/$mid" "$dir/$leaf")"
        for kind in R_X86_64_DTPMOD64 R_X86_64_DTPOFF64; do
            if ! grep -Fq "$kind" <<<"$relocations"; then
                printf 'ERROR: TLS graph has no %s relocation\n' "$kind" >&2
                exit 1
            fi
        done
        if grep -Fq R_X86_64_TPOFF64 <<<"$relocations"; then
            printf '%s\n' 'ERROR: GNU-Dynamic TLS graph selected initial-exec relocation' >&2
            exit 1
        fi
    fi
    (cd "$dir" && env -i PATH=/usr/bin:/bin CRABC_EXECUTION_MODE=native "$dir/main-musl") >"$report_dir/$name.musl.replay.log" 2>&1
    (cd "$dir" && env -i PATH=/usr/bin:/bin CRABC_EXECUTION_MODE=native "$dir/main-crabc") >"$report_dir/$name.crabc.replay.log" 2>&1
}

require_unreadable_phdr_rejection() {
    local dir="$1" image status
    image="$dir/libmid.so"
    cp "$image" "$dir/libmid-readable.so"
    python3 - "$image" <<'PY'
import struct
import sys

image = sys.argv[1]
data = bytearray(open(image, "rb").read())
if data[:6] != b"\x7fELF\x02\x01":
    raise SystemExit("mid fixture is not little-endian ELF64")
phoff = struct.unpack_from("<Q", data, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", data, 54)
if phentsize != 56 or phoff + phentsize * phnum > len(data):
    raise SystemExit("mid fixture has no complete program-header table")
matches = []
for index in range(phnum):
    offset = phoff + index * phentsize
    kind, flags = struct.unpack_from("<II", data, offset)
    file_offset, file_size = struct.unpack_from("<QQ", data, offset + 8)[0], struct.unpack_from("<Q", data, offset + 32)[0]
    if kind == 1 and file_offset <= phoff and phoff + phentsize * phnum <= file_offset + file_size:
        matches.append((offset, flags))
if len(matches) != 1 or matches[0][1] & 4 == 0:
    raise SystemExit("mid fixture lacks one readable PHDR-bearing PT_LOAD")
offset, flags = matches[0]
struct.pack_into("<I", data, offset + 4, flags & ~4)
with open(image, "wb") as output:
    output.write(data)
PY
    cp "$image" "$report_dir/initial-graph.unreadable-phdr.libmid.so"
    readelf -hW -lW -dW -rW "$image" >"$report_dir/initial-graph.unreadable-phdr.elf.txt"
    if (cd "$dir" && ulimit -c 0 && env -i PATH=/usr/bin:/bin CRABC_EXECUTION_MODE=native "$dir/main-crabc") \
        >"$report_dir/initial-graph.unreadable-phdr.launch.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    cp "$dir/libmid-readable.so" "$image"
    rm "$dir/libmid-readable.so"
    printf 'candidate unreadable PHDR launch status: %s\n' "$status" \
        >>"$report_dir/initial-graph.unreadable-phdr.launch.log"
    if [ "$status" -ne 127 ] || ! grep -Fq midmap "$report_dir/initial-graph.unreadable-phdr.launch.log"; then
        printf 'ERROR: unreadable PHDR-bearing PT_LOAD did not fail as a loader error (status %s); raw: %s\n' \
            "$status" "$report_dir/initial-graph.unreadable-phdr.launch.log" >&2
        cat "$report_dir/initial-graph.unreadable-phdr.launch.log" >&2
        exit 1
    fi
}

run_fixture graph run_ldso_initial_graph.sh CRABC_LDSO_INITIAL_GRAPH_KEEP_WORK=1
graph_dir="$(retained_graph_dir graph initial-graph)"
replay_graph initial-graph "$graph_dir" libmid.so libleaf.so absent
require_unreadable_phdr_rejection "$graph_dir"

run_fixture tls run_ldso_initial_tls.sh CRABC_LDSO_INITIAL_TLS_KEEP_WORK=1
tls_dir="$(retained_graph_dir tls initial-TLS)"
replay_graph initial-tls "$tls_dir" libmid-tls.so libleaf-tls.so present

run_fixture handoff run_ldso_owned_crt_handoff.sh
run_fixture introspection run_ldso_fixed_graph_introspection.sh
run_fixture dlfcn run_ldso_fixed_graph_dlfcn.sh
run_fixture public-dlfcn run_ldso_public_dlfcn.sh
run_fixture dladdr run_ldso_dladdr_symbol_bounds.sh
run_fixture bounded-dlopen run_ldso_bounded_dlopen.sh

rm -rf -- "$graph_dir" "$tls_dir"
printf 'admission raw evidence: %s\n' "$report_dir"
printf '%s\n' 'x86 dynamic-loader staged admission inventory: PASS'

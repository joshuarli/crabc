#!/usr/bin/env bash
# Direct-loader regression for the selected product's initial libc identity.
set -Eeu -o pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
case "$installed" in "$ROOT"/.work/*) ;; *) exit 2;; esac
[ -d "$installed" ] && [ ! -L "$installed" ] || exit 2
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/owned-loader-libc-identity.XXXXXX")"
chmod 755 "$work"
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly source="$work/identity.c"
readonly expected_stderr="$work/expected-libcidentity.stderr"
readonly receipt_runner=owned-loader-libc-identity

source_seal() {
    python3 -B - "$ROOT" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from native_shadow_receipt import source_seal
print(json.dumps(source_seal(root), sort_keys=True, separators=(',', ':')))
PY
}

rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
receipt_cases=()
receipt_products=()
allocator_backend=unknown
canonical_receipt=no
source_before="$(source_seal)"
publish_receipt() {
    local status=$?
    trap - EXIT
    local source_after=''
    if ! source_after="$(source_seal)" || [ "$source_after" != "$source_before" ]; then
        printf 'owned loader libc identity: source changed during the run\n' >&2
        status=1
    fi
    printf '%s\n' "$status" >"$work/runner.status"
    receipt_cases+=("runner=$status:runner.status")
    local -a arguments=(--runner "$receipt_runner" --work "$work" --canonical "$canonical_receipt"
        --parameter "ALLOCATOR_BACKEND=$allocator_backend"
        --parameter 'MODES=pie,non-pie'
        --parameter 'ENTRY=direct-copied-interpreter'
        --parameter 'IDENTITY_FAILURE_STATUS=127')
    local entry
    for entry in "${receipt_cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${receipt_products[@]}"; do arguments+=(--product "$entry"); done
    if ! python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}"; then
        status=1
    elif [ "$(source_seal)" != "$source_before" ]; then
        rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
        printf 'owned loader libc identity: source changed while publishing the receipt\n' >&2
        status=1
    fi
    exit "$status"
}
trap publish_receipt EXIT

trap 'printf "owned loader libc identity FAIL mode=%s case=%s; evidence: %s\n" "${mode:-setup}" "${case_name:-setup}" "$work" >&2' ERR

allocator_backend="$(python3 -B - "$installed/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as stream:
    print(json.load(stream)['allocator_backend'])
PY
)"
[ "$allocator_backend" != native-shadow ] || canonical_receipt=yes
receipt_products+=(
    "dynamic-manifest=$installed/share/crabc/manifest.json"
    "dynamic-product-state=$installed/share/crabc/dynamic-product-state.json"
    "dynamic-libc-provenance=$installed/share/crabc/libc-shared.provenance.json"
    "dynamic-loader-provenance=$installed/share/crabc/loader.provenance.json"
    "dynamic-libc=$installed/usr/lib/libc.so"
    "dynamic-loader=$installed/lib/ld-crabc-x86_64.so.1"
    "dynamic-driver=$driver"
    "identity-source=$source"
)

cat >"$source" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#ifdef IDENTITY_DSO
int cli_value(void) { return 17; }
__attribute__((constructor)) static void identity_dependency_constructor(void)
{
    puts("identity dependency constructor");
}
#else
extern int cli_value(void);
__attribute__((constructor)) static void identity_application_constructor(void)
{
    puts("identity application constructor");
}
int main(void)
{
    Dl_info libc = {0};
    void *puts_address = dlsym(RTLD_DEFAULT, "puts");
    if (!puts_address || !dladdr(puts_address, &libc) || !libc.dli_fname) return 92;
    if (cli_value() != 17) return 91;
    printf("identity libc %s\n", libc.dli_fname);
    puts("identity application main 17");
    return 0;
}
#endif
C
printf 'libcidentity\n' >"$expected_stderr"

prepare_root() {
    local root="$1"
    cp -a "$installed/." "$root/"
    mkdir -p "$root/plugins" "$root/p" "$root/override" \
        "$root/prefix/lib" "$root/prefix/usr/lib"
    cp "$root/lib/ld-crabc-x86_64.so.1" "$root/prefix/lib/loader"
}

root_aliases() {
    local root="$1"
    rm -f "$root/lib/libc.musl-x86_64.so.1"
    ln "$root/usr/lib/libc.so" "$root/lib/libc.musl-x86_64.so.1"
}

prefix_aliases_copy() {
    local root="$1"
    cp "$root/usr/lib/libc.so" "$root/prefix/usr/lib/libc.so"
    ln "$root/prefix/usr/lib/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
}

prefix_aliases_hardlink() {
    local root="$1"
    ln "$root/usr/lib/libc.so" "$root/prefix/usr/lib/libc.so"
    ln "$root/usr/lib/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
}

assert_needed() {
    local binary="$1" expected="$2" label="$3"
    local dynamic="$work/$mode-$case_name-$label.dynamic"
    readelf -dW "$binary" >"$dynamic"
    [ "$(grep -Fc "Shared library: [$expected]" "$dynamic")" -eq 1 ]
}

assert_runpath() {
    local binary="$1" expected="$2" label="$3"
    local dynamic="$work/$mode-$case_name-$label.runpath.dynamic"
    readelf -dW "$binary" >"$dynamic"
    [ "$(grep -Fc "Library runpath: [$expected]" "$dynamic")" -eq 1 ]
}

build_consumer() {
    local root="$1" library_search_path="$2" consumer_search_path="$3"
    "$driver" --dynamic-shared-object -DIDENTITY_DSO --application-runpath "$library_search_path" \
        "$source" -o "$root/plugins/libcli.so"
    "$driver" "--dynamic-$mode" --application-runpath "$consumer_search_path" \
        "$source" --application-dso "$root/plugins/libcli.so" -o "$root/consumer"
    assert_needed "$root/plugins/libcli.so" libc.so library
    assert_needed "$root/consumer" libcli.so consumer
    assert_needed "$root/consumer" libc.so consumer
    assert_runpath "$root/plugins/libcli.so" "$library_search_path" library
    assert_runpath "$root/consumer" "$consumer_search_path" consumer
}

mutate_cli_needed_to_second_libc() {
    local root="$1"
    python3 -B - "$root/consumer" "$root/consumer-mutated" <<'PYTHON'
from pathlib import Path
import struct
import sys

source, output = map(Path, sys.argv[1:])
image = bytearray(source.read_bytes())
assert image[:6] == b"\x7fELF\x02\x01"
phoff = struct.unpack_from("<Q", image, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", image, 54)
loads = []
dynamic = None
for index in range(phnum):
    at = phoff + index * phentsize
    kind, _, offset, address, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", image, at)
    if kind == 1:
        loads.append((address, offset, filesz))
    elif kind == 2:
        assert dynamic is None
        dynamic = (offset, filesz)
assert dynamic is not None
entries = [struct.unpack_from("<QQ", image, at) for at in range(dynamic[0], dynamic[0] + dynamic[1], 16)]
strtab = next(value for tag, value in entries if tag == 5)
strfile = next(offset + strtab - address for address, offset, size in loads if address <= strtab < address + size)
needed = [strfile + value for tag, value in entries if tag == 1]
names = [image[offset:image.index(0, offset)].decode("ascii") for offset in needed]
assert names.count("libcli.so") == 1 and names.count("libc.so") == 1
at = needed[names.index("libcli.so")]
assert image[at:at + 10] == b"libcli.so\0"
image[at:at + 10] = b"p/libc.so\0"
output.write_bytes(image)
output.chmod(0o755)
PYTHON
    assert_needed "$root/consumer-mutated" p/libc.so mutated
    assert_needed "$root/consumer-mutated" libc.so mutated
}

assert_same_identity() {
    [ "$1" -ef "$2" ]
}

assert_distinct_identity() {
    [ ! "$1" -ef "$2" ]
}

record_case_evidence() {
    local root="$1" program="$2" expected="$3"
    local id="$mode-$case_name" relative entry
    local -a paths=(
        prefix/lib/loader usr/lib/libc.so lib/libc.musl-x86_64.so.1
        prefix/usr/lib/libc.so prefix/lib/libc.musl-x86_64.so.1
        p/libc.so override/libc.so consumer consumer-mutated plugins/libcli.so
    )
    local -a logs=("$id.stdout" "$id.stderr" "$id.status" "$id.identity" "$(basename "$expected")")
    : >"$work/$id.identity"
    for relative in "${paths[@]}"; do
        [ -f "$root/$relative" ] || continue
        stat -Lc '%n dev=%d inode=%i size=%s' "$root/$relative" >>"$work/$id.identity"
        entry="${relative//\//-}"
        receipt_products+=("$id-$entry=$root/$relative")
    done
    for entry in "$work/$id-"*.dynamic; do
        [ -f "$entry" ] && logs+=("$(basename "$entry")")
    done
    [ -f "$root${program}" ]
    entry="${program#/}"
    receipt_products+=("$id-executed-program=$root${program}")
    receipt_cases+=("$id=0:$(IFS=,; printf '%s' "${logs[*]}")")
}

run_success() {
    local root="$1" program="$2" expected_libc="$3"
    local stdout="$work/$mode-$case_name.stdout" stderr="$work/$mode-$case_name.stderr"
    local expected="$work/$mode-$case_name.expected.stdout"
    local status=0
    printf '%s\n' \
        'identity dependency constructor' \
        'identity application constructor' \
        "identity libc $expected_libc" \
        'identity application main 17' >"$expected"
    timeout 20 chroot "$root" /prefix/lib/loader "$program" >"$stdout" 2>"$stderr" || status=$?
    printf '%s\n' "$status" >"$work/$mode-$case_name.status"
    record_case_evidence "$root" "$program" "$expected"
    [ "$status" -eq 0 ]
    cmp "$expected" "$stdout"
    [ ! -s "$stderr" ]
}

run_identity_failure() {
    local root="$1" program="$2"
    local stdout="$work/$mode-$case_name.stdout" stderr="$work/$mode-$case_name.stderr"
    local status=0
    timeout 20 chroot "$root" /prefix/lib/loader "$program" >"$stdout" 2>"$stderr" || status=$?
    printf '%s\n' "$status" >"$work/$mode-$case_name.status"
    record_case_evidence "$root" "$program" "$expected_stderr"
    [ "$status" -eq 127 ]
    [ ! -s "$stdout" ]
    cmp "$expected_stderr" "$stderr"
}

for mode in pie non-pie; do
    case_name=copied-prefix-root-libc
    root="$work/$mode-$case_name"
    prepare_root "$root"
    root_aliases "$root"
    build_consumer "$root" /usr/lib '$ORIGIN/plugins:/usr/lib'
    assert_same_identity "$root/usr/lib/libc.so" "$root/lib/libc.musl-x86_64.so.1"
    run_success "$root" /consumer /usr/lib/libc.so

    case_name=prefix-only-libc
    root="$work/$mode-$case_name"
    prepare_root "$root"
    root_aliases "$root"
    prefix_aliases_copy "$root"
    build_consumer "$root" /prefix/usr/lib:/usr/lib '$ORIGIN/plugins:/prefix/usr/lib:/usr/lib'
    assert_distinct_identity "$root/usr/lib/libc.so" "$root/prefix/usr/lib/libc.so"
    run_success "$root" /consumer /prefix/usr/lib/libc.so

    case_name=hardlink-one-identity
    root="$work/$mode-$case_name"
    prepare_root "$root"
    root_aliases "$root"
    prefix_aliases_hardlink "$root"
    build_consumer "$root" /usr/lib '$ORIGIN/plugins:/usr/lib'
    assert_same_identity "$root/usr/lib/libc.so" "$root/lib/libc.musl-x86_64.so.1"
    assert_same_identity "$root/usr/lib/libc.so" "$root/prefix/usr/lib/libc.so"
    assert_same_identity "$root/usr/lib/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
    run_success "$root" /consumer /usr/lib/libc.so

    case_name=two-distinct-libc-identities
    root="$work/$mode-$case_name"
    prepare_root "$root"
    root_aliases "$root"
    prefix_aliases_copy "$root"
    build_consumer "$root" /usr/lib '$ORIGIN/plugins:/usr/lib'
    cp "$root/prefix/usr/lib/libc.so" "$root/p/libc.so"
    rm "$root/prefix/usr/lib/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
    ln "$root/p/libc.so" "$root/prefix/usr/lib/libc.so"
    ln "$root/p/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
    assert_distinct_identity "$root/usr/lib/libc.so" "$root/p/libc.so"
    assert_same_identity "$root/p/libc.so" "$root/prefix/usr/lib/libc.so"
    assert_same_identity "$root/p/libc.so" "$root/prefix/lib/libc.musl-x86_64.so.1"
    mutate_cli_needed_to_second_libc "$root"
    run_identity_failure "$root" /consumer-mutated

    case_name=override-without-canonical-identity
    root="$work/$mode-$case_name"
    prepare_root "$root"
    root_aliases "$root"
    cp "$root/usr/lib/libc.so" "$root/override/libc.so"
    assert_distinct_identity "$root/usr/lib/libc.so" "$root/override/libc.so"
    build_consumer "$root" /override '$ORIGIN/plugins:/override:/usr/lib'
    run_identity_failure "$root" /consumer
done

# musl does not have this private selected-product identity guard. The positive
# output is therefore fixed by this source fixture; candidate-only negative
# layouts prove that the owned loader rejects before either constructor runs.
printf 'owned loader libc identity: PASS (5 cases across PIE and non-PIE); evidence: %s\n' "$work"

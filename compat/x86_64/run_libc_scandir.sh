#!/usr/bin/env bash
# Native Linux/x86-64 opt-in crabc-libc scandir evidence.
#
# This is deliberately a mixed-runtime differential. The candidate owns the
# feature-gated scandir allocation client plus its selected directory, qsort,
# errno, and C allocator boundaries. Pinned musl still supplies startup and
# process prerequisites outside the staged x86 runtime, but none of its
# scandir, directory, sort, or allocator objects may enter the candidate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 libc scandir: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        sort -u
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_dirent_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-scandir.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-scandir.a"
reference="$work_dir/pinned-musl-scandir-reference"
candidate="$work_dir/crabc-scandir-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_members_dir="$work_dir/selected-members"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_scandir_disassembly="$work_dir/candidate-scandir-disassembly"
candidate_allocator_thunks="$work_dir/candidate-allocator-thunks"
allocation_wrap_flags=(
    -Wl,--wrap=malloc
    -Wl,--wrap=realloc
    -Wl,--wrap=free
)

mkdir "$reference_work" "$candidate_work"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_scandir_probe.c >/dev/null 2>"$header_trace"
for header in dirent.h errno.h fcntl.h stdint.h stdlib.h sys/stat.h \
    sys/syscall.h sys/types.h bits/alltypes.h bits/fcntl.h bits/stat.h \
    bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SCANDIR_ALLOCATION_WRAP \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    "${allocation_wrap_flags[@]}" \
    -I"$ROOT_DIR/include" compat/x86_64/libc_scandir_probe.c -o "$reference"
if (cd "$reference_work" && env -i LC_ALL=C TZ=UTC "$reference"); then
    :
else
    reference_status=$?
    fail "pinned-musl scandir reference exited $reference_status"
fi

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-scandir --target x86_64-unknown-linux-musl -- \
    -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
    -C overflow-checks=off -C debug-assertions=off \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the opt-in x86 libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
for symbol in __crabc_x86_scandir_v1 scandir malloc realloc free; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "feature archive does not define $symbol"
done
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "scandir" { found = 1 }
     END { exit(found ? 0 : 1) }' "$archive_elf_symbols" \
    || fail "feature archive scandir is not a strong global function"
for symbol in malloc realloc free; do
    thunk="__crabc_x86_scandir_cabi_${symbol}"
    awk -v thunk="$thunk" '
        $4 == "FUNC" && $5 == "GLOBAL" && $6 == "HIDDEN" && $8 == thunk {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$archive_elf_symbols" \
        || fail "feature archive does not retain hidden C ABI thunk $thunk"
done

mapfile -t scandir_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_scandir_v1
)
mapfile -t directory_members < <(archive_member_for_symbol "$archive" opendir)
mapfile -t qsort_members < <(archive_member_for_symbol "$archive" qsort)
mapfile -t byte_string_members < <(archive_member_for_symbol "$archive" strverscmp)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(archive_member_for_symbol "$archive" __errno_location)
mapfile -t backend_members < <(ar t "$archive" | grep -- '-static\.o$')
[ "${#scandir_members[@]}" -eq 1 ] \
    || fail "scandir boundary must have exactly one archive member owner"
[ "${#directory_members[@]}" -eq 1 ] \
    || fail "directory boundary must have exactly one archive member owner"
[ "${#qsort_members[@]}" -eq 1 ] \
    || fail "qsort boundary must have exactly one archive member owner"
[ "${#byte_string_members[@]}" -eq 1 ] \
    || fail "byte-string boundary must have exactly one archive member owner"
[ "${#allocator_members[@]}" -eq 1 ] \
    || fail "allocator boundary must have exactly one archive member owner"
[ "${#errno_members[@]}" -eq 1 ] \
    || fail "errno boundary must have exactly one archive member owner"
[ "${scandir_members[0]}" = "${directory_members[0]}" ] \
    || fail "scandir must remain colocated with the private directory owner"
[ "${#backend_members[@]}" -eq 1 ] \
    || fail "allocator backend must have exactly one bundled static object"

mapfile -t selected_members < <(
    printf '%s\n' "${scandir_members[@]}" "${qsort_members[@]}" \
        "${byte_string_members[@]}" \
        "${allocator_members[@]}" "${errno_members[@]}" "${backend_members[@]}" |
        sort -u
)
mkdir "$selected_members_dir"
(
    cd "$selected_members_dir"
    ar x "$archive" "${selected_members[@]}"
    ar crs "$selected_archive" "${selected_members[@]}"
)
if [ "$(ar t "$selected_archive" | sort)" != \
    "$(printf '%s\n' "${selected_members[@]}" | sort)" ]; then
    fail "selected archive member set drifted during extraction"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SCANDIR_CANDIDATE \
    -DCRABC_SCANDIR_ALLOCATION_WRAP \
    -I"$ROOT_DIR/include" -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector "${allocation_wrap_flags[@]}" -Wl,-Map,"$link_map" \
    compat/x86_64/libc_scandir_probe.c "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=scandir "$candidate" >"$candidate_scandir_disassembly"
: >"$candidate_allocator_thunks"
for symbol in malloc realloc free; do
    objdump -d --disassemble="__crabc_x86_scandir_cabi_${symbol}" \
        "$candidate" >>"$candidate_allocator_thunks"
done

for symbol in __crabc_x86_scandir_v1 scandir opendir closedir readdir qsort \
    malloc realloc free; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks crabc scandir dependency $symbol"
done
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "scandir" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" \
    || fail "candidate scandir is not a strong global function"
awk '$4 == "FUNC" && $5 == "WEAK" && $8 == "malloc" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" \
    || fail "candidate malloc lost the selected weak binding"
for symbol in malloc realloc free; do
    grep -Fq "<__crabc_x86_scandir_cabi_${symbol}>" \
        "$candidate_scandir_disassembly" \
        || fail "candidate scandir bypassed C ABI thunk for $symbol"
    grep -Fq "__wrap_${symbol}" "$candidate_allocator_thunks" \
        || fail "candidate C ABI thunk did not reach wrapped $symbol"
done
if grep -Eq 'mi_(malloc|realloc|free)' "$candidate_scandir_disassembly"; then
    fail "candidate scandir calls allocator backend internals directly"
fi
for musl_member in \
    scandir.lo scandir64.lo opendir.lo fdopendir.lo closedir.lo dirfd.lo \
    readdir.lo readdir64.lo readdir_r.lo rewinddir.lo seekdir.lo telldir.lo \
    alphasort.lo versionsort.lo getdents.lo posix_getdents.lo fstat.lo \
    qsort.lo qsort_nr.lo qsort_r.lo strverscmp.lo \
    aligned_alloc.lo calloc.lo free.lo malloc.lo memalign.lo posix_memalign.lo \
    realloc.lo reallocarray.lo valloc.lo libc_calloc.lo lite_malloc.lo \
    malloc_usable_size.lo replaced.lo donate.lo; do
    if grep -Fq "libc.a($musl_member)" "$link_map"; then
        fail "candidate selected pinned-musl fallback object $musl_member"
    fi
done
for selected_member in "${selected_members[@]}"; do
    grep -Fq "$selected_archive($selected_member)" "$link_map" \
        || fail "candidate did not select required crabc archive member $selected_member"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks static TLS"
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' \
    "$candidate_program_headers" "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi

if (cd "$candidate_work" && env -i LC_ALL=C TZ=UTC "$candidate"); then
    :
else
    candidate_status=$?
    fail "crabc scandir candidate exited $candidate_status"
fi

printf 'x86 libc scandir: PASS\n'

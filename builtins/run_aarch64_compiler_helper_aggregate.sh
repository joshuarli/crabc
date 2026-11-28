#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-aarch64-musl-gcc
readonly BUILDER="${ROOT_DIR}/builtins/build.py"
readonly CONTRACT="${ROOT_DIR}/builtins/fixtures/aarch64_compiler_helper_imports.txt"
readonly READER="${ROOT_DIR}/compat/x86_64/compiler_helper_evidence.py"
readonly PROBE="${ROOT_DIR}/builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c"
readonly START="${ROOT_DIR}/builtins/fixtures/aarch64_compiler_helper_aggregate_start.S"
readonly WORK_DIR="${CRABC_COMPILER_HELPER_WORK_DIR:-${ROOT_DIR}/.work/aarch64/compiler-helper-aggregate}"
readonly TRANSCRIPT='compiler-helper-aggregate-ok'
readonly IMAGE_ID="${CRABC_X86_COMPILER_HELPER_IMAGE:-}"

fail() { printf 'ERROR: native compiler-helper aggregate: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in aarch64) ;; *) fail "refuses emulation on $(uname -m)";; esac
for tool in env grep nm objdump python3 readelf; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned arm musl compiler wrapper"
[[ "$IMAGE_ID" =~ ^crabc-core-evidence@sha256:[0-9a-f]{64}$ ]] || fail "missing pinned image identity"
for input in "$BUILDER" "$CONTRACT" "$READER" "$PROBE" "$START"; do [ -f "$input" ] || fail "missing input $input"; done
case "$WORK_DIR" in "$ROOT_DIR"/.work/aarch64/*) ;; *) fail "work directory must stay below checkout .work/aarch64";; esac
[ ! -e "$WORK_DIR" ] || fail "work directory must be fresh: $WORK_DIR"
mkdir -p "$WORK_DIR/raw"

archive="$WORK_DIR/libcrabc-builtins.a"
provenance="$WORK_DIR/libcrabc-builtins.a.provenance.json"
object="$WORK_DIR/aggregate.o"
start_object="$WORK_DIR/aggregate-start.o"
without="$WORK_DIR/without-archive"
candidate="$WORK_DIR/candidate"
reference_object="$WORK_DIR/pinned-musl-reference.o"
reference="$WORK_DIR/pinned-musl-reference"
events="$WORK_DIR/commands.json"
source_before="$WORK_DIR/source-before.json"
oracle_record="$WORK_DIR/oracle-compiler.json"
report="$WORK_DIR/report.json"

record_command() {
    local label="$1"
    shift
    local stdout="$WORK_DIR/raw/${label}.stdout"
    local stderr="$WORK_DIR/raw/${label}.stderr"
    local status
    local -a inputs=()
    local -a input_arguments=()
    case "$label" in
        builder|candidate-compile|start-compile|reference-compile) ;;
        candidate-imports) inputs=("$object") ;;
        archive-free-link) inputs=("$start_object" "$object") ;;
        candidate-link) inputs=("$start_object" "$object" "$archive") ;;
        candidate-definitions|candidate-undefined|candidate-header|candidate-program-headers|candidate-dynamic|candidate-disassembly|candidate-execute)
            inputs=("$candidate") ;;
        reference-link) inputs=("$reference_object") ;;
        reference-execute) inputs=("$reference") ;;
        *) fail "unknown command label $label" ;;
    esac
    for input in "${inputs[@]}"; do
        input_arguments+=(--input "$input")
    done
    set +e
    "$@" >"$stdout" 2>"$stderr"
    status=$?
    set -e
    python3 "$READER" append-command --work "$WORK_DIR" --events "$events" \
        --label "$label" --status "$status" --stdout "$stdout" --stderr "$stderr" \
        "${input_arguments[@]}" -- "$@" >/dev/null
    return "$status"
}

python3 "$READER" capture-oracle-compiler --work "$WORK_DIR" --output "$oracle_record" \
    --compiler "$ORACLE_CC" >/dev/null
python3 "$READER" capture-source --output "$source_before" >/dev/null
tools_dir="$(python3 -B -c 'import sys; sys.path.insert(0,"compat/x86_64"); import owned_posix_product_evidence as p; print(p.source_native_compiler_tool_records()["rustc"]["sysroot"])')/lib/rustlib/aarch64-unknown-linux-musl/bin"
record_command builder python3 "$BUILDER" --output "$archive" --llvm-ar "$tools_dir/llvm-ar" --llvm-nm "$tools_dir/llvm-nm" --llvm-readelf /usr/bin/readelf --ld-lld /usr/bin/mold --verify-reproducible --provenance "$provenance"
python3 - "$CONTRACT" "$provenance" <<'PY'
import json, sys
names = open(sys.argv[1], encoding='utf-8').read().splitlines()
record = json.load(open(sys.argv[2], encoding='utf-8'))
archive = record['archive']
if (record['component']['target'] != 'aarch64-unknown-linux-musl'
        or archive['members'] != ['crabc-builtins.o']
        or not set(names) <= set(archive['defined_symbols'])
        or archive['undefined_symbols'] or record['build']['reproducible'] is not True):
    raise SystemExit('arm compiler helper archive provenance differs')
PY

record_command candidate-compile env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -std=c11 -O2 -fno-builtin \
    -Wno-builtin-declaration-mismatch -fno-stack-protector -fno-asynchronous-unwind-tables \
    -fno-unwind-tables -ffreestanding -fno-pic -fno-pie -DCRABC_BUILTINS_FREESTANDING \
    -c "$PROBE" -o "$object"
record_command start-compile env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -c "$START" -o "$start_object"
record_command candidate-imports nm --undefined-only "$object"
python3 - "$CONTRACT" "$WORK_DIR/raw/candidate-imports.stdout" <<'PY'
import sys
names = open(sys.argv[1], encoding="utf-8").read().splitlines()
imports = {line.split()[-1] for line in open(sys.argv[2], encoding='utf-8') if line.split()}
if imports != set(names):
    raise SystemExit('aggregate C object import roster differs')
PY
if record_command archive-free-link env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -nostdlib -static -no-pie -Wl,--build-id=none \
    -Wl,--no-undefined -Wl,-e,_start "$start_object" "$object" -o "$without"; then
    fail "archive-free aggregate link unexpectedly succeeded"
fi
python3 - "$CONTRACT" "$WORK_DIR/raw/archive-free-link.stderr" <<'PY'
import sys
names = open(sys.argv[1], encoding="utf-8").read().splitlines()
log = open(sys.argv[2], encoding='utf-8', errors='replace').read()
missing = [name for name in names if name not in log]
if missing:
    raise SystemExit('archive-free failure did not name intended helper(s): ' + ', '.join(missing))
PY
record_command candidate-link env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -nostdlib -static -no-pie -Wl,--build-id=none \
    -Wl,--no-undefined -Wl,-e,_start -Wl,--trace "$start_object" "$object" "$archive" -o "$candidate"
if grep -Eq 'libgcc|compiler-rt|libc\.a|/[Sr]?crt[^/[:space:]]*\.o' "$WORK_DIR/raw/candidate-link.stdout"; then
    fail "candidate link admitted an ambient CRT or compiler runtime"
fi
record_command candidate-definitions nm --defined-only "$candidate"
record_command candidate-undefined nm --undefined-only "$candidate"
record_command candidate-header readelf -hW "$candidate"
record_command candidate-program-headers readelf -lW "$candidate"
record_command candidate-dynamic readelf -dW "$candidate"
record_command candidate-disassembly objdump --disassemble "$candidate"
python3 - "$CONTRACT" "$WORK_DIR/raw/candidate-definitions.stdout" "$WORK_DIR/raw/candidate-disassembly.stdout" <<'PY'
import re, sys
names = open(sys.argv[1], encoding="utf-8").read().splitlines()
addresses = {}
for line in open(sys.argv[2], encoding='utf-8'):
    fields = line.split()
    if len(fields) == 3:
        addresses[fields[2]] = int(fields[0], 16)
missing = sorted(set(names) - addresses.keys())
if missing:
    raise SystemExit('candidate did not retain helper(s): ' + ', '.join(missing))
text = open(sys.argv[3], encoding='utf-8', errors='replace').read()
targets = {int(match.group(1), 16) for match in re.finditer(r'\bbl?\s+([0-9a-f]+)\s+<', text)}
missing = [name for name in names if addresses[name] not in targets]
if missing:
    raise SystemExit('candidate has no direct transfer to helper(s): ' + ', '.join(missing))
PY
readelf -hW "$candidate" | grep -F 'Type:                              EXEC (Executable file)' >/dev/null || fail "candidate is not ET_EXEC"
readelf -lW "$candidate" | grep -E 'INTERP| TLS ' >/dev/null && fail "candidate has an interpreter or TLS"
if readelf -dW "$candidate" | grep -E '\((NEEDED|JMPREL|PLTGOT)\)' >/dev/null; then
    fail "candidate has dynamic linkage"
fi
if awk '$NF != "_PROCEDURE_LINKAGE_TABLE_" && $NF != "__rela_iplt_start" && $NF != "__rela_iplt_end" { found = 1 } END { exit !found }' \
    "$WORK_DIR/raw/candidate-undefined.stdout"; then
    fail "candidate retains an undefined symbol"
fi

record_command reference-compile env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -std=c11 -O2 -fno-stack-protector -fno-pie \
    -DCRABC_HELPER_REFERENCE -c "$PROBE" -o "$reference_object"
record_command reference-link env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -no-pie "$reference_object" -o "$reference"
record_command reference-execute "$reference"
record_command candidate-execute "$candidate"
printf '%s\n' "$TRANSCRIPT" >"$WORK_DIR/expected.stdout"
cmp "$WORK_DIR/expected.stdout" "$WORK_DIR/raw/reference-execute.stdout"
cmp "$WORK_DIR/expected.stdout" "$WORK_DIR/raw/candidate-execute.stdout"

python3 "$READER" write-aggregate-report --work "$WORK_DIR" --source-before "$source_before" \
    --events "$events" --output "$report" --image "$IMAGE_ID" --source-mount /workspace \
    --oracle-record "$oracle_record" >/dev/null
python3 "$READER" validate-aggregate-report "$report" >/dev/null
printf 'native arm64 compiler-helper aggregate: PASS (%s)\n' "$report"

#!/usr/bin/env bash
# Bounded native x86-64 archive proof for the exact compiler-helper roster.
#
# The candidate has one C object with explicit imports of all 23 helpers and
# links it only with a fresh Rust-owned archive. The separate pinned-musl C
# reference compiles the same fixed cases through arithmetic/overflow/bit-loop
# alternatives. It is an oracle object, not the candidate object.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly BUILDER="${ROOT_DIR}/builtins/build_x86_64.py"
readonly CONTRACT="${ROOT_DIR}/builtins/x86_64-helper-contract.toml"
readonly READER="${ROOT_DIR}/compat/x86_64/compiler_helper_evidence.py"
readonly PROBE="${ROOT_DIR}/builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c"
readonly START="${ROOT_DIR}/builtins/fixtures/x86_64_compiler_helper_aggregate_start.S"
readonly WORK_DIR="${CRABC_COMPILER_HELPER_WORK_DIR:-${ROOT_DIR}/.work/x86_64/compiler-helper-aggregate}"
readonly TRANSCRIPT='compiler-helper-aggregate-ok'
readonly IMAGE_ID="${CRABC_X86_COMPILER_HELPER_IMAGE:-}"

fail() { printf 'ERROR: native compiler-helper aggregate: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)";; esac
for tool in env grep nm objdump python3 readelf; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned x86 musl compiler wrapper"
[[ "$IMAGE_ID" =~ ^crabc-core-evidence@sha256:[0-9a-f]{64}$ ]] || fail "missing pinned image identity"
for input in "$BUILDER" "$CONTRACT" "$READER" "$PROBE" "$START"; do [ -f "$input" ] || fail "missing input $input"; done
case "$WORK_DIR" in "$ROOT_DIR"/.work/x86_64/*) ;; *) fail "work directory must stay below checkout .work/x86_64";; esac
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
record_command builder python3 "$BUILDER" --output "$archive" --provenance "$provenance" --verify-reproducible
python3 - "$CONTRACT" "$provenance" <<'PY'
import json, sys, tomllib
contract = tomllib.loads(open(sys.argv[1], encoding='utf-8').read())
record = json.load(open(sys.argv[2], encoding='utf-8'))
names = [row['name'] for row in contract['helpers']]
archive = record.get('archive', {})
if record.get('target') != 'x86_64-unknown-linux-musl' or record.get('contract') != 'builtins/x86_64-helper-contract.toml':
    raise SystemExit('archive provenance target/contract differs')
if archive.get('members') != ['crabc-builtins.o'] or set(archive.get('defined_symbols', ())) < set(names):
    raise SystemExit('archive provenance helper roster differs')
if record.get('reproducible') is not True:
    raise SystemExit('archive reproducibility proof did not pass')
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
import sys, tomllib
names = [row['name'] for row in tomllib.loads(open(sys.argv[1], encoding='utf-8').read())['helpers']]
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
import sys, tomllib
names = [row['name'] for row in tomllib.loads(open(sys.argv[1], encoding='utf-8').read())['helpers']]
log = open(sys.argv[2], encoding='utf-8', errors='replace').read()
missing = [name for name in names if name not in log]
if missing:
    raise SystemExit('archive-free failure did not name intended helper(s): ' + ', '.join(missing))
PY
record_command candidate-link env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -nostdlib -static -no-pie -Wl,--build-id=none \
    -Wl,--no-undefined -Wl,-e,_start -Wl,-t "$start_object" "$object" "$archive" -o "$candidate"
if grep -Eq 'libgcc|compiler-rt|libc\.a|/crt[^[:space:]]*\.o' "$WORK_DIR/raw/candidate-link.stdout"; then
    fail "candidate link admitted an ambient CRT or compiler runtime"
fi
record_command candidate-definitions nm --defined-only "$candidate"
record_command candidate-undefined nm --undefined-only "$candidate"
record_command candidate-header readelf -hW "$candidate"
record_command candidate-program-headers readelf -lW "$candidate"
record_command candidate-dynamic readelf -dW "$candidate"
record_command candidate-disassembly objdump --disassemble "$candidate"
python3 - "$CONTRACT" "$WORK_DIR/raw/candidate-definitions.stdout" "$WORK_DIR/raw/candidate-disassembly.stdout" <<'PY'
import re, sys, tomllib
names = [row['name'] for row in tomllib.loads(open(sys.argv[1], encoding='utf-8').read())['helpers']]
definitions = {line.split()[-1] for line in open(sys.argv[2], encoding='utf-8') if line.split()}
missing = sorted(set(names) - definitions)
if missing:
    raise SystemExit('candidate did not retain helper(s): ' + ', '.join(missing))
text = open(sys.argv[3], encoding='utf-8', errors='replace').read()
missing = [name for name in names if re.search(r'(?:call|jmp)\S*\s+[^\n]*<' + re.escape(name) + r'>', text) is None]
if missing:
    raise SystemExit('candidate has no direct transfer to helper(s): ' + ', '.join(missing))
PY
readelf -hW "$candidate" | grep -F 'Type:                              EXEC (Executable file)' >/dev/null || fail "candidate is not ET_EXEC"
readelf -lW "$candidate" | grep -E 'INTERP| TLS ' >/dev/null && fail "candidate has an interpreter or TLS"
if readelf -dW "$candidate" | grep -E '\((NEEDED|JMPREL|PLTGOT)\)' >/dev/null; then
    fail "candidate has dynamic linkage"
fi
[ ! -s "$WORK_DIR/raw/candidate-undefined.stdout" ] || fail "candidate retains an undefined symbol"

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
printf 'native x86 compiler-helper aggregate: PASS (%s)\n' "$report"

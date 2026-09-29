#!/usr/bin/env bash
# Keep raw pinned-musl and source-built crabc exp2 edge streams for inspection.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
report="$root/.work/x86_64/libc-math-exp2-edges"
mkdir -p "$report"
archive="$report/libc.a"
source="$root/compat/x86_64/libc_math_exp2_probe.c"
start="$root/compat/x86_64/libc_math_exp2_edges_start.S"
common=(-std=c11 -D_GNU_SOURCE -DCRABC_MATH_EXP2_EXTENDED \
    -I"$root/include" -fno-builtin -fno-stack-protector)

"$oracle_cc" "${common[@]}" "$source" -lm -o "$report/oracle"
"$report/oracle" >"$report/oracle.records"
build_source_runtime_libc "$archive"
"$oracle_cc" "${common[@]}" -DCRABC_MATH_EXP2_FREESTANDING \
    -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    "$source" "$start" "$archive" -o "$report/candidate"
"$report/candidate" >"$report/candidate.records"

python3 - "$report" <<'PY'
from pathlib import Path
import struct
import sys

report = Path(sys.argv[1])
oracle = (report / 'oracle.records').read_bytes()
candidate = (report / 'candidate.records').read_bytes()
size = 360 * 32
if len(oracle) != size or len(candidate) != size:
    raise SystemExit(f'expected {size} bytes per stream; got {len(oracle)}, {len(candidate)}')
with (report / 'mismatches.tsv').open('w') as out:
    out.write('index\tinput\toracle_result\tcandidate_result\trequested_observed\toracle_flags\tcandidate_flags\n')
    mismatches = 0
    for index in range(360):
        offset = index * 32
        expected = struct.unpack_from('<4Q', oracle, offset)
        actual = struct.unpack_from('<4Q', candidate, offset)
        if expected == actual:
            continue
        mismatches += 1
        out.write(f'{index}\t{expected[0]:016x}\t{expected[1]:016x}\t{actual[1]:016x}'
                  f'\t{expected[2]:016x}/{actual[2]:016x}'
                  f'\t{expected[3]:x}\t{actual[3]:x}\n')
print(f'exp2/exp2f edge differential: {360 - mismatches}/360 exact records; raw streams: {report}')
if mismatches:
    raise SystemExit(f'{mismatches} mismatches; see {report / "mismatches.tsv"}')
PY

#!/bin/sh
set -eu
# Run inside the pinned native image. Account FILE/cancellation providers are
# musl fixture dependencies; account/protocol/lifecycle implementations are
# included directly from the current candidate source.
out=${ACCOUNTS109_OUTPUT:-/workspace/.work/x86_64/reports/accounts109}
mkdir -p "$out"
rustc --edition=2021 --crate-type=staticlib -C opt-level=0 -C panic=abort compat/x86_64/accounts109/account_source_bridge.rs -o "$out/account-source.a"
for db in passwd group; do
 cc -O0 -fno-pie -no-pie -static -specs=/opt/musl-1.2.6/lib/musl-gcc.specs "compat/x86_64/owned_${db}_probe.c" "$out/account-source.a" -o "$out/$db-candidate"
 cc -O0 -fno-pie -no-pie -static -specs=/opt/musl-1.2.6/lib/musl-gcc.specs "compat/x86_64/owned_${db}_probe.c" -o "$out/$db-oracle"
 for impl in oracle candidate; do
  for scenario in lookup ranges enumeration stream output threads fork; do
   "$out/$db-$impl" "$scenario" "$impl" > "$out/$db-$impl-$scenario.log" 2>&1
  done
 done
 done
for impl in oracle candidate; do
 for scenario in duplicate-cursor memberships; do
  "$out/group-$impl" "$scenario" "$impl" > "$out/group-$impl-$scenario.log" 2>&1
 done
done
for family in protocol_database service_lifecycle; do
 for impl in oracle candidate; do
  archive=
  if [ "$impl" = candidate ]; then archive="$out/account-source.a"; fi
  cc -O0 -fno-pie -no-pie -static -specs=/opt/musl-1.2.6/lib/musl-gcc.specs "compat/x86_64/libc_${family}_probe.c" $archive -o "$out/$family-$impl"
  "$out/$family-$impl" > "$out/$family-$impl.log" 2>&1
 done
done
cc -O0 -fno-pie -no-pie -static -specs=/opt/musl-1.2.6/lib/musl-gcc.specs compat/x86_64/accounts109/service_lookup_probe.c -o "$out/service-oracle"
"$out/service-oracle" > "$out/service-oracle.log" 2>&1
# Local-only lookup deliberately retains local open errors rather than querying
# musl's optional nscd provider. Compare these with the selected source rule.
for db in passwd group; do
 for scenario in missing directory; do
  "$out/$db-candidate" "$scenario" candidate > "$out/$db-candidate-$scenario.log" 2>&1
 done
done
for impl in oracle candidate; do
 "$out/group-$impl" memberships-missing "$impl" > "$out/group-$impl-memberships-missing.log" 2>&1
done

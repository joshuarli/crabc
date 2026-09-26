# Selected static function authority

`owned_static_link_authority.require_static_functions` is a process-free join
between a component's exact admitted input objects, its LLD map, and the linked
static ELF. Components still own their finite function roster, source/final
symbol metadata, product admission, tool binding, and static-link mode.

For selected links with TLS, the helper retains the existing complete `PT_TLS`
geometry proof: every mapped TLS input section supplies the ordered segment
layout, alignment, file size, and memory size. A link with no `PT_TLS` is
admitted only when all of the following are absent: final TLS program headers,
final TLS sections, selected mapped TLS input sections, and selected mapped TLS
relocations. A present TLS input cannot use the TLS-free path, and adding an
output TLS segment cannot replace the nonempty proof.

The helper also recognizes one static RuntimeV1 absence form:
`__crabc_x86_64_loader_tls_runtime_v1` may remain the exact weak/default/NOTYPE
undefined symbol at value zero in a relocation-free `ET_EXEC` final ELF. Its
selected source relocation must be `R_X86_64_GOTPCREL` with addend `-4`, and the
linked instruction must resolve one initialized zero GOT slot. No other weak
undefined symbol, relocation form, output type, or dynamic relocation receives
that treatment.

`tests/test_owned_static_link_authority.py` uses a supplied pinned ordinary LLD
fixture through `CRABC_STATIC_LINK_AUTHORITY_FIXTURE_DIR`. The fixture contains
the selected freestanding RuntimeV1 probe and attachment link, a real
`__thread` source variation, the selected weak-descriptor absence link, and
ordinary C controls for an unknown weak target and a direct weak-descriptor
relocation. It never edits an ELF, section table, or relocation record.

The installed static `libc.a` carries one member per Rust module, so a selected
function often references a hidden function or TLS object defined in a sibling
member. An undefined non-local target joins its traced map definition; LLD's
map prints Rust-mangled names demangled, so a target with no map row by name
resolves to the one non-local definition among the traced inputs, whose section
placement and final symbol are then checked as usual. A defined hidden or local
target still resolves in its own object. `OwnedStaticLinkAuthorityCrossMemberTests`
proves both forms against one ordinary two-object LLD link supplied through
`CRABC_STATIC_LINK_AUTHORITY_CROSS_MEMBER_FIXTURE_DIR`, built in the pinned
image with:

```sh
lld=$(ls /opt/rustup/toolchains/*/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld)
cat >caller.c <<'C'
__attribute__((visibility("hidden"))) int sibling_hidden(int);
extern __thread int sibling_tls __asm__("_RNvCs0_5crate11SIBLING_TLS");
__asm__(".hidden _RNvCs0_5crate11SIBLING_TLS");
int selected_entry(int value) { return sibling_hidden(value) + sibling_tls; }
void _start(void) { __asm__ volatile("mov $60, %%eax; syscall" :: "D"(selected_entry(1)) : "rax"); }
C
cat >callee.c <<'C'
__attribute__((visibility("hidden"))) int sibling_hidden(int value) { return value * 2; }
__attribute__((visibility("hidden"))) __thread int sibling_tls __asm__("_RNvCs0_5crate11SIBLING_TLS") = 0;
C
for name in caller callee; do
  gcc -O2 -fPIC -ftls-model=initial-exec -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -c $name.c -o $name.o
done
"$lld" -static -e _start -Map cross-member.map caller.o callee.o -o cross-member
```

One selected Rust archive member carries an eight-byte anonymous `GLOBAL HIDDEN`
object in `.rodata.cst8`. The static link merges that input section and
localizes the final symbol. The authority admits this form only when the
relocation names that selected member's source symbol, its bytes occur at one
place in the mapped constant pool, and the unique final `LOCAL HIDDEN` symbol
points to that place. Other source bindings, visibility, section shape, source
positions, final positions, and duplicate final constants remain invalid.
`OwnedStaticLinkAuthorityMergedConstantTests` replays the selected archive,
trace, map, and executable supplied through
`CRABC_STATIC_LINK_AUTHORITY_SYSCALL_RUNNER` and
`CRABC_STATIC_LINK_AUTHORITY_STATIC_PRODUCT`; it mutates copies of the real ELF
bytes for rejection cases.

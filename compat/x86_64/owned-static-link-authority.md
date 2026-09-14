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

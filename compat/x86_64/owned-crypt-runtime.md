# Owned x86 bounded `crypt(3)` runtime receipt

`run_owned_crypt_runtime.sh` proves that the existing bounded C crypt provider
is present in the ordinary owned static and dynamic products. It uses the
existing `libc_crypt_probe.c` fixture without changing its cryptographic
implementation or dependency graph. The fixture enters its candidate path, so
it executes public `crypt`, weak `crypt_r`, and each existing private
`__crypt_*` alias. It checks the canonical SHA-256-crypt (`$5$`) and
SHA-512-crypt (`$6$`) vectors, the dependency's default-round spelling,
null behavior, caller-buffer and trailing-guard ownership, and accepted input
that overlaps the output/shared result. It also verifies the frozen rejection
of MD5-crypt, bcrypt, malformed settings, overlong bounded inputs, and invalid
round/salt forms.

The runner creates one installed-header fixture object through the installed dynamic driver's
`--dynamic-pie` source path. Before that translation
it records the actual driver command, installed driver/helper/compiler and
manifest identities, clean compiler environment, source hash, exact dependency
preprocessing command, and every source/header hash. It seals the object hash
in `compile.json` and revalidates the complete receipt before and after the
pinned-musl link and each product link. That candidate object has no absolute
32-bit relocation and is linked into static ET_EXEC, static PIE, dynamic PIE,
and dynamic non-PIE. The pinned-musl oracle separately translates the same
unchanged fixture with the candidate macro disabled, then compares only the
raw observations shared by the two fixture paths. Static and shared provider
audits require one owner for all aliases and retain `crypt_r` as a weak
binding. Every sealed product link is independently checked by
`owned_posix_product_evidence.validate_link`; dynamic consumers run through
both the kernel interpreter path and direct owned-loader entry. Before the
first candidate launch, it has copied both dynamic products and consumers and
records each source and execution copy of the manifest, every manifest payload
file, every manifest symbolic-link alias, and the linked consumer. It audits
those immutable records before execution, after each consumer's kernel and
direct launches, and once more at final sealing. The runner records raw
stdout, stderr, and exit status for every execution and compares them with the
pinned-musl fixture run.

Run it through the native evidence environment with:

```bash
./scripts/dev-x86_64.sh owned-crypt-runtime \
  --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT
```

The optional replay interface is
`[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With no arguments it
builds disposable static and dynamic products below `.work`. A positional
dynamic product requests a dynamic-only replay. A supplied static product
still gets a disposable dynamic product when needed for the one installed
source translation. Supplying both products invokes no producer. Arguments
must be nonempty physical directories below this checkout's `.work` tree.

The runner additionally translates one installed-header observer object containing
all 32 original calls from the pinned libc-test `functional/crypt` source.
That same object runs against pinned musl and all four owned dynamic entries.
It records actual pointer nullness and output bytes; expected profile rejection
requires nonnull `*`. The two supported low-round SHA settings normalize rounds
to 1000 and retain their exact upstream hashes. Twelve legacy hashes and sixteen
unsupported SHA settings have finite profile differences. The original upstream
unit remains unchanged and retains its raw failure and 28 diagnostics.

`owned_crypt_profile.py` reconstructs `crypt-profile.json` from both fixture
objects, retained compiler/header identities, physical ELF metadata, sealed
links, copied runtime payloads, all raw executions, and the full artifact tree.
Host validation requires neither a compiler nor Docker:

```sh
python3 -B compat/x86_64/owned_crypt_profile.py validate PATH/crypt-profile.json
```

The native aggregate requires this companion on its identical installed
product. It supports only the finite qualification described in
[`owned-posix-native-dispositions.md`](owned-posix-native-dispositions.md).
It is not an upstream libc-test pass, a full historical crypt implementation,
a public x86 support claim, or a cryptographic algorithm change.

The installed runtime selects `x86-crypt-allocator-composition` through
`x86-owned-static-runtime`; the default frozen archive remains separate.

# Pinned musl declared-without-provider boundary

`run_header_callable_disposition.sh` invokes
`header_callable_oracle_no_provider_audit.py` after the checked compiler
inventory and disposition report. The audit reads the exact deferred-owner
group whose resolution is `oracle-declared-no-provider`; it does not copy a
separate symbol roster into the runner. Every member must still be a checked
candidate external declaration.

The native audit verifies the pinned musl `.crabc-oracle` identity, compiler
target and selected `libc.a`/`libc.so`, installed declaration-header hashes,
and the SHA-256-verified musl source tree. It records no source occurrence for
the corrected priority-ceiling pair. The older cache declarations have musl
source conditional on other Linux architectures, so their native absence is
established by the complete x86 artifact audit. That audit keeps global defined
`nm` dumps for the archive and shared object plus the complete shared `.dynsym`
dump. Any GLOBAL or WEAK definition, including an alias, fails. An inspection
command failure also fails; empty output alone is never treated as an absence.

The two priority-ceiling mutex-attribute declarations additionally have C11
and C++17 installed-header compile objects. The exact same object is hashed
before and after ordinary static and dynamic pinned-oracle links. Each link
must fail only for its intended undefined symbol, with no CRT, tool, or other
unresolved-name diagnostic.

Receipts remain in a unique
`.work/x86_64/tmp/header-callable-oracle-no-provider.*` directory. They record
input identities, commands, return codes, stdout, stderr, source scan, object
hashes, and link witnesses. The result is only structural evidence that the
pinned oracle declares this finite group without a provider. It does not
establish header, family, archive, runtime-behavior, or public-support
closure.

# Installed descriptor-admission control

`installed_crt_descriptor_admission.py` is a finite, development-only
installed-loader control for
`__crabc_x86_64_loader_tls_runtime_v1`. It operates on one supplied dynamic
product and one supplied owned final main without rebuilding either product.
It rebuilds only the current-source interpreter, copies the supplied product
to a private execution root, and records an immutable receipt below the
checkout's `.work/x86_64/` boundary.

The input main must contain exactly one weak, default-visible, undefined
`NOTYPE` descriptor symbol and one zero-addend `R_X86_64_GLOB_DAT` relocation.
The collector makes four single-field copies: `OBJECT` instead of `NOTYPE`,
global instead of weak binding, `JUMP_SLOT` instead of `GLOB_DAT`, and addend
one instead of zero. It also builds one DSO with the otherwise canonical weak
descriptor request and one application that depends on that DSO. The unchanged
main is the positive control. Every input is bound before and after collection;
the report binds the copied execution tree, every mutation offset and byte
identity, each source file, each generated object, exact commands, and every
raw outcome.

The application driver also emits its usual canonical main-image wire. Host
replay reparses that wire and the rogue DSO independently, so the DSO control
cannot be satisfied by omitting the dependency's descriptor request. The
loader admits the endpoint's main wire, rejects the DSO request during graph
relocation, and therefore never calls application `main`.

The accepted result is deliberately narrow. In both kernel and direct entry,
the unchanged main prints `PICOMAFL` and exits zero. Each of the four altered
main images and the DSO endpoint exits `127`, writes no stdout, and writes
only `reloc` to stderr. The companion application writes `application-main`
only from `main`, so empty stdout establishes that rejection occurred before
application execution. A report that differs in a source identity, supplied
product identity, mutation bytes, copied tree, command, raw outcome, or source
epoch fails host replay.

This is not a runtime qualification receipt and it is not an input to native
ABI selection. It proves only this current interpreter's admission boundary
over its retained supplied-product control. It leaves release-READY ordering,
descriptor lifetime, generation transitions, worker mapping, and fork
ownership open. A changed interpreter needs a new current-source receipt and
fresh product evidence before any selector or promotion decision.

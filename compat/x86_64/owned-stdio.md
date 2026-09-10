# Installed stdio composition

`run_owned_stdio.sh` is a bounded installed-product behavior component for
`stdio.path-stream`, `stdio.stream-io`, `stdio.position-buffering`, and
`stdio.format-scan`. It translates one C11 object through the selected dynamic
product's installed headers, then links those unchanged object bytes with
pinned musl and the selected owned products. It is not a private archive
fixture.

The object keeps byte and wide operations on separate live `FILE` objects. The
byte stream opens a path as `w+`, keeps a caller full buffer, verifies the
kernel offset before and after buffered output, saves a logical position,
changes from output through `fseek` and byte input, restores that position with
`fsetpos`, and writes again. It then checks byte `fprintf`/`fscanf`, EOF and
`clearerr`, successful `freopen` identity and descriptor reuse, and a write to
a read-only stream. That direction error retains the caller's `errno`, sets
`ferror`, and is cleared explicitly. A separate `fdopen` stream takes one
descriptor; `fclose` retires it while an independent `dup` remains usable.

The wide stream fixes `LC_CTYPE` to `C.UTF-8`, establishes wide orientation,
and checks one Euro sign plus a supplementary-plane character through
`fputwc`, `fputws`, `fgetwc`, `ungetwc`, `fgetws`, and EOF. It neither changes
the byte stream's orientation nor establishes a general locale or encoding
policy. The component excludes cookie and memory streams, standard streams,
threads, wide printf/scanf grammar, arbitrary locale maps, legacy encodings,
and general stdio completion.

The runner retains one pinned-musl static ET_EXEC link using
`-static -fno-pie -no-pie`, static ET_EXEC and static PIE when a static product
is supplied, and dynamic PIE/non-PIE through both kernel and direct owned
loader entry. Every successful run has retained exact argv, stdout, stderr,
and zero status. It traces installed headers, seals the probe, runner, tool
roster, selected manifests and trees before and after execution, keeps the one
object identity, validates every product link receipt, and records/audits each
copied dynamic execution payload before and after both entries.

Run it in the pinned native environment:

```sh
./scripts/dev-x86_64.sh owned-stdio \
  --static-sysroot .work/x86_64/static-product \
  .work/x86_64/dynamic-product
```

Its interface is `[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With
supplied products it never builds replacements. With neither argument it
builds disposable products below checkout-local `.work`. Inputs must be
physical directories below that tree. A supplied static product also requires
the dynamic product that provides the installed compilation headers. Every
dynamic product must replay this component in the canonical qualification catalog.

This receipt is evidence for four finite stdio components only. It does not
close the stdio family, alter a disposition, imply broad locale or wide-format
coverage, or claim promotion or public x86 support.

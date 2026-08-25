# Extracted sysroot smoke

This harness tests the packaged `.tar.xz` after safe extraction. It does not
rebuild or repair the archive and never installs the crabc loader into the
container's real `/lib`.

Re-run a release asset through the pinned native development container with:

```sh
./scripts/dev.sh sysroot-smoke \
  dist/crabc-sysroot-aarch64-<short-sha>.tar.xz
```

The dispatcher reads the full source commit from the safely extracted archive.
The underlying runner is also directly invokable inside that container when a
specific report location is useful:

```sh
python3 compat/sysroot-smoke/run.py \
  --archive dist/crabc-sysroot-aarch64-<short-sha>.tar.xz \
  --source-commit <full-40-character-sha> \
  --report compat/reports/sysroot-smoke/latest.json
```

The smoke includes manifest/hash/symlink validation, isolated public-header
tracing, explicit sealed-driver/lld link plans and maps for a shared module and
dynamic PIE, a `dlopen`/`dlsym`/`dlclose` runtime probe in a scratch `chroot`,
and the repository's static pthread/TLS fixture through the extracted driver.
The report retains raw subprocess streams, ELF parser/tool output, linker
traces/maps, and the archive SHA-256.

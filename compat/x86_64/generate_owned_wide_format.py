#!/usr/bin/env python3
"""Emit fixed musl wide printf/scanf parser assembly with owned FILE callbacks."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from generate_owned_printf_float import generation_environment
from generate_libc_math_long_double_completion import (
    ROOT, EXPECTED_MUSL_TREE_DIGEST, normalized_tree_digest, checked_compiler, COMPILE_FLAGS,
)

SOURCES = ("src/stdio/vfwprintf.c", "src/stdio/vfwscanf.c")
ADAPTER = r"""
#define _GNU_SOURCE
#define FILE crabc_public_FILE
#include <stdio.h>
#include <wchar.h>
#undef FILE
#include <wctype.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <inttypes.h>
#define FLOCK(f) ((void)0)
#define FUNLOCK(f) ((void)0)
struct operations {
    wint_t (*get)(void *);
    wint_t (*put)(void *, wchar_t);
    wint_t (*unget)(void *, wint_t);
    int (*error)(void *);
    int (*orient)(void *, int);
    int (*begin)(void *);
    int (*end)(void *, int);
    int (*print)(void *, const char *, va_list *);
    int (*scan)(void *, const char *, va_list *);
};
/* Only synchronous context, never a counterfeit public FILE layout. */
typedef struct { void *context; const struct operations *ops; } FILE;
static wint_t bridge_getwc(FILE *f) { return f->ops->get(f->context); }
static wint_t bridge_fputwc(wchar_t c, FILE *f) { return f->ops->put(f->context,c); }
static wint_t bridge_ungetwc(wint_t c, FILE *f) { return f->ops->unget(f->context,c); }
static int bridge_ferror(FILE *f) { return f->ops->error(f->context); }
static int bridge_fwide(FILE *f, int mode) { return f->ops->orient(f->context,mode); }
static int bridge_begin(FILE *f) { return f->ops->begin(f->context); }
static int bridge_end(FILE *f,int old) { return f->ops->end(f->context,old); }
static int bridge_fprintf(FILE *f, const char *format, ...) {
    va_list ap; va_start(ap,format);
    int result=f->ops->print(f->context,format,&ap);
    va_end(ap); return result;
}
static int bridge_fscanf(FILE *f, const char *format, ...) {
    va_list ap; va_start(ap,format);
    int result=f->ops->scan(f->context,format,&ap);
    va_end(ap); return result;
}
"""
ENTRY = r"""
__attribute__((visibility("hidden")))
int __crabc_owned_wide_format(void *context, const struct operations *ops,
    int scan, const wchar_t *format, va_list *arguments)
{
    FILE cursor={context,ops};
    return scan ? crabc_owned_vfwscanf(&cursor,format,*arguments)
        : crabc_owned_vfwprintf(&cursor,format,*arguments);
}
"""

def translation(source_root):
    sources = {name: (source_root / name).read_text() for name in SOURCES}
    bodies=[]
    for name, original in sources.items():
        body=re.sub(r"^#include[^\n]*\n", "", original, flags=re.MULTILINE)
        if name.endswith("vfwscanf.c"):
            body=body[:body.index("weak_alias(")]
            begin=body.index("#if 1\n")
            end=body.index("#endif",begin)+len("#endif")
            body=body[:begin]+body[end:]
        else:
            old="olderr = f->flags & F_ERR;\n\tf->flags &= ~F_ERR;"
            assert body.count(old)==1
            body=body.replace(old,"olderr = bridge_begin(f);")
            old="if (ferror(f)) ret = -1;\n\tf->flags |= olderr;"
            assert body.count(old)==1
            body=body.replace(old,"if (bridge_end(f, olderr)) ret = -1;")
        for symbol in ("getwc","fputwc","ungetwc","ferror","fwide","fprintf","fscanf"):
            body=re.sub(r"\b"+symbol+r"\b", "bridge_"+symbol, body)
        # Keep each source's private helpers separate in this translation unit.
        prefix="crabc_owned_wscan_" if name.endswith("vfwscanf.c") else "crabc_owned_wprint_"
        for symbol in ("store_int","arg_n","in_set","states","pop_arg","out","pad","getint","sizeprefix","wprintf_core"):
            body=re.sub(r"\b"+symbol+r"\b",prefix+symbol,body)
        for symbol in ("vfwprintf","vfwscanf"):
            body=re.sub(r"\b"+symbol+r"\b","crabc_owned_"+symbol,body)
        bodies.append(body)
    return ADAPTER+"\n".join(bodies)+ENTRY, sources

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-source", required=True, type=Path)
    parser.add_argument("--cc", default="/usr/local/bin/crabc-x86_64-musl-gcc")
    parser.add_argument("--output", type=Path, default=ROOT/"libc/src/c_abi/x86_64/owned_wide_format_musl_x86_64.S")
    args=parser.parse_args()
    source_root=args.musl_source.resolve()
    if normalized_tree_digest(source_root)!=EXPECTED_MUSL_TREE_DIGEST:
        raise SystemExit("pinned musl tree digest mismatch")
    environment=generation_environment()
    compiler=checked_compiler(args.cc,environment=environment)
    source,sources=translation(source_root)
    with tempfile.TemporaryDirectory(prefix="owned-wide-format.",dir=environment["TMPDIR"]) as temporary:
        unit,assembly=Path(temporary)/"wide.c",Path(temporary)/"wide.S"
        unit.write_text(source)
        subprocess.run([compiler,*COMPILE_FLAGS,"-fPIC","-fvisibility=hidden","-S",str(unit),"-o",str(assembly)],check=True,env=environment)
        text=assembly.read_text()
    text=re.sub(r"(?<![A-Za-z0-9_.])\.L([A-Za-z0-9_.$]+)",r".Lcrabc_owned_wide_format_\1",text)
    text=re.sub(r"^\s*\.(file|ident)\s+.*\n","",text,flags=re.MULTILINE)
    notice=(source_root/"COPYRIGHT").read_text().split("Authors/contributors include:")[0]
    header="/*\nGenerated by compat/x86_64/generate_owned_wide_format.py from musl 1.2.6.\n"
    header+="See owned_wide_format.rs for source mapping and callback/FILE ownership.\n"
    for name,contents in sources.items():
        header+=name+" SHA256: "+hashlib.sha256(contents.encode()).hexdigest()+"\n"
    header+="Translation SHA256: "+hashlib.sha256(source.encode()).hexdigest()+"\n\n"
    args.output.write_text(header+notice+"\n*/\n"+text)

if __name__ == "__main__":
    main()

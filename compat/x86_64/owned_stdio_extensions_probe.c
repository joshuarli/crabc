#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <wchar.h>
#include <locale.h>

/* Source boundary: musl 1.2.6 stdio/{ext,ext2,fgetln,gets,getw,putw,
 * setbuf,setbuffer,setlinebuf}.c, and the active read/write pointer lifecycle
 * in __toread/__towrite/fflush/fseek. Every pathname is caller-private. */
extern char *gets(char *);
extern int _IO_feof_unlocked(FILE *);
extern int _IO_ferror_unlocked(FILE *);
extern int _IO_getc(FILE *), _IO_getc_unlocked(FILE *), __uflow(FILE *);
extern int _IO_putc(int,FILE *), _IO_putc_unlocked(int,FILE *), __overflow(FILE *,int);
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"extensions:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)

static void state(const char *name, FILE *f) {
    printf("%s %d %d %d %d %d %zu %zu %zu %d %d\n",name,
        !!__freading(f),!!__fwriting(f),__freadable(f),__fwritable(f),
        __flbf(f),__fbufsize(f),__fpending(f),__freadahead(f),
        !!feof_unlocked(f),!!ferror_unlocked(f));
}
struct cookie { FILE *file; int fail; size_t count; int short_write; };
static ssize_t output(void *data, const char *bytes, size_t count) {
    struct cookie *c=data; (void)bytes;
    /* Introspection is non-locking and is valid inside the FILE callback. */
    if (!__fwriting(c->file) || __freading(c->file)) _exit(91);
    if (c->fail) { errno=ENOSPC; return -1; }
    if (c->short_write && count) return count-1;
    c->count+=count; return count;
}
int main(int argc, char **argv) {
    CHECK(argc==2); alarm(30);
    CHECK(__flbf(stdout)==1 && !fwide(stdout,0) && __flbf(stdout)==1);
    puts("stdout-first"); /* __stdout_write delays terminal probing until now. */
    CHECK(!!__flbf(stdout)==!!isatty(fileno(stdout)));
    char buffer[40], bytes[64];
    FILE *f=fopen(argv[1],"w+"); CHECK(f);
    setbuffer(f,buffer,sizeof buffer);
    state("new",f);
    CHECK(!__freading(f) && !__fwriting(f) && __fbufsize(f)==32);
    CHECK(!fread(bytes,0,1,f)); state("empty-read",f);
    CHECK(!__freading(f) && !__fwriting(f));
    CHECK(!fwrite(bytes,0,1,f)); state("empty-write",f);
    CHECK(__fwriting(f) && !__freading(f));
    CHECK(!fflush_unlocked(f)); state("flushed",f);
    CHECK(!__freading(f) && !__fwriting(f));
    CHECK(fputs_unlocked("discard",f)>=0 && __fpending(f)==7);
    CHECK(!__fpurge(f) && !__fpending(f) && !ftell(f));
    CHECK(fputs("alpha\nbeta\nlast",f)>=0 && __fpending(f)==15);
    CHECK(!fflush(f) && !fseek(f,0,SEEK_SET));
    CHECK(getc_unlocked(f)=='a'); state("reading",f);
    size_t available=777; const char *view=__freadptr(f,&available);
    CHECK(view && available==14 && !memcmp(view,"lpha\nbeta\nlast",14));
    __freadptrinc(f,4); CHECK(ftell(f)==5 && fgetc(f)=='\n');
    CHECK(!__fpurge(f)); state("purged-read",f);
    CHECK(ftell(f)==15 && fgetc(f)==EOF && feof_unlocked(f));
    size_t unchanged=123; CHECK(!__freadptr(f,&unchanged) && unchanged==123);
    __fseterr(f); CHECK(ferror_unlocked(f) && _IO_ferror_unlocked(f) && _IO_feof_unlocked(f));
    clearerr_unlocked(f); CHECK(!feof_unlocked(f) && !ferror_unlocked(f));
    CHECK(!fseek(f,0,SEEK_SET));
    size_t length=0; char *line=fgetln(f,&length);
    CHECK(line && length==6 && !memcmp(line,"alpha\n",6));
    line=fgetln(f,&length); CHECK(line && length==5 && !memcmp(line,"beta\n",5));
    line=fgetln(f,&length); CHECK(line && length==4 && !memcmp(line,"last",4));
    length=199; CHECK(!fgetln(f,&length) && length==199 && feof(f));
    CHECK(!fclose(f));

    /* Line fallback owns a separate reallocating buffer until fclose. */
    f=fopen(argv[1],"w+"); CHECK(f); setbuffer(f,buffer,sizeof buffer);
    for (int i=0;i<5;i++) { for (int j=0;j<1200+i*317;j++) CHECK(fputc('A'+i,f)=='A'+i); CHECK(fputc('\n',f)=='\n'); }
    CHECK(fputs("tail",f)>=0 && !fseek(f,0,SEEK_SET));
    for (int i=0;i<5;i++) {
        line=fgetln(f,&length); CHECK(line && length==(size_t)(1201+i*317));
        for (size_t j=0;j<length-1;j++) CHECK(line[j]=='A'+i);
        CHECK(line[length-1]=='\n');
    }
    line=fgetln(f,&length); CHECK(line && length==4 && !memcmp(line,"tail",4));
    CHECK(freopen(argv[1],"r",f)==f && __freading(f) && !__fwriting(f));
    CHECK(fgets_unlocked(bytes,sizeof bytes,f)==bytes && bytes[0]=='A');
    CHECK(!fclose(f));

    char left[]="left", right[]="right";
    FILE *a=fmemopen(left,4,"r"), *b=fmemopen(right,5,"r"); CHECK(a && b);
    char *first=fgetln(a,&length); CHECK(first && length==4);
    char *second=fgetln(b,&length); CHECK(second && length==5);
    CHECK(!memcmp(first,"left",4) && !memcmp(second,"right",5));
    CHECK(!fclose(a) && !fclose(b));

    /* A global flush skips active input and empty dynamic output, but a
     * pending stream leaves writing mode after its write callback. */
    char mem[32]="xyz";
    FILE *input=fmemopen(mem,3,"r+"), *empty=fopen(argv[1],"w+");
    f=fopen(argv[1],"r+"); CHECK(input && empty && f);
    CHECK(fgetc(input)=='x' && !fwrite(bytes,0,1,empty) && fputc('Q',f)=='Q');
    CHECK(!fflush(NULL));
    state("global-input",input); state("global-empty",empty); state("global-output",f);
    CHECK(__freading(input) && __fwriting(empty) && !__fwriting(f));
    CHECK(!fclose(input) && !fclose(empty) && !fclose(f));

    f=fopen(argv[1],"w+"); CHECK(f); setlinebuf(f);
    CHECK(__flbf(f) && fputs("before",f)>=0 && __fpending(f)==6);
    _flushlbf(); CHECK(!__fpending(f) && !__fwriting(f));
    CHECK(__fsetlocking(f,FSETLOCKING_QUERY)==0 && __fsetlocking(f,FSETLOCKING_BYCALLER)==0);
    flockfile(f); CHECK(!ftrylockfile(f)); funlockfile(f); funlockfile(f);
    CHECK(!fclose(f));
    f=fopen(argv[1],"w+"); CHECK(f); setbuf(f,NULL);
    CHECK(!__fbufsize(f) && fprintf(f,"%s","")==0 && !__fwriting(f));
    CHECK(putw(0x12345678,f)==0 && putw(-1,f)==0 && !fseek(f,0,SEEK_SET));
    CHECK(getw(f)==0x12345678 && getw(f)==-1 && !feof(f) && getw(f)==EOF && feof(f));
    CHECK(!fclose(f));
    f=fopen(argv[1],"w+"); CHECK(f); flockfile(f);
    CHECK(_IO_putc('r',f)=='r' && _IO_putc_unlocked('s',f)=='s' && __overflow(f,-1)==255);
    CHECK(!fseek(f,0,SEEK_SET) && !__freadahead(f) && __uflow(f)=='r');
    CHECK(_IO_getc(f)=='s' && _IO_getc_unlocked(f)==255 && __uflow(f)==EOF);
    funlockfile(f); CHECK(!fclose(f));

    struct cookie cookie={0}; cookie_io_functions_t io={0,output,0,0};
    f=fopencookie(&cookie,"w+",io); CHECK(f); cookie.file=f;
    CHECK(fputs("pending",f)>=0); cookie.fail=1; errno=0;
    CHECK(fflush(f)==EOF && errno==ENOSPC && ferror(f) && !__fpending(f) && !__fwriting(f));
    state("failed-write",f); clearerr(f); cookie.fail=0;
    CHECK(fputc('x',f)=='x'); errno=0;
    CHECK(fseek(f,0,SEEK_SET)==-1 && errno==ENOTSUP && !__fwriting(f));
    CHECK(!fclose(f));
    cookie=(struct cookie){0}; cookie.short_write=1;
    f=fopencookie(&cookie,"w+",io); CHECK(f); cookie.file=f; setbuffer(f,buffer,16);
    CHECK(fwrite("0123456789",1,10,f)==9 && !ferror(f) && __fwriting(f));
    state("short-write",f); CHECK(!fclose(f));

    CHECK(setlocale(LC_CTYPE,"C.UTF-8"));
    wchar_t *wide; size_t wide_count;
    f=open_wmemstream(&wide,&wide_count); CHECK(f);
    setlinebuf(f); CHECK(!__flbf(f)); /* zero-capacity streams stay unbuffered */
    CHECK(fputwc(0x20ac,f)==0x20ac && __fwriting(f) && !__fpending(f));
    state("wide-write",f); CHECK(!fflush(f) && !fclose(f)); free(wide);

    f=fopen(argv[1],"w"); CHECK(f && fputs("one\ntwo",f)>=0 && !fclose(f));
    CHECK(freopen(argv[1],"r",stdin)==stdin);
    CHECK(gets(bytes)==bytes && !strcmp(bytes,"one"));
    CHECK(gets(bytes)==bytes && !strcmp(bytes,"two"));
    CHECK(!gets(bytes) && !*bytes && feof(stdin));
    CHECK(fileno_unlocked(stdin)>=0 && !fclose(stdin));
    CHECK(!unlink(argv[1])); puts("owned-stdio-extensions-ok"); return 0;
}

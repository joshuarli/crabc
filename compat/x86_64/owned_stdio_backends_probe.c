#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>

static void record(int tag, int result, FILE *f, const void *data, size_t size)
{
    struct { int tag, result, error, indicator; long position; size_t size; unsigned char bytes[64]; } out = {0};
    out.tag=tag; out.result=result; out.error=errno;
    out.indicator=f ? (!!ferror(f) | (!!feof(f)<<1)) : 0;
    out.position=f ? ftell(f) : -1;
    out.size=size;
    if (data) memcpy(out.bytes, data, size<64 ? size : 64);
    if (write(1, &out, sizeof out) != sizeof out) _Exit(90);
}

static int descriptor(const char *path)
{
    char block[4096]; memset(block, 'D', sizeof block);
    FILE *f=fopen(path, "w+");
    if (!f || fwrite("old", 1, 3, f)!=3 || close(fileno(f))) return 1;
    errno=0;
    int count=fwrite(block, 1, sizeof block, f);
    record(1, count, f, NULL, 0);
    fclose(f);
    f=fopen(path, "w+");
    if (!f || fwrite("old", 1, 3, f)!=3 || fwrite(block, 1, sizeof block, f)!=sizeof block
        || fflush(f) || fseek(f, 0, SEEK_SET)) return 2;
    char got[4099];
    if (fread(got, 1, sizeof got, f)!=sizeof got || memcmp(got, "old", 3) || memcmp(got+3, block, sizeof block)) return 3;
    fclose(f); unlink(path);
    return 0;
}

#ifndef DESCRIPTOR_ONLY
struct cookie { unsigned char data[4096]; size_t pos, len; int reads, writes, closes, short_write, failure, read_fail_at; FILE *nested; };
static ssize_t reader(void *opaque, char *buffer, size_t length)
{
    struct cookie *c=opaque; c->reads++;
    if (c->failure || (c->read_fail_at && c->reads >= c->read_fail_at)) { errno=EIO; return -1; }
    size_t available=c->pos<c->len ? c->len-c->pos : 0;
    if (length>available) length=available;
    memcpy(buffer, c->data+c->pos, length); c->pos+=length;
    return length;
}
static ssize_t writer(void *opaque, const char *buffer, size_t length)
{
    struct cookie *c=opaque; c->writes++;
    if (c->failure) { errno=EIO; return -1; }
    if (c->short_write && length>2) length=2;
    if (length>sizeof c->data-c->pos) length=sizeof c->data-c->pos;
    if (length) memcpy(c->data+c->pos, buffer, length);
    c->pos+=length; if(c->pos>c->len) c->len=c->pos;
    if(c->nested && length) { if(fwrite("!",1,1,c->nested)!=1) _Exit(91); }
    return length;
}
static int seeker(void *opaque, off_t *offset, int whence)
{
    struct cookie *c=opaque;
    off_t target=*offset+(whence==SEEK_CUR ? c->pos : whence==SEEK_END ? c->len : 0);
    if(target<0 || (size_t)target>sizeof c->data) { errno=EINVAL; return -1; }
    c->pos=*offset=target; return 0;
}
static int closer(void *opaque) {
    struct cookie *c=opaque; c->closes++;
    if(c->failure==2) { errno=ENOSPC; return -1; }
    return 0;
}
static int exit_descriptor;
static ssize_t exit_writer(void *opaque, const char *bytes, size_t length)
{
    return write(*(int *)opaque,bytes,length);
}

static int memories(void)
{
    unsigned char data[16]; memset(data,'?',sizeof data);
    FILE *f=fmemopen(data,sizeof data,"w+");
    if(!f) return 10;
    errno=0; record(10, fputs("alpha",f),f,data,sizeof data);
    errno=0; record(11, fflush(f),f,data,sizeof data);
    if(fseek(f,9,SEEK_SET) || fputc('Z',f)==EOF) return 11;
    errno=0; record(12, fflush(f),f,data,sizeof data);
    errno=0; record(13, fseek(f,17,SEEK_SET),f,data,sizeof data);
    rewind(f); unsigned char copy[20]={0};
    errno=0; int count=fread(copy,1,sizeof copy,f); record(14,count,f,copy,sizeof copy);
    fclose(f);
    f=fmemopen(data,4,"w");
    if(!f || setvbuf(f,NULL,_IONBF,0)) return 12;
    errno=0; count=fwrite("abcdef",1,6,f); record(15,count,f,data,8);
    fclose(f);
    memcpy(data,"ab\0rest",7); f=fmemopen(data,8,"a+");
    if(!f || fseek(f,0,SEEK_SET) || fwrite("CD",1,2,f)!=2) return 13;
    errno=0; record(16,fflush(f),f,data,8); fclose(f);
    f=fmemopen(NULL,32,"w+");
    if(!f || fprintf(f,"%d %.2f",17,2.5)!=7 || fseek(f,0,SEEK_SET)) return 14;
    int integer; double real;
    if(fscanf(f,"%d %lf",&integer,&real)!=2 || integer!=17 || real!=2.5 || fclose(f)) return 15;
    char *output=(char *)(uintptr_t)1; size_t size=99;
    f=open_memstream(&output,&size);
    if(!f || !output || size || *output) return 16;
    if(fwrite("abcdef",1,6,f)!=6) return 17;
    errno=0; int status=fflush(f); record(17,status,f,output,size);
    if(fseek(f,2,SEEK_SET) || fwrite("X",1,1,f)!=1) return 18;
    errno=0; status=fflush(f); record(18,status,f,output,size);
    if(size!=3 || memcmp(output,"abXdef\0",7)) return 28;
    if(fseek(f,12,SEEK_SET) || fputc('Z',f)==EOF) return 19;
    errno=0; status=fflush(f); record(19,status,f,output,size);
    errno=0; status=fileno(f); record(20,status,f,output,size);
    if(fclose(f)) return 20;
    record(21,0,NULL,output,size); free(output);
    f=fmemopen(NULL,0,"w+"); if(!f) return 21;
    errno=0; record(22,fgetc(f),f,NULL,0); fclose(f);
    /* musl's w+ initialization writes a first NUL even for logical size zero;
     * provide that real byte, independently of the stream's empty capacity. */
    unsigned char zero_size_sentinel='?';
    f=fmemopen(&zero_size_sentinel,0,"w+");
    if(!f || zero_size_sentinel || fclose(f)) return 29;
    /* A direction error remains set across subsequent successful reads.
     * fgets still returns the accumulated line when the final read hits EOF. */
    unsigned char read_only_data[]="abc";
    f=fmemopen(read_only_data,3,"r");
    if(!f || fwrite("!",1,1,f) || !ferror(f)) return 46;
    char retained_line[5]={0};
    if(fgets(retained_line,sizeof retained_line,f)!=retained_line
        || strcmp(retained_line,"abc") || !feof(f) || !ferror(f)
        || fclose(f)) return 47;
    output=NULL; size=99; f=open_memstream(&output,&size); if(!f) return 22;
    if(fseek(f,((long)1<<31),SEEK_SET) || fputc('X',f)==EOF) return 23;
    struct rlimit original, constrained;
    if(getrlimit(RLIMIT_AS,&original)) return 24;
    constrained=original;
    if(constrained.rlim_cur>256UL*1024*1024) constrained.rlim_cur=256UL*1024*1024;
    if(setrlimit(RLIMIT_AS,&constrained)) return 25;
    errno=0; status=fflush(f); int failure_errno=errno;
    if(setrlimit(RLIMIT_AS,&original)) return 26;
    errno=failure_errno; record(23,status,f,output,size);
    if(size || *output || fclose(f)) return 27;
    free(output);
    return 0;
}

static int cookies(void)
{
    struct cookie state={0};
    cookie_io_functions_t functions={reader,writer,seeker,closer};
    FILE *f=fopencookie(&state,"w+",functions);
    if(!f || fwrite("abcdef",1,6,f)!=6) return 30;
    errno=0; int status=fflush(f); record(30,status,f,state.data,state.len);
    if(state.writes!=2 || fseek(f,0,SEEK_SET)) return 31;
    unsigned char data[16]={0};
    errno=0; int count=fread(data,1,3,f); record(31,count,f,data,sizeof data);
    if(fgetc(f)!='d' || ungetc('d',f)!='d' || fflush(f) || state.pos!=3) return 32;
    if(fclose(f) || state.closes!=1) return 33;
    for(int failure=0;failure<2;failure++) {
        memset(&state,0,sizeof state); state.short_write=!failure; state.failure=failure;
        f=fopencookie(&state,"w",functions); if(!f) return 34;
        if(fwrite("abcdef",1,6,f)!=6) return 35;
        errno=0; status=fflush(f); record(32+failure,status,f,state.data,state.len);
        fclose(f); if(state.closes!=1) return 36;
    }
    memset(&state,0,sizeof state); functions.seek=NULL; functions.read=NULL; functions.write=NULL;
    f=fopencookie(&state,"w+",functions); if(!f) return 37;
    errno=0; status=fseek(f,0,SEEK_SET); record(34,status,f,NULL,0);
    errno=0; status=fgetc(f); record(35,status,f,NULL,0);
    clearerr(f); if(fputs("ignored",f)<0 || fflush(f) || fclose(f) || state.closes!=1) return 38;
    char *output=NULL; size_t length=0;
    memset(&state,0,sizeof state); state.nested=open_memstream(&output,&length);
    functions=(cookie_io_functions_t){reader,writer,seeker,closer};
    f=fopencookie(&state,"w",functions);
    if(!f || !state.nested || fprintf(f,"%s/%d","hello",123)!=9 || fflush(f) || fclose(f)
        || fclose(state.nested) || length!=1 || *output!='!') return 39;
    free(output);
    memset(&state,0,sizeof state); state.short_write=1;
    f=fopencookie(&state,"w",functions); if(!f) return 40;
    errno=0; count=fprintf(f,"%2000s","x"); record(36,count,f,state.data,state.len);
    errno=0; status=fflush(f); record(37,status,f,state.data,state.len); fclose(f);
    memset(&state,0,sizeof state); state.short_write=1;
    f=fopencookie(&state,"w",functions); if(!f) return 41;
    char literal[2001]; memset(literal,'L',2000); literal[2000]=0;
    errno=0; count=fprintf(f,literal); record(38,count,f,state.data,state.len);
    errno=0; status=fflush(f); record(39,status,f,state.data,state.len); fclose(f);
    memset(&state,0,sizeof state); state.failure=1;
    f=fopencookie(&state,"w",functions); if(!f) return 42;
    int counted=-1;
    errno=0; count=fprintf(f,"%2000s%n","x",&counted); record(40,count,f,&counted,sizeof counted);
    fclose(f);
    memset(&state,0,sizeof state); state.failure=2;
    f=fopencookie(&state,"w",functions); if(!f) return 43;
    errno=0; status=fclose(f); record(41,status,NULL,&state.closes,sizeof state.closes);
    memset(&state,0,sizeof state);
    f=fopencookie(&state,"w+",functions); if(!f) return 44;
    if(setvbuf(f,NULL,_IONBF,0)) return 45;
    errno=0; count=fprintf(f,""); record(42,count,f,&state.writes,sizeof state.writes);
    errno=0; status=fseek(f,-1,SEEK_SET); record(43,status,f,NULL,0); fclose(f);
    return 0;
}

/* A global flush holds the stream registry while a newer cookie writes to an
 * older cookie. A failed middle stream must not prevent the older one from
 * receiving that write, and clearing its error must not replay lost bytes. */
struct flush_chain {
    FILE *older;
    unsigned char events[16];
    size_t event_count;
    unsigned char older_bytes[16];
    size_t older_count;
    unsigned char newer_bytes[16];
    size_t newer_count;
    int closes;
};
struct flush_link { struct flush_chain *chain; unsigned char kind; };

static ssize_t flush_chain_write(void *opaque, const char *bytes, size_t length)
{
    struct flush_link *link = opaque;
    struct flush_chain *chain = link->chain;
    if (chain->event_count >= sizeof chain->events) _Exit(81);
    chain->events[chain->event_count++] = link->kind;
    if (link->kind == 'F' && length) { errno = ENOSPC; return -1; }
    if (link->kind == 'N') {
        if (length > sizeof chain->newer_bytes - chain->newer_count) _Exit(82);
        memcpy(chain->newer_bytes + chain->newer_count, bytes, length);
        chain->newer_count += length;
        if (length && fwrite("nested", 1, 6, chain->older) != 6) _Exit(83);
    } else if (link->kind == 'O') {
        if (length > sizeof chain->older_bytes - chain->older_count) _Exit(84);
        memcpy(chain->older_bytes + chain->older_count, bytes, length);
        chain->older_count += length;
    }
    return (ssize_t)length;
}

static int flush_chain_close(void *opaque)
{
    ((struct flush_link *)opaque)->chain->closes++;
    return 0;
}

static int global_cookie_flush(void)
{
    struct flush_chain chain = {0};
    struct flush_link older_link = {&chain, 'O'};
    struct flush_link failed_link = {&chain, 'F'};
    struct flush_link newer_link = {&chain, 'N'};
    cookie_io_functions_t functions = {NULL, flush_chain_write, NULL, flush_chain_close};
    FILE *older = fopencookie(&older_link, "w", functions);
    FILE *failed = fopencookie(&failed_link, "w", functions);
    FILE *newer = fopencookie(&newer_link, "w", functions);
    if (!older || !failed || !newer) return 61;
    chain.older = older;
    if (fwrite("old", 1, 3, older) != 3 ||
        fwrite("lost", 1, 4, failed) != 4 ||
        fwrite("new", 1, 3, newer) != 3) return 62;
    errno = 0;
    int status = fflush(NULL);
    if (status != EOF || errno != ENOSPC || !ferror(failed) ||
        chain.older_count != 9 || memcmp(chain.older_bytes, "oldnested", 9) ||
        chain.newer_count != 3 || memcmp(chain.newer_bytes, "new", 3) ||
        chain.event_count != 5 || memcmp(chain.events, "NNFOO", 5)) return 63;
    record(60, status, NULL, chain.events, sizeof chain.events);
    clearerr(failed);
    errno = 0;
    status = fflush(NULL);
    if (status != 0 || errno != 0 || ferror(failed) || chain.event_count != 5) return 64;
    record(61, status, NULL, chain.events, sizeof chain.events);
    if (fwrite("retry", 1, 5, failed) != 5) return 65;
    errno = 0;
    status = fflush(NULL);
    if (status != EOF || errno != ENOSPC || !ferror(failed) ||
        chain.event_count != 6 || memcmp(chain.events, "NNFOOF", 6)) return 66;
    record(62, status, NULL, chain.events, sizeof chain.events);
    if (fclose(newer) || fclose(failed) || fclose(older) || chain.closes != 3) return 67;
    record(63, chain.closes, NULL, chain.older_bytes, chain.older_count);
    return 0;
}

struct closing_cookie {
    FILE *nested;
    int writes, closes;
    unsigned char events[2];
};

static ssize_t closing_cookie_write(void *opaque, const char *bytes, size_t length)
{
    struct closing_cookie *state = opaque;
    (void)bytes; (void)length;
    if (state->writes + state->closes >= 2) _Exit(86);
    state->events[state->writes++ + state->closes] = 'W';
    errno = EIO;
    return -1;
}

static int closing_cookie_close(void *opaque)
{
    struct closing_cookie *state = opaque;
    if (state->writes + state->closes >= 2) _Exit(87);
    state->events[state->writes + state->closes++] = 'C';
    if (fputs("closed", state->nested) < 0 || fclose(state->nested)) _Exit(85);
    state->nested = NULL;
    errno = ENOSPC;
    return -1;
}

/* A failed pending cookie write still leaves a live close callback. That
 * callback closes a different stream, publishing its caller-owned buffer. */
static int failed_cookie_close(void)
{
    char *output = NULL;
    size_t size = 99;
    struct closing_cookie state = {0};
    state.nested = open_memstream(&output, &size);
    cookie_io_functions_t functions = {NULL, closing_cookie_write, NULL, closing_cookie_close};
    FILE *f = fopencookie(&state, "w", functions);
    if (!state.nested || !f || fwrite("lost", 1, 4, f) != 4) return 81;
    errno = 0;
    int status = fclose(f);
    int saved_errno = errno;
    if (status != EOF || saved_errno != ENOSPC || state.writes != 1 || state.closes != 1 ||
        state.nested || size != 6 || memcmp(output, "closed\0", 7) ||
        memcmp(state.events, "WC", 2)) return 82;
    errno = saved_errno;
    record(75, status, NULL, output, size + 1);
    record(76, state.writes + state.closes, NULL, state.events, sizeof state.events);
    free(output);
    return 0;
}

struct reentry_cookie {
    struct cookie base;
    FILE *nested;
    char *output;
    size_t size;
    int calls;
};

/* Each callback allocates and flushes a different live stream. Its published
 * allocation remains caller-owned after the close callback closes that stream. */
static void callback_other_stream(struct reentry_cookie *state, int marker)
{
    char *scratch = malloc(64);
    if (!scratch) _Exit(92);
    memset(scratch, marker, 64);
    if (fputc(scratch[0], state->nested) == EOF || fflush(state->nested)) _Exit(93);
    free(scratch);
    if (state->size != (size_t)++state->calls || state->output[state->size] != 0) _Exit(94);
}

static ssize_t reentry_read(void *opaque, char *bytes, size_t length)
{
    struct reentry_cookie *state = opaque;
    callback_other_stream(state, 'R');
    return reader(&state->base, bytes, length);
}

static ssize_t reentry_write(void *opaque, const char *bytes, size_t length)
{
    struct reentry_cookie *state = opaque;
    callback_other_stream(state, 'W');
    return writer(&state->base, bytes, length);
}

static int reentry_seek(void *opaque, off_t *offset, int whence)
{
    struct reentry_cookie *state = opaque;
    callback_other_stream(state, 'S');
    return seeker(&state->base, offset, whence);
}

static int reentry_close(void *opaque)
{
    struct reentry_cookie *state = opaque;
    callback_other_stream(state, 'C');
    int status = fclose(state->nested);
    state->nested = NULL;
    state->base.closes++;
    return status;
}

static int cookie_callback_reentry(void)
{
    struct reentry_cookie state = {0};
    state.nested = open_memstream(&state.output, &state.size);
    cookie_io_functions_t functions = {reentry_read, reentry_write, reentry_seek, reentry_close};
    FILE *f = fopencookie(&state, "w+", functions);
    char bytes[3];
    if (!state.nested || !f || setvbuf(f, NULL, _IONBF, 0)) return 83;
    if (fwrite("abc", 1, 3, f) != 3 || fseek(f, 0, SEEK_SET) ||
        fread(bytes, 1, 3, f) != 3 || memcmp(bytes, "abc", 3) || fclose(f)) return 84;
    if (state.nested || state.base.closes != 1 || state.calls != 4 ||
        state.size != 4 || memcmp(state.output, "WSRC\0", 5)) return 85;
    record(77, state.calls, NULL, state.output, state.size + 1);
    free(state.output);
    return 0;
}

/* The same binary record crosses FILE buffering, allocated line input,
 * logical-position restoration, and scanf on two independent backends. */
static int binary_record(void)
{
    static const unsigned char bytes[] = {'A', 'B', 0, 'C', 'D', 0, 'E'};
    struct cookie state={0};
    memcpy(state.data, bytes, sizeof bytes);
    state.len=sizeof bytes;
    cookie_io_functions_t functions={reader,writer,seeker,closer};
    for (int backend=0; backend<2; backend++) {
        FILE *f=backend ? fopencookie(&state,"r",functions)
                        : fmemopen((void *)bytes,sizeof bytes,"r");
        if (!f) return 50;
        char buffer[32];
        if (setvbuf(f,buffer,_IOFBF,sizeof buffer)) return 51;
        fpos_t start;
        if (fgetpos(f,&start)) return 52;
        char *line=NULL; size_t capacity=0;
        errno=0;
        ssize_t length=getdelim(&line,&capacity,0,f);
        if (length!=3 || memcmp(line,bytes,3) || ftell(f)!=3) return 53;
        record(50+backend,(int)length,f,line,(size_t)length);
        if (fsetpos(f,&start) || ftell(f)!=0) return 54;
        char prefix[3]={0};
        if (fscanf(f,"%2c",prefix)!=1 || memcmp(prefix,"AB",2)) return 55;
        if (fgetc(f)!=0 || ftell(f)!=3) return 56;
        errno=0;
        length=getdelim(&line,&capacity,0,f);
        if (length!=3 || memcmp(line,"CD\0",3)) return 57;
        record(52+backend,(int)length,f,line,(size_t)length);
        if (fgetc(f)!='E' || fgetc(f)!=EOF || !feof(f) || ferror(f)) return 58;
        free(line);
        if (fclose(f)) return 59;
    }
    if (state.closes!=1) return 60;
    return 0;
}

/* A cookie read fills the user buffer, then fails at its next callback.
 * Recovery must discard the error while preserving the logical seek target. */
static int cookie_read_recovery(void)
{
    struct cookie state={0};
    memcpy(state.data,"abcdef",6); state.len=6; state.read_fail_at=2;
    cookie_io_functions_t functions={reader,writer,seeker,closer};
    FILE *f=fopencookie(&state,"r+",functions);
    if (!f) return 70;
    char buffer[3];
    if (setvbuf(f,buffer,_IOFBF,sizeof buffer)) return 71;
    for (int index=0; index<6; index++)
        if (fgetc(f)!='a'+index) return 72;
    errno=0;
    int result=fgetc(f); record(70,result,f,&state.reads,sizeof state.reads);
    if (result!=EOF || !ferror(f) || feof(f)) return 73;
    clearerr(f); state.read_fail_at=0;
    errno=0;
    result=fseek(f,1,SEEK_SET); record(71,result,f,&state.pos,sizeof state.pos);
    if (result || ferror(f) || fgetc(f)!='b') return 74;
    errno=0;
    result=fseek(f,-1,SEEK_CUR); record(72,result,f,&state.pos,sizeof state.pos);
    if (result || fgetc(f)!='b' || fclose(f) || state.closes!=1) return 75;
    return 0;
}

/* A fixed stream permits a seek into its unwritten capacity. EOF from that
 * position does not erase the earlier bytes, and a later seek clears EOF. */
static int fixed_seek_recovery(void)
{
    unsigned char data[8]="ab";
    FILE *f=fmemopen(data,sizeof data,"a+");
    if (!f || fseek(f,6,SEEK_SET)) return 76;
    errno=0;
    int result=fgetc(f); record(73,result,f,data,sizeof data);
    if (result!=EOF || !feof(f) || ferror(f)) return 77;
    errno=0;
    result=fseek(f,0,SEEK_SET); record(74,result,f,data,sizeof data);
    if (result || feof(f) || fgetc(f)!='a' || fclose(f)) return 78;
    return 0;
}
#endif

int main(int argc,char **argv)
{
    if(argc!=2) return 80;
    int status=descriptor(argv[1]); if(status) return status;
#ifndef DESCRIPTOR_ONLY
    status=memories(); if(status) return status;
    status=cookies(); if(status) return status;
    status=global_cookie_flush(); if(status) return status;
    status=failed_cookie_close(); if(status) return status;
    status=cookie_callback_reentry(); if(status) return status;
    status=binary_record(); if(status) return status;
    status=cookie_read_recovery(); if(status) return status;
    status=fixed_seek_recovery(); if(status) return status;
    /* Deliberately left open: ordinary exit must flush the registered cookie.
     * Userdata is static and survives main; no close callback is expected. */
    exit_descriptor=open(argv[1],O_WRONLY|O_CREAT|O_TRUNC,0600);
    cookie_io_functions_t functions={NULL,exit_writer,NULL,NULL};
    FILE *exit_stream=fopencookie(&exit_descriptor,"w",functions);
    if(exit_descriptor<0 || !exit_stream || fputs("backend-exit\n",exit_stream)<0) return 79;
#endif
    return 0;
}

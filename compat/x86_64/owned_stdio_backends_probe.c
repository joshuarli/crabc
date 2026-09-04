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
struct cookie { unsigned char data[4096]; size_t pos, len; int reads, writes, closes, short_write, failure; FILE *nested; };
static ssize_t reader(void *opaque, char *buffer, size_t length)
{
    struct cookie *c=opaque; c->reads++;
    if (c->failure) { errno=EIO; return -1; }
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
#endif

int main(int argc,char **argv)
{
    if(argc!=2) return 80;
    int status=descriptor(argv[1]); if(status) return status;
#ifndef DESCRIPTOR_ONLY
    status=memories(); if(status) return status;
    status=cookies(); if(status) return status;
    /* Deliberately left open: ordinary exit must flush the registered cookie.
     * Userdata is static and survives main; no close callback is expected. */
    exit_descriptor=open(argv[1],O_WRONLY|O_CREAT|O_TRUNC,0600);
    cookie_io_functions_t functions={NULL,exit_writer,NULL,NULL};
    FILE *exit_stream=fopencookie(&exit_descriptor,"w",functions);
    if(exit_descriptor<0 || !exit_stream || fputs("backend-exit\n",exit_stream)<0) return 79;
#endif
    return 0;
}

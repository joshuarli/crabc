#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Independent invariants: RFC 9636 sections 3.1/3.2 and POSIX tzset.
   `observe` retains pinned-musl bug output without treating it as acceptance;
   `check` asserts specification behavior in the owned product. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"tzif:%d\n",__LINE__); exit(1); } } while (0)
static void be32(unsigned char *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static size_t block(unsigned char *p, int version, int width, int count,
    int first_dst, int offset0, int offset1) {
    memset(p,0,128); memcpy(p,"TZif",4); p[4]=version;
    be32(p+32,count); be32(p+36,2); be32(p+40,8);
    size_t n=44;
    for (int i=0;i<count;i++) { if (width==8) { be32(p+n,0); n+=4; }
        be32(p+n,86400*(i+1)); n+=4; }
    for (int i=0;i<count;i++) p[n++]=i ? 0 : 1;
    be32(p+n,offset0); p[n+4]=first_dst; n+=6;
    be32(p+n,offset1); p[n+5]=4; n+=6;
    memcpy(p+n,"ONE\0TWO\0",8); return n+8;
}
static void run(const char *path, int check, int tag, int version, int count,
    int first_dst, int offset0, int offset1, const char *footer,
    long expected_offset, long expected_timezone, int expected_dst, const char *expected_name) {
    unsigned char bytes[512]; size_t n=0;
    n+=block(bytes+n,version,4,version ? 0 : count,first_dst,offset0,offset1);
    if (version) {
        n+=block(bytes+n,version,8,count,first_dst,offset0,offset1);
        bytes[n++]='\n'; size_t len=strlen(footer); memcpy(bytes+n,footer,len); n+=len; bytes[n++]='\n';
    }
    FILE *file=fopen(path,"wb"); CHECK(file && fwrite(bytes,1,n,file)==n && !fclose(file));
    CHECK(!setenv("TZ","UTC0",1)); tzset();
    CHECK(!setenv("TZ",path,1)); tzset();
    time_t t=0; struct tm tm; CHECK(localtime_r(&t,&tm));
    printf("%d offset=%ld timezone=%ld dst=%d name=%s\n",tag,tm.tm_gmtoff,timezone,tm.tm_isdst,tm.tm_zone);
    if (check) CHECK(tm.tm_gmtoff==expected_offset && timezone==expected_timezone &&
        tm.tm_isdst==expected_dst && !strcmp(tm.tm_zone,expected_name));
    CHECK(!unlink(path));
}
int main(int argc, char **argv) {
    CHECK(argc==3); int check=!strcmp(argv[2],"check");
    run(argv[1],check,1,0,0,0,3600,3600,"",3600,-3600,0,"ONE");
    run(argv[1],check,2,0,0,0,-18000,-18000,"",-18000,18000,0,"ONE");
    run(argv[1],check,3,'2',0,0,0,0,"XXX-3",10800,-10800,0,"XXX");
    run(argv[1],check,4,'2',2,1,7200,3600,"TWO-1",7200,-3600,1,"ONE");
    run(argv[1],check,5,'3',1,1,7200,3600,"TWO-1",7200,-3600,1,"ONE");
    run(argv[1],check,6,'2',0,0,3600,3600,"",3600,-3600,0,"ONE");
    return 0;
}

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"service lookup line %d errno %d\n",__LINE__,errno); return 1; } } while (0)
int main(void)
{
    FILE *file=fopen("/etc/services","w"); CHECK(file);
    CHECK(fputs("alpha 4242/tcp alias shared # comment\nbeta 4343/udp shared\nzero 0/tcp\nlongcanonical 4545/tcp\n",file)>=0);
    CHECK(!fclose(file));
    struct servent record,*result;
    char storage[128];
    for (unsigned offset=0;offset<8;offset++) {
        char *buffer=storage+offset;
        size_t align=-(size_t)buffer&7;
        memset(storage,0x5a,sizeof storage); errno=EDOM; result=(void*)1;
        CHECK(getservbyname_r("alias","tcp",&record,buffer,16+align-1,&result)==ERANGE && !result && errno==EINVAL);
        for (unsigned i=0;i<sizeof storage;i++) CHECK(storage[i]==0x5a);
        CHECK(!getservbyname_r("alias","tcp",&record,buffer,16+align,&result) && result==&record);
        CHECK(!strcmp(record.s_name,"alias") && record.s_aliases[0]==record.s_name && !record.s_aliases[1]);
        CHECK(record.s_port==htons(4242) && !strcmp(record.s_proto,"tcp"));
        CHECK((char*)record.s_aliases>=buffer && (char*)(record.s_aliases+2)<=buffer+16+align);
        result=(void*)1; errno=EDOM;
        CHECK(getservbyport_r(htons(4545),"tcp",&record,buffer,16+align+13,&result)==ERANGE && !result && errno==EDOM);
        CHECK(!getservbyport_r(htons(4545),"tcp",&record,buffer,16+align+14,&result) && result==&record);
        CHECK(!strcmp(record.s_name,"longcanonical") && record.s_name==record.s_aliases[0] && !record.s_aliases[1]);
        CHECK(record.s_name>=buffer && record.s_name+14<=buffer+16+align+14);
    }
    errno=EDOM;
    CHECK(getservbyname_r("4242","tcp",&record,storage,sizeof storage,&result)==ENOENT && !result && errno==EDOM);
    CHECK(getservbyname_r("alias","sctp",&record,storage,sizeof storage,&result)==EINVAL && !result && errno==EINVAL);
    CHECK(getservbyname_r("absent","tcp",&record,storage,sizeof storage,&result)==ENOENT && !result && errno==EINVAL);
    CHECK(!getservbyname_r("shared",NULL,&record,storage,sizeof storage,&result) && result && record.s_port==htons(4242));
    CHECK(!getservbyname_r("shared","udp",&record,storage,sizeof storage,&result) && result && record.s_port==htons(4343));
    CHECK(!getservbyname_r("zero","tcp",&record,storage,sizeof storage,&result) && result && !record.s_port);
    CHECK(getservbyport_r(htons(4244),NULL,&record,storage,sizeof storage,&result)==ENOENT && !result);
    struct servent *named=getservbyname("alpha","tcp"); CHECK(named && named->s_port==htons(4242));
    struct servent *reverse=getservbyport(htons(4343),NULL); CHECK(reverse && reverse!=named && !strcmp(reverse->s_name,"beta"));
    CHECK(named->s_port==htons(4242));
    CHECK(getservbyname("beta","udp")==named && named->s_port==htons(4343));
    CHECK(!strcmp(reverse->s_name,"beta"));
    puts("service lookup caller buffer and separate shared owners passed");
    return 0;
}

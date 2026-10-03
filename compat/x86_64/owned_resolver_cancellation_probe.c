#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "owned_cancellation_proc_witness.h"

#define CHECK(c) do { if (!(c)) { dprintf(2,"resolver cancellation line %d errno %d\n",__LINE__,errno); _exit(77); } } while (0)
static int baseline, cleanup_count, cleanup_fds, returned, state_after, result_errno, successful;
static atomic_int extra_fds;
static atomic_int worker_tid;
static const char *scenario, *api;
static int uses_server, tcp_case, initial_state, cancel_before_tcp, socket_failure, kernel_canceled;
static int normal_case, retry_case, reuse_case, dual_mixed_later_errno_case, post_tcp_later_eagain_case;
static int retained_case;
static char *retained_buffer;
static struct addrinfo *retained_result;
static int descriptor_count(void) {
    int count=0;
    for(int fd=0;fd<512;fd++) {
        if(fcntl(fd,F_GETFD)>=0) count++;
        else CHECK(errno==EBADF);
    }
    return count;
}
static void cleanup(void *unused) {
    (void)unused;
    cleanup_fds=descriptor_count()-baseline-atomic_load(&extra_fds);
    if(retained_case) {
        /* Cancellation retires the in-flight resolver descriptors before
           caller cleanup releases an earlier, independently owned result. */
        CHECK(retained_result&&!retained_result->ai_next&&retained_result->ai_family==AF_INET);
        CHECK(((struct sockaddr_in*)retained_result->ai_addr)->sin_addr.s_addr==htonl(INADDR_LOOPBACK));
        CHECK(((struct sockaddr_in*)retained_result->ai_addr)->sin_port==htons(80));
        for(unsigned i=0;i<4096;i++)CHECK(retained_buffer[i]==(char)(i%127));
        freeaddrinfo(retained_result);free(retained_buffer);
        retained_result=0;retained_buffer=0;
    }
    cleanup_count++;
}
static void query(void) {
    unsigned char answer[512];
    if(!strcmp(api,"query")) successful=res_query("cancel.example.test",1,1,answer,sizeof answer)>=12;
    else if(!strcmp(api,"send")) {
        unsigned char request[512];
        int n=res_mkquery(0,"cancel.example.test",1,1,0,0,0,request,sizeof request);
        CHECK(n>0);successful=res_send(request,n,answer,sizeof answer)>=12;
    } else if(!strcmp(api,"classic")) {
        struct hostent host,*result;char buffer[4096];int error;
        successful=!gethostbyname_r("cancel.example.test",&host,buffer,sizeof buffer,&result,&error) && result!=0;
    } else if(!strcmp(api,"modern")) {
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*result=0;
        successful=!getaddrinfo("cancel.example.test",0,&hints,&result) && result!=0;if(result) freeaddrinfo(result);
    } else if(!strcmp(api,"modern-dual")) {
        struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM},*result=0;
        successful=!getaddrinfo("cancel.example.test",0,&hints,&result) && result!=0;if(result) freeaddrinfo(result);
    } else if(!strcmp(api,"reverse")) {
        struct sockaddr_in address={.sin_family=AF_INET};char name[256];
        CHECK(inet_pton(AF_INET,"198.51.100.23",&address.sin_addr)==1);
        successful=!getnameinfo((void *)&address,sizeof address,name,sizeof name,0,0,NI_NAMEREQD)
                   && !strcmp(name,"resolved.example.test");
    } else CHECK(0);
}
static void syscall_error(int number,int error,int stream_only) {
    struct instruction { unsigned short code;unsigned char yes,no;unsigned value; };
    struct program { unsigned short count;struct instruction *instructions; };
    struct instruction instructions[]={
        {0x20,0,0,0}, {0x15,0,4,(unsigned)number},
        {0x20,0,0,24}, {0x54,0,0,15}, {0x15,0,1,1},
        {0x06,0,0,0x00050000u|(unsigned)error}, {0x06,0,0,0x7fff0000u},
    };
    if(!stream_only) { instructions[1].no=1;instructions[2]=instructions[5];instructions[3]=instructions[6]; }
    struct program program={(unsigned short)(stream_only?7:4),instructions};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    CHECK(!prctl(PR_SET_SECCOMP,2,&program));
}
static void *worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid,(int)syscall(SYS_gettid));
    if(retained_case) {
        retained_buffer=malloc(4096);CHECK(retained_buffer);
        for(unsigned i=0;i<4096;i++)retained_buffer[i]=(char)(i%127);
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM};
        CHECK(!getaddrinfo("127.0.0.1","80",&hints,&retained_result)&&retained_result);
    }
    pthread_cleanup_push(cleanup,0);
    if(!uses_server && !kernel_canceled) {
        CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,0));
        CHECK(!pthread_cancel(pthread_self()));
    }
    CHECK(!pthread_setcancelstate(initial_state,0));
    if(socket_failure) syscall_error(SYS_socket,EMFILE,socket_failure==2);
    if(kernel_canceled) syscall_error(SYS_sendto,ECANCELED,0);
    if(reuse_case) { query();CHECK(successful);successful=0; }
    query();result_errno=errno;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&state_after));
    returned=1;
    pthread_cleanup_pop(0);
    return (void *)42;
}
static int server(int type) {
    int fd=socket(AF_INET,type,0);CHECK(fd>=0);
    int one=1;CHECK(!setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one));
    struct timeval timeout={.tv_sec=3};
    CHECK(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout));
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(53),.sin_addr={htonl(INADDR_LOOPBACK)}};
    CHECK(!bind(fd,(void *)&address,sizeof address));
    if(type==SOCK_STREAM) CHECK(!listen(fd,1));
    return fd;
}
static void read_exact(int fd,unsigned char *p,size_t n) {
    while(n) { ssize_t r=read(fd,p,n);CHECK(r>0);p+=r;n-=(size_t)r; }
}
static size_t dns_answer(unsigned char *packet,size_t length) {
    CHECK(length>=12 && length+40<512);
    unsigned kind=((unsigned)packet[length-4]<<8)|packet[length-3];
    CHECK(kind==1 || kind==12 || kind==28);
    packet[2]=0x81;packet[3]=0x80;packet[6]=0;packet[7]=1;
    const unsigned char record[]={0xc0,0x0c,0,0,0,1,0,0,0,30,0,0};
    memcpy(packet+length,record,sizeof record);packet[length+3]=(unsigned char)kind;
    const unsigned char address[]={198,51,100,23};
    const unsigned char address6[]={32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,23};
    const unsigned char name[]={8,'r','e','s','o','l','v','e','d',7,'e','x','a','m','p','l','e',4,'t','e','s','t',0};
    size_t amount=kind==1?sizeof address:kind==28?sizeof address6:sizeof name;
    packet[length+11]=(unsigned char)amount;
    memcpy(packet+length+sizeof record,kind==1?address:kind==28?address6:name,amount);
    return length+sizeof record+amount;
}
static void witness_blocked_wait(void) {
    const struct timespec pause={0,1000000};
    for(int attempt=0;attempt<500;attempt++) {
        char path[96],record[256];
        snprintf(path,sizeof path,"/proc/self/task/%d/syscall",atomic_load(&worker_tid));
        int fd=owned_cancellation_open_proc(path);CHECK(fd>=0);
        ssize_t n=read(fd,record,sizeof record-1);CHECK(!close(fd));
        if(n>0) {
            record[n]=0;long number=-1;
            if(sscanf(record,"%ld",&number)==1 && (number==SYS_poll || number==SYS_ppoll)) return;
        }
        CHECK(!nanosleep(&pause,0));
    }
    CHECK(0);
}

static int network_success, network_errno, network_h_errno, network_cleanup_errno;
static int network_cleanup_h_errno, network_returned, network_state, network_cleanup;
static int network_baseline, network_extra_fd;
static void network_cleanup_handler(void *unused) {
    (void)unused;
    network_cleanup++;
    network_cleanup_errno=errno;
    network_cleanup_h_errno=h_errno;
    CHECK(descriptor_count()==network_baseline+network_extra_fd);
}
static void *network_worker(void *unused) {
    (void)unused;
    atomic_store(&worker_tid,(int)syscall(SYS_gettid));
    pthread_cleanup_push(network_cleanup_handler,0);
    errno=157;
    h_errno=37;
    query();
    network_success=successful;
    network_errno=errno;
    network_h_errno=h_errno;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&network_state));
    network_returned=1;
    pthread_cleanup_pop(0);
    return (void *)42;
}
static int network_server(unsigned char last) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);CHECK(fd>=0);
    struct timeval timeout={.tv_sec=4};
    CHECK(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout));
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(53)};
    unsigned char *bytes=(unsigned char *)&address.sin_addr;
    bytes[0]=127;bytes[1]=0;bytes[2]=0;bytes[3]=last;
    CHECK(!bind(fd,(void *)&address,sizeof address));
    return fd;
}
static int network_main(const char *mode) {
    CHECK(!strcmp(api,"query") || !strcmp(api,"send") || !strcmp(api,"classic"));
    int config=open("/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(config>=0);
    const char *single="nameserver 127.0.0.1\noptions timeout:1 attempts:2\n";
    const char *failover="nameserver 127.0.0.2\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n";
    const char *setting=!strcmp(mode,"failover")?failover:single;
    CHECK(write(config,setting,strlen(setting))==(ssize_t)strlen(setting));CHECK(!close(config));
    int hosts=open("/etc/hosts",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(hosts>=0);CHECK(!close(hosts));
    int udp=network_server(1),first=-1,tcp=-1,accepted=-1;
    if(!strcmp(mode,"failover")) first=network_server(2);
    if(!strcmp(mode,"tcp-wait")) tcp=server(SOCK_STREAM);
    network_baseline=descriptor_count();
    int parent_h_errno=h_errno;
    pthread_t thread;CHECK(!pthread_create(&thread,0,network_worker,0));
    unsigned char packet[512];struct sockaddr_in peer;socklen_t size=sizeof peer;
    ssize_t n=recvfrom(udp,packet,sizeof packet,0,(void *)&peer,&size);CHECK(n>=12);
    if(!strcmp(mode,"udp-wait")) {
        witness_blocked_wait();CHECK(!pthread_cancel(thread));
    } else if(!strcmp(mode,"tcp-wait")) {
        packet[2]|=0x82;packet[3]|=0x80;
        CHECK(sendto(udp,packet,(size_t)n,0,(void *)&peer,size)==n);
        accepted=accept(tcp,0,0);CHECK(accepted>=0);
        network_extra_fd=1;
        unsigned char length[2];read_exact(accepted,length,2);
        unsigned amount=((unsigned)length[0]<<8)|length[1];CHECK(amount<=sizeof packet);
        read_exact(accepted,packet,amount);
        witness_blocked_wait();CHECK(!pthread_cancel(thread));
    } else if(!strcmp(mode,"retry-timeout")) {
        size=sizeof peer;n=recvfrom(udp,packet,sizeof packet,0,(void *)&peer,&size);CHECK(n>=12);
    } else if(!strcmp(mode,"failover")) {
        unsigned char dropped[512];struct sockaddr_in ignored;socklen_t ignored_size=sizeof ignored;
        CHECK(recvfrom(first,dropped,sizeof dropped,0,(void *)&ignored,&ignored_size)>=12);
        size_t length=dns_answer(packet,(size_t)n);
        CHECK(sendto(udp,packet,length,0,(void *)&peer,size)==(ssize_t)length);
    } else CHECK(0);
    void *joined=0;CHECK(!pthread_join(thread,&joined));
    int parent_h_errno_after=h_errno;
    int leaked=descriptor_count()-network_baseline-network_extra_fd;
    printf("canceled=%d returned=%d cleanup=%d leaked=%d success=%d state=%d errno=%d h_errno=%d cleanup_errno=%d cleanup_h_errno=%d parent_h_errno_same=%d\n",
           joined==PTHREAD_CANCELED,network_returned,network_cleanup,leaked,network_success,
           network_state,network_errno,network_h_errno,network_cleanup_errno,
           network_cleanup_h_errno,parent_h_errno_after==parent_h_errno);
    CHECK(!leaked && parent_h_errno_after==parent_h_errno);
    if(!strcmp(mode,"udp-wait") || !strcmp(mode,"tcp-wait"))
        CHECK(joined==PTHREAD_CANCELED && !network_returned && network_cleanup==1);
    else CHECK(joined==(void *)42 && network_returned && !network_cleanup &&
               network_success==!strcmp(mode,"failover"));
    if(accepted>=0) CHECK(!close(accepted));
    if(tcp>=0) CHECK(!close(tcp));
    if(first>=0) CHECK(!close(first));
    CHECK(!close(udp));
    return 0;
}
int main(int argc,char **argv) {
    CHECK(argc==3);scenario=argv[1];api=argv[2];
    if(!strncmp(scenario,"network-",8)) return network_main(scenario+8);
    retained_case=!strcmp(scenario,"udp")||!strcmp(scenario,"tcp")||!strcmp(scenario,"reuse-cancel-udp")||
                  !strcmp(scenario,"retained-cancel-udp")||!strcmp(scenario,"retained-cancel-tcp");
    uses_server=strstr(scenario,"udp")!=0 || strstr(scenario,"tcp")!=0;
    tcp_case=strstr(scenario,"tcp")!=0;
    normal_case=!strncmp(scenario,"normal-",7) || !strcmp(scenario,"retry-udp");
    retry_case=!strncmp(scenario,"retry-",6);
    reuse_case=!strcmp(scenario,"reuse-cancel-udp");
    initial_state=!strncmp(scenario,"masked",6)?PTHREAD_CANCEL_MASKED:
                  !strncmp(scenario,"disabled",8)?PTHREAD_CANCEL_DISABLE:PTHREAD_CANCEL_ENABLE;
    cancel_before_tcp=!strcmp(scenario,"masked-udp-to-tcp") || !strcmp(scenario,"masked-tcp-socket-failure") || !strcmp(scenario,"masked-dual-mixed-tcp");
    /* In the two-request batch both cells cancel the witnessed poll, then send
       the truncated A and the paired AAAA as separate datagrams, so the
       drain after the consumed MASKED request may find the AAAA not yet
       queued and end on EAGAIN. */
    dual_mixed_later_errno_case=(!strcmp(scenario,"masked-dual-mixed-tcp") || !strcmp(scenario,"masked-udp-to-tcp")) && !strcmp(api,"modern-dual");
    /* This dedicated source-shaped cell proves that a consumed MASKED request
       need not retain ECANCELED if a later nonblocking UDP drain finds the
       socket empty. It is intentionally admitted only for the two-request
       batch, whose first A slot has already moved to TCP. */
    post_tcp_later_eagain_case=!strcmp(scenario,"masked-dual-post-tcp-later-eagain");
    if(post_tcp_later_eagain_case) CHECK(!strcmp(api,"modern-dual"));
    socket_failure=!strcmp(scenario,"setup-pending")?1:!strcmp(scenario,"masked-tcp-socket-failure")?2:0;
    kernel_canceled=!strcmp(scenario,"kernel-canceled");
    if(kernel_canceled) initial_state=PTHREAD_CANCEL_MASKED;
    const struct rlimit descriptor_limit={512,512};
    CHECK(!setrlimit(RLIMIT_NOFILE,&descriptor_limit));
    int config=open("/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(config>=0);
    char bytes[96];int config_size=snprintf(bytes,sizeof bytes,"nameserver 127.0.0.1\noptions timeout:1 attempts:%d\n",retry_case?2:1);
    CHECK(config_size>0 && config_size<(int)sizeof bytes);
    CHECK(write(config,bytes,(size_t)config_size)==config_size);CHECK(!close(config));
    int hosts=open("/etc/hosts",O_WRONLY|O_CREAT|O_TRUNC,0600);CHECK(hosts>=0);CHECK(!close(hosts));
    int udp=server(SOCK_DGRAM),tcp=server(SOCK_STREAM),accepted=-1;
    baseline=descriptor_count();CHECK(baseline>=6);
    pthread_t thread;CHECK(!pthread_create(&thread,0,worker,0));
    if(uses_server) {
        unsigned char packet[2][512];struct sockaddr_in peer[2];socklen_t size[2];ssize_t n[2];
        int packets=!strcmp(api,"modern-dual")?2:1;
        for(int i=0;i<packets;i++) { size[i]=sizeof peer[i];n[i]=recvfrom(udp,packet[i],sizeof packet[i],0,(void *)&peer[i],&size[i]);CHECK(n[i]>=12); }
        if(reuse_case) {
            for(int i=0;i<packets;i++) { size_t length=dns_answer(packet[i],(size_t)n[i]);CHECK(sendto(udp,packet[i],length,0,(void *)&peer[i],size[i])==(ssize_t)length); }
            for(int i=0;i<packets;i++) { size[i]=sizeof peer[i];n[i]=recvfrom(udp,packet[i],sizeof packet[i],0,(void *)&peer[i],&size[i]);CHECK(n[i]>=12); }
        }
        if(retry_case || reuse_case) {
            if(!reuse_case) for(int i=0;i<packets;i++) { size[i]=sizeof peer[i];n[i]=recvfrom(udp,packet[i],sizeof packet[i],0,(void *)&peer[i],&size[i]);CHECK(n[i]>=12); }
        }
        if(cancel_before_tcp) { witness_blocked_wait();CHECK(!pthread_cancel(thread)); }
        if(tcp_case) {
            packet[0][2]|=0x82;packet[0][3]|=0x80;
            CHECK(sendto(udp,packet[0],(size_t)n[0],0,(void *)&peer[0],size[0])==n[0]);
            if(!post_tcp_later_eagain_case) {
                /* The paired AAAA remains UDP while the first A slot follows TCP. */
                for(int i=1;i<packets;i++) { size_t length=dns_answer(packet[i],(size_t)n[i]);CHECK(sendto(udp,packet[i],length,0,(void *)&peer[i],size[i])==(ssize_t)length); }
            }
            if(!socket_failure) {
                accepted=accept(tcp,0,0);CHECK(accepted>=0);atomic_store(&extra_fds,1);
                unsigned char length[2];read_exact(accepted,length,2);
                unsigned amount=((unsigned)length[0]<<8)|length[1];CHECK(amount<=sizeof packet[0]);
                read_exact(accepted,packet[0],amount);n[0]=amount;
            }
            if(post_tcp_later_eagain_case) {
                /* The first TC reply has started TCP and the second UDP
                   receive already found no packet. Cancel the next witnessed
                   poll, then wake it with the retired A ID. The source drain
                   ignores that datagram for the pending AAAA slot and makes
                   one later empty recvmsg, whose EAGAIN is the final residue. */
                witness_blocked_wait();CHECK(!pthread_cancel(thread));
                CHECK(sendto(udp,packet[0],(size_t)n[0],0,(void *)&peer[0],size[0])==n[0]);
            }
        }
        if(normal_case) {
            size_t length=dns_answer(packet[0],(size_t)n[0]);
            if(tcp_case) {
                unsigned char prefix[]={(unsigned char)(length>>8),(unsigned char)length};
                CHECK(write(accepted,prefix,2)==2);CHECK(write(accepted,packet[0],length)==(ssize_t)length);
            } else {
                CHECK(sendto(udp,packet[0],length,0,(void *)&peer[0],size[0])==(ssize_t)length);
                for(int i=1;i<packets;i++) { length=dns_answer(packet[i],(size_t)n[i]);CHECK(sendto(udp,packet[i],length,0,(void *)&peer[i],size[i])==(ssize_t)length); }
            }
        } else if(!cancel_before_tcp && !post_tcp_later_eagain_case) { witness_blocked_wait();CHECK(!pthread_cancel(thread)); }
    }
    void *joined=0;CHECK(!pthread_join(thread,&joined));
    if(retained_case)CHECK(!retained_result&&!retained_buffer);
    int leaked=descriptor_count()-baseline-atomic_load(&extra_fds);
    unsigned char packet[512];ssize_t received=recv(udp,packet,sizeof packet,MSG_DONTWAIT);
    CHECK(received>=0 || errno==EAGAIN);int transmitted=received>=0;
    printf("canceled=%d returned=%d cleanup=%d cleanup_fds=%d leaked=%d state=%d transmitted=%d success=%d errno=%d\n",
           joined==PTHREAD_CANCELED,returned,cleanup_count,cleanup_fds,leaked,state_after,transmitted,successful,result_errno);
    if(accepted>=0) CHECK(!close(accepted));CHECK(!close(tcp));CHECK(!close(udp));
    if((uses_server && initial_state==PTHREAD_CANCEL_ENABLE && !normal_case) || !strcmp(scenario,"pending"))
        CHECK(joined==PTHREAD_CANCELED && !returned && cleanup_count==1 && !cleanup_fds && !leaked && !transmitted);
    else {
        int expected=kernel_canceled?PTHREAD_CANCEL_MASKED:socket_failure==1 || normal_case?PTHREAD_CANCEL_ENABLE:PTHREAD_CANCEL_DISABLE;
        CHECK(joined==(void *)42 && returned && !cleanup_count && !leaked && state_after==expected);
        /* In musl's two-query batch, a MASKED cancellation consumed by the
           first UDP send changes the actual state to DISABLE; the second
           source slot can then transmit. */
        int expected_transmitted=!uses_server && (initial_state==PTHREAD_CANCEL_DISABLE || !kernel_canceled && !strcmp(api,"modern-dual") && initial_state==PTHREAD_CANCEL_MASKED);
        CHECK(transmitted==expected_transmitted);
        if(post_tcp_later_eagain_case) CHECK(result_errno==EAGAIN);
        else if(dual_mixed_later_errno_case) CHECK(result_errno==ECANCELED || result_errno==EAGAIN);
        else if(initial_state==PTHREAD_CANCEL_MASKED && !kernel_canceled) CHECK(result_errno==ECANCELED);
        if(socket_failure==1) CHECK(result_errno==EMFILE);
        CHECK(successful==normal_case);
    }
    return 0;
}

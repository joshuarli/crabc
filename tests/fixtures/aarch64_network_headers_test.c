#include <stddef.h>
#include <stdio.h>
#include <signal.h>

#include <arpa/ftp.h>
#undef ERROR
#include <arpa/telnet.h>
#undef ABORT
#undef NOP
#include <arpa/tftp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>
#include <sys/procfs.h>
#include <sys/reg.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <ucontext.h>

int main(void) {
    printf("ether %zu %zu %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct ether_addr), sizeof(struct ether_header),
           offsetof(struct ether_header, ether_dhost),
           offsetof(struct ether_header, ether_shost),
           offsetof(struct ether_header, ether_type),
           sizeof(struct ethhdr), ETHERTYPE_IP, ETHERTYPE_IPV6,
           ETHERMTU, ETHERMIN);

    printf("arp %zu %zu %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct arphdr), sizeof(struct arpreq),
           sizeof(struct arpreq_old), sizeof(struct arpd_request),
           offsetof(struct arpreq, arp_dev), offsetof(struct arpd_request, ha),
           ARPHRD_ETHER, ARPHRD_LOOPBACK, ARPOP_REQUEST, ARPOP_NAK);

    printf("route %zu %zu %zu %zu %zu %zu %zu %d %d %d\n",
           sizeof(struct rtentry), offsetof(struct rtentry, rt_dst),
           offsetof(struct rtentry, rt_gateway), offsetof(struct rtentry, rt_genmask),
           offsetof(struct rtentry, rt_flags), offsetof(struct rtentry, rt_dev),
           sizeof(struct in6_rtmsg), RTF_DEFAULT, RTF_LOCAL, RTMSG_CONTROL);

    printf("ip %zu %zu %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct iphdr), sizeof(struct ip), sizeof(struct icmphdr),
           sizeof(struct icmp), offsetof(struct ip, ip_src),
           offsetof(struct icmp, icmp_dun), IPVERSION, IP_DF,
           ICMP_SOURCE_QUENCH, ICMP_INFOTYPE(ICMP_ECHO));

    printf("ip6 %zu %zu %zu %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct ip6_hdr), sizeof(struct ip6_ext),
           sizeof(struct ip6_rthdr), sizeof(struct ip6_rthdr0),
           sizeof(struct ip6_frag), offsetof(struct ip6_hdr, ip6_src),
           offsetof(struct ip6_hdr, ip6_dst), IP6F_MORE_FRAG,
           IP6OPT_JUMBO, ICMP6_ECHO_REQUEST, ND_NEIGHBOR_ADVERT);

    printf("icmp6 %zu %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct icmp6_filter), sizeof(struct icmp6_hdr),
           sizeof(struct nd_router_advert), sizeof(struct nd_neighbor_advert),
           sizeof(struct nd_opt_prefix_info), ICMP6_FILTER_BLOCK,
           ND_RA_FLAG_MANAGED, ND_OPT_PREFIX_INFORMATION,
           ICMP6_PARAMPROB_OPTION);

    printf("igmp %zu %zu %zu %d %d %d\n",
           sizeof(struct igmp), sizeof(n_short), sizeof(n_long),
           IGMP_MINLEN, IGMP_MEMBERSHIP_QUERY, IGMP_V2_LEAVE_GROUP);

    printf("udp %zu %zu %d %d %d %d\n",
           sizeof(struct udphdr), offsetof(struct udphdr, uh_sum),
           UDP_ENCAP_ESPINUDP, UDP_ENCAP_RXRPC, UDP_SEGMENT, SOL_UDP);

    printf("scsi %zu %zu %zu %zu %d %d %d %d\n",
           sizeof(struct ccs_modesel_head), sizeof(sg_io_hdr_t),
           sizeof(struct sg_scsi_id), sizeof(struct sg_header),
           TEST_UNIT_READY, READ_10, SG_IO, SG_MAX_SENSE);

    printf("procfs %zu %zu %zu %zu %zu %d %d %d\n",
           sizeof(struct user_regs_struct), sizeof(struct user_fpsimd_struct),
           sizeof(struct elf_prstatus), sizeof(struct elf_prpsinfo),
           sizeof(struct sg_req_info), ELF_NREG, SCSI_IOCTL_DOORLOCK,
           SCSI_IOCTL_TEST_UNIT_READY);

    printf("context %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(mcontext_t), _Alignof(mcontext_t),
           offsetof(mcontext_t, fault_address), offsetof(mcontext_t, regs),
           offsetof(mcontext_t, sp), offsetof(mcontext_t, pc),
           offsetof(mcontext_t, pstate), sizeof(ucontext_t),
           offsetof(ucontext_t, uc_sigmask), offsetof(ucontext_t, uc_mcontext));
    return 0;
}

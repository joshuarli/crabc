/* C++17 source-only companion for the Linux/x86-64 TCP header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <netinet/tcp.h>

#define CRABC_OFFSETOF(type, member) __builtin_offsetof(type, member)

static_assert(TCP_NODELAY == 1 && TCP_MAXSEG == 2 && TCP_CORK == 3 &&
    TCP_KEEPIDLE == 4 && TCP_KEEPINTVL == 5 && TCP_KEEPCNT == 6 &&
    TCP_SYNCNT == 7 && TCP_LINGER2 == 8 && TCP_DEFER_ACCEPT == 9 &&
    TCP_WINDOW_CLAMP == 10 && TCP_INFO == 11 && TCP_QUICKACK == 12 &&
    TCP_CONGESTION == 13 && TCP_MD5SIG == 14 &&
    TCP_THIN_LINEAR_TIMEOUTS == 16 && TCP_THIN_DUPACK == 17 &&
    TCP_USER_TIMEOUT == 18 && TCP_REPAIR == 19 && TCP_REPAIR_QUEUE == 20 &&
    TCP_QUEUE_SEQ == 21 && TCP_REPAIR_OPTIONS == 22 && TCP_FASTOPEN == 23 &&
    TCP_TIMESTAMP == 24 && TCP_NOTSENT_LOWAT == 25 && TCP_CC_INFO == 26 &&
    TCP_SAVE_SYN == 27 && TCP_SAVED_SYN == 28 && TCP_REPAIR_WINDOW == 29 &&
    TCP_FASTOPEN_CONNECT == 30 && TCP_ULP == 31 && TCP_MD5SIG_EXT == 32 &&
    TCP_FASTOPEN_KEY == 33 && TCP_FASTOPEN_NO_COOKIE == 34 &&
    TCP_ZEROCOPY_RECEIVE == 35 && TCP_INQ == 36 && TCP_TX_DELAY == 37 &&
    TCP_CM_INQ == TCP_INQ, "unconditional TCP option values");
static_assert(TCP_ESTABLISHED == 1 && TCP_SYN_SENT == 2 && TCP_SYN_RECV == 3 &&
    TCP_FIN_WAIT1 == 4 && TCP_FIN_WAIT2 == 5 && TCP_TIME_WAIT == 6 &&
    TCP_CLOSE == 7 && TCP_CLOSE_WAIT == 8 && TCP_LAST_ACK == 9 &&
    TCP_LISTEN == 10 && TCP_CLOSING == 11, "unconditional TCP states");
static_assert(TCP_NLA_PAD == 0 && TCP_NLA_BUSY == 1 &&
    TCP_NLA_RWND_LIMITED == 2 && TCP_NLA_SNDBUF_LIMITED == 3 &&
    TCP_NLA_DATA_SEGS_OUT == 4 && TCP_NLA_TOTAL_RETRANS == 5 &&
    TCP_NLA_PACING_RATE == 6 && TCP_NLA_DELIVERY_RATE == 7 &&
    TCP_NLA_SND_CWND == 8 && TCP_NLA_REORDERING == 9 &&
    TCP_NLA_MIN_RTT == 10 && TCP_NLA_RECUR_RETRANS == 11 &&
    TCP_NLA_DELIVERY_RATE_APP_LMT == 12 && TCP_NLA_SNDQ_SIZE == 13 &&
    TCP_NLA_CA_STATE == 14 && TCP_NLA_SND_SSTHRESH == 15 &&
    TCP_NLA_DELIVERED == 16 && TCP_NLA_DELIVERED_CE == 17 &&
    TCP_NLA_BYTES_SENT == 18 && TCP_NLA_BYTES_RETRANS == 19 &&
    TCP_NLA_DSACK_DUPS == 20 && TCP_NLA_REORD_SEEN == 21 &&
    TCP_NLA_SRTT == 22 && TCP_NLA_TIMEOUT_REHASH == 23 &&
    TCP_NLA_BYTES_NOTSENT == 24 && TCP_NLA_EDT == 25 && TCP_NLA_TTL == 26,
    "TCP netlink attribute values");

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
static_assert(TCPOPT_EOL == 0 && TCPOPT_NOP == 1 && TCPOPT_MAXSEG == 2 &&
    TCPOPT_WINDOW == 3 && TCPOPT_SACK_PERMITTED == 4 && TCPOPT_SACK == 5 &&
    TCPOPT_TIMESTAMP == 8 && TCPOLEN_SACK_PERMITTED == 2 &&
    TCPOLEN_WINDOW == 3 && TCPOLEN_MAXSEG == 4 && TCPOLEN_TIMESTAMP == 10 &&
    SOL_TCP == 6, "GNU/BSD TCP option values");
static_assert(sizeof(tcp_seq) == 4 && alignof(tcp_seq) == 4,
    "GNU/BSD tcp_seq type");
static_assert(sizeof(tcphdr) == 20 && alignof(tcphdr) == 4 &&
    CRABC_OFFSETOF(tcphdr, th_sport) == 0 &&
    CRABC_OFFSETOF(tcphdr, th_dport) == 2 &&
    CRABC_OFFSETOF(tcphdr, th_seq) == 4 &&
    CRABC_OFFSETOF(tcphdr, th_ack) == 8 &&
    CRABC_OFFSETOF(tcphdr, th_win) == 14 &&
    CRABC_OFFSETOF(tcphdr, th_sum) == 16 &&
    CRABC_OFFSETOF(tcphdr, th_urp) == 18, "GNU/BSD tcphdr layout");

#if defined(_GNU_SOURCE)
static_assert(sizeof(tcp_info) == 232 && alignof(tcp_info) == 8 &&
    CRABC_OFFSETOF(tcp_info, tcpi_rto) == 8 &&
    CRABC_OFFSETOF(tcp_info, tcpi_total_retrans) == 100 &&
    CRABC_OFFSETOF(tcp_info, tcpi_pacing_rate) == 104 &&
    CRABC_OFFSETOF(tcp_info, tcpi_segs_out) == 136 &&
    CRABC_OFFSETOF(tcp_info, tcpi_delivery_rate) == 160 &&
    CRABC_OFFSETOF(tcp_info, tcpi_delivered) == 192 &&
    CRABC_OFFSETOF(tcp_info, tcpi_bytes_sent) == 200 &&
    CRABC_OFFSETOF(tcp_info, tcpi_dsack_dups) == 216 &&
    CRABC_OFFSETOF(tcp_info, tcpi_snd_wnd) == 228, "GNU tcp_info layout");
static_assert(sizeof(tcp_md5sig) == 216 && alignof(tcp_md5sig) == 8 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_addr) == 0 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_flags) == 128 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_prefixlen) == 129 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_keylen) == 130 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_ifindex) == 132 &&
    CRABC_OFFSETOF(tcp_md5sig, tcpm_key) == 136, "GNU tcp_md5sig layout");
static_assert(sizeof(tcp_diag_md5sig) == 100 && alignof(tcp_diag_md5sig) == 4 &&
    CRABC_OFFSETOF(tcp_diag_md5sig, tcpm_family) == 0 &&
    CRABC_OFFSETOF(tcp_diag_md5sig, tcpm_prefixlen) == 1 &&
    CRABC_OFFSETOF(tcp_diag_md5sig, tcpm_keylen) == 2 &&
    CRABC_OFFSETOF(tcp_diag_md5sig, tcpm_addr) == 4 &&
    CRABC_OFFSETOF(tcp_diag_md5sig, tcpm_key) == 20, "GNU tcp_diag_md5sig layout");
static_assert(sizeof(tcp_repair_window) == 20 && alignof(tcp_repair_window) == 4 &&
    CRABC_OFFSETOF(tcp_repair_window, snd_wl1) == 0 &&
    CRABC_OFFSETOF(tcp_repair_window, snd_wnd) == 4 &&
    CRABC_OFFSETOF(tcp_repair_window, max_window) == 8 &&
    CRABC_OFFSETOF(tcp_repair_window, rcv_wnd) == 12 &&
    CRABC_OFFSETOF(tcp_repair_window, rcv_wup) == 16, "GNU tcp_repair_window layout");
static_assert(sizeof(tcp_zerocopy_receive) == 64 &&
    alignof(tcp_zerocopy_receive) == 8 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, address) == 0 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, length) == 8 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, recv_skip_hint) == 12 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, inq) == 16 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, err) == 20 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, copybuf_address) == 24 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, copybuf_len) == 32 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, flags) == 36 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, msg_control) == 40 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, msg_controllen) == 48 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, msg_flags) == 56 &&
    CRABC_OFFSETOF(tcp_zerocopy_receive, reserved) == 60, "GNU tcp_zerocopy layout");
static_assert(TCPI_OPT_TIMESTAMPS == 1 && TCPI_OPT_SACK == 2 &&
    TCPI_OPT_WSCALE == 4 && TCPI_OPT_ECN == 8 && TCP_CA_Open == 0 &&
    TCP_CA_Disorder == 1 && TCP_CA_CWR == 2 && TCP_CA_Recovery == 3 &&
    TCP_CA_Loss == 4 && TCP_MD5SIG_MAXKEYLEN == 80 &&
    TCP_MD5SIG_FLAG_PREFIX == 1 && TCP_MD5SIG_FLAG_IFINDEX == 2 &&
    TCP_REPAIR_ON == 1 && TCP_REPAIR_OFF == 0 && TCP_REPAIR_OFF_NO_WP == -1 &&
    TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT == 1,
    "GNU TCP diagnostic constants");
static_assert(TFO_STATUS_UNSPEC == 0 && TFO_COOKIE_UNAVAILABLE == 1 &&
    TFO_DATA_NOT_ACKED == 2 && TFO_SYN_RETRANSMITTED == 3,
    "GNU TCP fast-open status values");

static int tcphdr_gnu_aliases(tcphdr *header)
{
    header->source = 1;
    header->dest = 2;
    header->seq = 3;
    header->ack_seq = 4;
    header->doff = 5;
    header->fin = 1;
    header->ack = 1;
    header->window = 6;
    header->check = 7;
    header->urg_ptr = 8;
    return header->th_sport + header->th_dport + static_cast<int>(header->th_seq) +
        static_cast<int>(header->th_ack) + header->th_win + header->th_sum +
        header->th_urp;
}
#else
/* BSD gets the legacy option/record surface but not GNU diagnostics. */
#if defined(TCPI_OPT_TIMESTAMPS) || defined(TCP_CA_Open) || \
    defined(TCP_MD5SIG_MAXKEYLEN) || defined(TCP_MD5SIG_FLAG_PREFIX) || \
    defined(TCP_MD5SIG_FLAG_IFINDEX) || defined(TCP_REPAIR_ON) || \
    defined(TCP_REPAIR_OFF) || defined(TCP_REPAIR_OFF_NO_WP) || \
    defined(TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT)
#error "BSD TCP profile unexpectedly exposes GNU diagnostics"
#endif
#endif
#else
#if defined(TCPOPT_EOL) || defined(SOL_TCP)
#error "strict TCP profile unexpectedly exposes GNU/BSD options"
#endif
#endif

int crabc_x86_64_tcp_header_abi_probe_cpp()
{
    return TCP_NODELAY == 1 ? 0 : 1;
}

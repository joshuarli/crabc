#include <arpa/nameser.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int make_packet(unsigned char *packet)
{
    static const unsigned char question[] = {
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0, 0, 1, 0, 1
    };
    static const unsigned char answer[] = {
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4,
        192, 0, 2, 1
    };

    ns_put16(0x1234, packet);
    ns_put16(0x8180, packet + 2);
    ns_put16(1, packet + 4);
    ns_put16(1, packet + 6);
    ns_put16(0, packet + 8);
    ns_put16(0, packet + 10);
    memcpy(packet + 12, question, sizeof question);
    memcpy(packet + 12 + sizeof question, answer, sizeof answer);
    return 12 + (int)sizeof question + (int)sizeof answer;
}

int main(void)
{
    unsigned char wire[8] = {0};
    unsigned char packet[128] = {0};
    char name[NS_MAXDNAME];
    ns_msg message;
    ns_rr rr;
    int packet_len;
    int answer_offset;

    ns_put16(0x1234, wire);
    ns_put32(0x89abcdefUL, wire + 2);
    if (ns_get16(wire) != 0x1234 || ns_get32(wire + 2) != 0x89abcdefUL)
        return 1;

    packet_len = make_packet(packet);
    answer_offset = 12 + 21;
    if (ns_initparse(packet, packet_len, &message) != 0)
        return 2;
    if (ns_msg_id(message) != 0x1234 || ns_msg_count(message, ns_s_qd) != 1 ||
        ns_msg_count(message, ns_s_an) != 1 || !ns_msg_getflag(message, ns_f_qr) ||
        !ns_msg_getflag(message, ns_f_rd))
        return 3;
    if (ns_skiprr(packet + 12, packet + packet_len, ns_s_qd, 1) != 21 ||
        ns_skiprr(packet + answer_offset, packet + packet_len, ns_s_an, 1) != 16)
        return 4;

    if (ns_parserr(&message, ns_s_qd, 0, &rr) != 0 ||
        strcmp(ns_rr_name(rr), "www.example.com") != 0 ||
        ns_rr_type(rr) != T_A || ns_rr_class(rr) != C_IN ||
        ns_rr_rdlen(rr) != 0 || ns_rr_rdata(rr) != 0)
        return 5;
    if (ns_parserr(&message, ns_s_an, -1, &rr) != 0 ||
        strcmp(ns_rr_name(rr), "www.example.com") != 0 ||
        ns_rr_type(rr) != T_A || ns_rr_class(rr) != C_IN ||
        ns_rr_ttl(rr) != 300 || ns_rr_rdlen(rr) != 4 ||
        rr.rdata[0] != 192 || rr.rdata[1] != 0 ||
        rr.rdata[2] != 2 || rr.rdata[3] != 1)
        return 6;
    if (ns_name_uncompress(packet, packet + packet_len, packet + answer_offset,
                           name, sizeof name) != 2 ||
        strcmp(name, "www.example.com") != 0)
        return 7;

    errno = 0;
    if (ns_initparse(packet, packet_len - 1, &message) != -1 || errno != EMSGSIZE)
        return 8;

    /* A declared RDLENGTH larger than the packet is rejected at parse time. */
    packet[answer_offset + 10] = 0;
    packet[answer_offset + 11] = 5;
    errno = 0;
    if (ns_initparse(packet, packet_len, &message) != -1 || errno != EMSGSIZE)
        return 9;

    /* Restore the answer and make its compressed owner point beyond EOM. */
    packet[answer_offset + 10] = 0;
    packet[answer_offset + 11] = 4;
    packet[answer_offset] = 0xc0;
    packet[answer_offset + 1] = 0xff;
    if (ns_initparse(packet, packet_len, &message) != 0)
        return 10;
    errno = 0;
    if (ns_parserr(&message, ns_s_an, 0, &rr) != -1 || errno != EMSGSIZE)
        return 11;

    errno = 0;
    if (ns_parserr(&message, ns_s_an, 1, &rr) != -1 || errno != ENODEV)
        return 12;
    errno = 0;
    if (ns_name_uncompress(packet, packet + packet_len, packet + answer_offset,
                           name, sizeof name) != -1 || errno != EMSGSIZE)
        return 13;
    errno = 0;
    if (ns_name_uncompress(packet, packet + packet_len, packet + 12,
                           name, 0) != -1 || errno != EMSGSIZE)
        return 14;

    puts("c-abi dns packet helpers ok");
    return 0;
}

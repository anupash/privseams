/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * Sockets and functions for reinjection of packets.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/tool/checksum.h"
#include "reinject.h"

static int firewall_raw_sock_tcp_v4        = 0;
static int firewall_raw_sock_udp_v4        = 0;
static int firewall_raw_sock_icmp_v4       = 0;
static int firewall_raw_sock_tcp_v6        = 0;
static int firewall_raw_sock_udp_v6        = 0;
static int firewall_raw_sock_icmp_v6       = 0;
static int firewall_raw_sock_icmp_outbound = 0;
static int firewall_raw_sock_esp_v4        = 0;
static int firewall_raw_sock_esp_v6        = 0;

/**
 * Initialize an ICMP raw socket
 *
 * @param firewall_raw_sock_v6 the raw socket is written into this pointer
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_outbound(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failiped\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize raw IPv4 sockets for TCP
 *
 * @param firewall_raw_sock_v4 the result will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_tcp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize UDP-based raw socket
 *
 * @param firewall_raw_sock_v4 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_udp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ICMP-based raw socket
 *
 * @param firewall_raw_sock_v4 the result is written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize TCPv6 raw socket
 *
 * @param firewall_raw_sock_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_tcp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize UDPv6-based raw socket
 *
 * @param firewall_raw_sock_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_udp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ICMPv6-based raw socket
 *
 * @param firewall_raw_sock_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ESPv4-based raw socket
 *
 * @param sock the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_esp_v4(int *sock)
{
    int on = 1, off = 0, err = 0;
    *sock = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);

    HIP_IFE(setsockopt(*sock, IPPROTO_IP, IP_RECVERR, &off, sizeof(off)), -1);
    HIP_IFE(setsockopt(*sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)), -1);
    HIP_IFE(setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), -1);

out_err:
    if (err) {
        HIP_ERROR("init sock esp v4\n");
    }
    return err;
}

/**
 * Initialize ESPv6-based raw socket
 *
 * @param sock the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_esp_v6(int *sock)
{
    int on = 1, off = 0, err = 0;
    *sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ESP);

    HIP_IFE(setsockopt(*sock, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(off)), -1);
    HIP_IFE(setsockopt(*sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on)), -1);
    HIP_IFE(setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), -1);

out_err:
    if (err) {
        HIP_ERROR("init sock esp v4\n");
    }
    return err;
}

/**
 * Initialize all raw sockets
 *
 */
void hip_firewall_init_raw_sockets(void)
{
    hip_firewall_init_raw_sock_tcp_v4(&firewall_raw_sock_tcp_v4);
    hip_firewall_init_raw_sock_udp_v4(&firewall_raw_sock_udp_v4);
    hip_firewall_init_raw_sock_icmp_v4(&firewall_raw_sock_icmp_v4);
    hip_firewall_init_raw_sock_icmp_outbound(&firewall_raw_sock_icmp_outbound);
    hip_firewall_init_raw_sock_tcp_v6(&firewall_raw_sock_tcp_v6);
    hip_firewall_init_raw_sock_udp_v6(&firewall_raw_sock_udp_v6);
    hip_firewall_init_raw_sock_icmp_v6(&firewall_raw_sock_icmp_v6);
    hip_firewall_init_raw_sock_esp_v4(&firewall_raw_sock_esp_v4);
    hip_firewall_init_raw_sock_esp_v6(&firewall_raw_sock_esp_v6);
}

/**
 * Translate and reinject an incoming packet back to the networking stack.
 * Supports TCP, UDP and ICMP. LSI code uses this to translate
 * the HITs from an incoming packet to the corresponding LSIs. Also,
 * the system-based opportunistic mode uses this to translate the HITs of
 * an incoming packet to an IPv4 or IPv6 address.
 *
 * @param src_hit source HIT of the packet
 * @param dst_hit destination HIT of the packet
 * @param msg a pointer to the transport layer header of the packet
 * @param len the length of the packet in bytes
 * @param proto the transport layer protocol of the packet
 * @param ttl new ttl value for the transformed packet
 *
 * @return zero on success and non-zero on error
 */
int hip_firewall_send_incoming_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto,
                                   int ttl)
{
    int                     err               = 0, sent, sa_size;
    int                     firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
    struct ip              *iphdr             = NULL;
    struct udphdr          *udp               = NULL;
    struct tcphdr          *tcp               = NULL;
    struct icmphdr         *icmp              = NULL;
    struct sockaddr_storage src               = { 0 }, dst       = { 0 };
    struct sockaddr_in6    *sock_src6         = NULL, *sock_dst6 = NULL;
    struct sockaddr_in     *sock_src4         = NULL, *sock_dst4 = NULL;
    struct in6_addr         any               = IN6ADDR_ANY_INIT;

    HIP_ASSERT(src_hit != NULL && dst_hit != NULL);

    sock_src4 = (struct sockaddr_in *) &src;
    sock_dst4 = (struct sockaddr_in *) &dst;
    sock_src6 = (struct sockaddr_in6 *) &src;
    sock_dst6 = (struct sockaddr_in6 *) &dst;

    if (IN6_IS_ADDR_V4MAPPED(src_hit)) {
        sock_src4->sin_family = AF_INET;
        sock_dst4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(src_hit, &sock_src4->sin_addr);
        IPV6_TO_IPV4_MAP(dst_hit, &sock_dst4->sin_addr);
        sa_size = sizeof(struct sockaddr_in);
        HIP_DEBUG_LSI("src4 addr ", &sock_src4->sin_addr);
        HIP_DEBUG_LSI("dst4 addr ", &sock_dst4->sin_addr);
    } else {
        sock_src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
        sock_dst6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
        sa_size = sizeof(struct sockaddr_in6);
        is_ipv6 = 1;
    }

    switch (proto) {
    case IPPROTO_UDP:
        if (is_ipv6) {
            HIP_DEBUG(" IPPROTO_UDP v6\n");
            firewall_raw_sock              = firewall_raw_sock_udp_v6;
            ((struct udphdr *) msg)->check = ipv6_checksum(IPPROTO_UDP,
                                                           &sock_src6->sin6_addr,
                                                           &sock_dst6->sin6_addr, msg, len);
        } else {
            HIP_DEBUG(" IPPROTO_UDP v4\n");
            firewall_raw_sock = firewall_raw_sock_udp_v4;

            udp = (struct udphdr *) msg;

            sa_size = sizeof(struct sockaddr_in);

            udp->check = htons(0);
            udp->check = ipv4_checksum(IPPROTO_UDP,
                                       (uint8_t *) &sock_src4->sin_addr,
                                       (uint8_t *) &sock_dst4->sin_addr,
                                       (uint8_t *) udp, len);
            memmove(msg + sizeof(struct ip), udp, len);
        }
        break;
    case IPPROTO_TCP:
        tcp        = (struct tcphdr *) msg;
        tcp->check = htons(0);

        if (is_ipv6) {
            HIP_DEBUG(" IPPROTO_TCP v6\n");
            firewall_raw_sock = firewall_raw_sock_tcp_v6;
            tcp->check        = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr,
                                              &sock_dst6->sin6_addr, msg, len);
        } else {
            HIP_DEBUG(" IPPROTO_TCP v4\n");
            firewall_raw_sock = firewall_raw_sock_tcp_v4;

            tcp->check = ipv4_checksum(IPPROTO_TCP,
                                       (uint8_t *) &sock_src4->sin_addr,
                                       (uint8_t *) &sock_dst4->sin_addr,
                                       (uint8_t *) tcp, len);

            memmove(msg + sizeof(struct ip), tcp, len);
        }
        break;
    case IPPROTO_ICMP:
        firewall_raw_sock = firewall_raw_sock_icmp_v4;
        icmp              = (struct icmphdr *) msg;
        icmp->checksum    = htons(0);
        icmp->checksum    = inchksum(icmp, len);
        memmove(msg + sizeof(struct ip), icmp, len);
        break;
    case IPPROTO_ICMPV6:
        goto not_sending;
        break;
    default:
        HIP_ERROR("No protocol family found\n");
        break;
    }

    if (!is_ipv6) {
        iphdr         = (struct ip *) msg;
        iphdr->ip_v   = 4;
        iphdr->ip_hl  = sizeof(struct ip) >> 2;
        iphdr->ip_tos = 0;
        iphdr->ip_len = len + iphdr->ip_hl * 4;
        iphdr->ip_id  = htons(0);
        iphdr->ip_off = 0;
        iphdr->ip_ttl = ttl;
        iphdr->ip_p   = proto;
        iphdr->ip_src = sock_src4->sin_addr;
        iphdr->ip_dst = sock_dst4->sin_addr;
        iphdr->ip_sum = htons(0);

        /* @todo: move the socket option to fw initialization */
        if (setsockopt(firewall_raw_sock, IPPROTO_IP,
                       IP_HDRINCL, &on, sizeof(on))) {
            HIP_IFEL(err, -1, "setsockopt IP_HDRINCL ERROR\n");
        }

        sent = sendto(firewall_raw_sock, iphdr,
                      iphdr->ip_len, 0,
                      (struct sockaddr *) &dst, sa_size);
        if (sent != (int) (len + sizeof(struct ip))) {
            HIP_ERROR("Could not send the all requested" \
                      " data (%d/%d)\n", sent,
                      iphdr->ip_len);
        } else {
            HIP_DEBUG("sent=%d/%d \n",
                      sent, (len + sizeof(struct ip)));
            HIP_DEBUG("Packet sent ok\n");
        }
    }

out_err:
    if (is_ipv6) {
        ipv6_addr_copy(&sock_src6->sin6_addr, &any);
    } else {
        sock_src4->sin_addr.s_addr = INADDR_ANY;
        sock_src4->sin_family      = AF_INET;
    }

    bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
not_sending:
    if (err) {
        HIP_DEBUG("sterror %s\n", strerror(errno));
    }
    return err;
}

/**
 * translate and reinject an incoming packet
 *
 * @param src_hit source HIT of the packet
 * @param dst_hit destination HIT of the packet
 * @param msg a pointer to the transport header of the packet
 * @param len length of the packet
 * @param proto transport layer protocol
 *
 * @return zero on success and non-zero on error
 *
 * @todo unify common code with hip_firewall_send_outgoing_pkt()
 */
int hip_firewall_send_outgoing_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto)
{
    int err               = 0, sent, sa_size;
    int firewall_raw_sock = 0, is_ipv6 = 0;

    struct sockaddr_storage src = { 0 }, dst = { 0 };
    struct sockaddr_in6    *sock_src6, *sock_dst6;
    struct sockaddr_in     *sock_src4, *sock_dst4;
    struct in6_addr         any = IN6ADDR_ANY_INIT;

    HIP_ASSERT(src_hit != NULL && dst_hit != NULL);

    sock_src4 = (struct sockaddr_in *) &src;
    sock_dst4 = (struct sockaddr_in *) &dst;
    sock_src6 = (struct sockaddr_in6 *) &src;
    sock_dst6 = (struct sockaddr_in6 *) &dst;

    if (IN6_IS_ADDR_V4MAPPED(src_hit)) {
        sock_src4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(src_hit, &sock_src4->sin_addr);
        sock_dst4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(dst_hit, &sock_dst4->sin_addr);
        sa_size = sizeof(struct sockaddr_in);
        HIP_DEBUG_LSI("src4 addr ", &sock_src4->sin_addr);
        HIP_DEBUG_LSI("dst4 addr ", &sock_dst4->sin_addr);
    } else {
        sock_src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
        sock_dst6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
        sa_size = sizeof(struct sockaddr_in6);
        is_ipv6 = 1;
        HIP_DEBUG_HIT("src6 addr ", &sock_src6->sin6_addr);
        HIP_DEBUG_HIT("dst6 addr ", &sock_dst6->sin6_addr);
    }

    switch (proto) {
    case IPPROTO_TCP:
        ((struct tcphdr *) msg)->check = htons(0);
        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_tcp_v6;
            ((struct tcphdr *) msg)->check
                = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr,
                                &sock_dst6->sin6_addr, msg, len);
        } else {
            firewall_raw_sock = firewall_raw_sock_tcp_v4;
            ((struct tcphdr *) msg)->check
                = ipv4_checksum(IPPROTO_TCP, (uint8_t *) &sock_src4->sin_addr,
                                (uint8_t *) &sock_dst4->sin_addr, msg, len);
        }
        break;
    case IPPROTO_UDP:
        HIP_DEBUG("IPPROTO_UDP\n");
        HIP_DEBUG("src_port is %d\n", ntohs(((struct udphdr *) msg)->source));
        HIP_DEBUG("dst_port is %d\n", ntohs(((struct udphdr *) msg)->dest));
        HIP_DEBUG("checksum is %x\n", ntohs(((struct udphdr *) msg)->check));
        ((struct udphdr *) msg)->check = htons(0);
        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_udp_v6;
            ((struct udphdr *) msg)->check
                = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr,
                                &sock_dst6->sin6_addr, msg, len);
        } else {
            firewall_raw_sock = firewall_raw_sock_udp_v4;
            ((struct udphdr *) msg)->check
                = ipv4_checksum(IPPROTO_UDP, (uint8_t *) &sock_src4->sin_addr,
                                (uint8_t *) &sock_dst4->sin_addr, msg, len);
        }
        break;
    case IPPROTO_ICMP:
        ((struct icmphdr *) msg)->checksum = htons(0);
        ((struct icmphdr *) msg)->checksum = inchksum(msg, len);

        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_icmp_outbound;
        } else {
            firewall_raw_sock = firewall_raw_sock_icmp_v4;
        }

        break;
    case IPPROTO_ICMPV6:
        firewall_raw_sock                       = firewall_raw_sock_icmp_v6;
        ((struct icmp6_hdr *) msg)->icmp6_cksum = htons(0);
        ((struct icmp6_hdr *) msg)->icmp6_cksum
            = ipv6_checksum(IPPROTO_ICMPV6, &sock_src6->sin6_addr,
                            &sock_dst6->sin6_addr, msg, len);
        break;

    case IPPROTO_ESP:
        if (!is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_esp_v4;
        }
        break;
    default:
        HIP_DEBUG("No protocol family found\n");
        goto out_err;
        break;
    }


    HIP_IFEL(bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size),
             -1, "Binding to raw sock failed\n");
    sent = sendto(firewall_raw_sock, msg, len, 0,
                  (struct sockaddr *) &dst, sa_size);
    if (sent != len) {
        HIP_ERROR("Could not send the all requested" \
                  " data (%d/%d): %s\n", sent, len, strerror(errno));
    } else {
        HIP_DEBUG("sent=%d/%d \n",
                  sent, len);
    }

out_err:
    /* Reset the interface to wildcard*/
    if (is_ipv6) {
        ipv6_addr_copy(&sock_src6->sin6_addr, &any);
    } else {
        sock_src4->sin_addr.s_addr = INADDR_ANY;
        sock_src4->sin_family      = AF_INET;
    }

    bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
    if (err) {
        HIP_DEBUG("sterror %s\n", strerror(errno));
    }

    return err;
}

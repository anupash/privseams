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
 * @brief Few "utility" functions for the firewall
 *
 * @todo the actual utility of this file seems questionable (should be removed)
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/tool/checksum.h"
#include "helpers.h"

/**
 * A wrapper for inet_ntop(). Converts a numeric IPv6 address to a string.
 *
 * @param addrp an IPv6 address to be converted to a string
 *
 * @return A static pointer to a string containing the the IPv6 address.
 *         Caller must not try to deallocate. On error, returns NULL and sets
 *         errno (see man inet_ntop).
 *
 * @note this function is not re-entrant and should not be used with threads
 *
 */
const char *addr_to_numeric(const struct in6_addr *addrp)
{
    static char buf[50 + 1];
    return inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * A wrapper for inet_pton(). Converts a string to a numeric IPv6 address
 *
 * @param num the string to be converted into an in6_addr structure
 *
 * @return A static pointer to an in6_addr structure corresponding to the
 *         given "num" string. Caller must not try to deallocate.
 *         On error, returns NULL and sets errno (see man inet_ntop).
 *
 * @note this function is not re-entrant and should not be used with threads
 */
struct in6_addr *numeric_to_addr(const char *num)
{
    static struct in6_addr ap;
    int                    err;
    if ((err = inet_pton(AF_INET6, num, &ap)) == 1) {
        return &ap;
    }
    return NULL;
}

/**
 * Executes a command and prints an error if command wasn't successful.
 *
 * @param command The command. The caller of this function must take
 *                care that command does not contain malicious code.
 * @return        Exit code on success, -1 on failure.
 */
int system_print(const char *const command)
{
    int ret;

    if ((ret = system(command)) == -1) {
        HIP_ERROR("Could not execute command `%s'", command);
        return -1;
    }

    HIP_DEBUG("$ %s -> %d\n", command, WEXITSTATUS(ret));

    return WEXITSTATUS(ret);
}

/**
 * printf()-like wrapper around system_print.
 * Fails and returns an error if the resulting command line
 * would be longer than ::MAX_COMMAND_LINE characters.
 *
 * @param command The command. This is a printf format string.
 *                The caller of this function must take care that command
 *                does not contain malicious code.
 * @return        Exit code on success, -1 on failure.
 */
int system_printf(const char *const command, ...)
{
    char bfr[MAX_COMMAND_LINE + 1];

    va_list vargs;
    va_start(vargs, command);

    const int ret = vsnprintf(bfr, sizeof(bfr), command, vargs);
    if (ret <= 0) {
        HIP_ERROR("vsnprintf failed\n");
        va_end(vargs);
        return -1;
    }

    // cast to unsigned value (we know that ret >= 0)
    if ((unsigned) ret > MAX_COMMAND_LINE) {
        HIP_ERROR("Format '%s' results in unexpectedly large command line "
                  "(%d characters): not executed.\n", command, ret);
        va_end(vargs);
        return -1;
    }

    va_end(vargs);
    return system_print(bfr);
}

/**
 * Changes IPv4 header to match new length and updates the checksum.
 *
 * @param ip  a pointer to the IPv4 header
 * @param len new payload length
 */
static void update_ipv4_header(struct iphdr *ip, int len)
{
    unsigned short *w = (unsigned short *) ip;
    int             hdrlen, checksum = 0;

    ip->tot_len = htons(len);
    ip->check   = 0;

    for (hdrlen = ip->ihl * 4, checksum = 0; hdrlen > 1; hdrlen -= 2) {
        checksum += *w++;
    }
    if (hdrlen == 1) {
        unsigned short padding = 0;
        *(unsigned char *) (&padding) = *(unsigned char *) w;
        checksum                     += padding;
    }

    checksum  = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);

    ip->check = ~checksum;
}

/**
 * Changes IPv6 header to match new length.
 *
 * @param ip a pointer to the IPv6 header
 * @param len new IPv6 packet length
 */
static void update_ipv6_header(struct ip6_hdr *ip, int len)
{
    ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
}

#define CHECKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/**
 * Changes UDP header for IPv4 to match new content and updates the checksum.
 *
 * @param ip a pointer to the IPv4 header, not the UDP header
 * @param len total length of the IPv4 packet
 */
static void update_udp_header(struct iphdr *ip, int len)
{
    unsigned long  sum;
    uint16_t      *w        = (uint16_t *) ((unsigned char *) ip + (ip->ihl * 4));
    uint16_t       protocol = ntohs(IPPROTO_UDP);
    int            i;
    struct udphdr *udp = (struct udphdr *) w;

    len -= ip->ihl * 4;

    udp->check = 0;
    udp->len   = htons(len);

    /* UDP header and data */
    sum = 0;
    while (len > 0) {
        sum += *w++;
        len -= 2;
    }
    if (len == 1) {
        unsigned short padding = 0;
        *(unsigned char *) (&padding) = *(unsigned char *) w;
        sum                          += padding;
    }

    /* add UDP pseudoheader */
    w = (uint16_t *) &ip->saddr;
    for (i = 0; i < 4; w++, i++) {
        sum += *w;
    }
    sum += protocol;
    sum += udp->len;

    /* set the checksum */
    udp->check = (CHECKSUM_CARRY(sum));
}

/**
 * Calculate the new checksum for the HIP packet in IPv4. Note that UDP
 * encapsulated HIP packets don't have a checksum. Therefore don't call this
 * function for them.
 *
 * @param ip the modified IP packet
 */
static void update_hip_checksum_ipv4(struct iphdr *ip)
{
    struct sockaddr_in src, dst;
    struct hip_common *msg = (struct hip_common *) ((char *) ip +
                                                    (ip->ihl * 4));

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    src.sin_family = AF_INET;
    memcpy(&src.sin_addr, &ip->saddr, sizeof(uint32_t));

    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr, &ip->daddr, sizeof(uint32_t));

    hip_zero_msg_checksum(msg);
    msg->checksum = hip_checksum_packet((char *) msg,
                                        (struct sockaddr *) &src,
                                        (struct sockaddr *) &dst);
}

/**
 * Calculate the new checksum for the HIP packet in IPv6.
 *
 * @param ip the modified IP packet
 */
static void update_hip_checksum_ipv6(struct ip6_hdr *ip)
{
    struct sockaddr_in6 src, dst;
    struct hip_common  *msg = (struct hip_common *) ((char *) ip +
                                                     sizeof(struct ip6_hdr));

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    src.sin6_family = AF_INET6;
    memcpy(&src.sin6_addr, &ip->ip6_src, sizeof(struct in6_addr));

    dst.sin6_family = AF_INET6;
    memcpy(&dst.sin6_addr, &ip->ip6_dst, sizeof(struct in6_addr));

    hip_zero_msg_checksum(msg);
    msg->checksum = hip_checksum_packet((char *) msg,
                                        (struct sockaddr *) &src,
                                        (struct sockaddr *) &dst);
}

/**
 * Take care of adapting all headers in front of the HIP payload to the new
 * content.
 *
 * @param ctx context of the modified midauth packet
 */
void update_all_headers(struct hip_fw_context *ctx)
{
    struct iphdr   *ipv4 = NULL;
    struct ip6_hdr *ipv6 = NULL;
    size_t          len  = 0;

    len = hip_get_msg_total_len(ctx->transport_hdr.hip);

    switch (ctx->ip_version) {
    case 4:
        ipv4 = (struct iphdr *) ctx->ipq_packet->payload;
        len += ipv4->ihl * 4;
        if (ipv4->protocol == IPPROTO_UDP) {
            len += sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN;
            update_udp_header(ipv4, len);
        } else {
            update_hip_checksum_ipv4(ipv4);
        }
        update_ipv4_header(ipv4, len);
        break;
    case 6:
        ipv6 = (struct ip6_hdr *) ctx->ipq_packet->payload;
        len += sizeof(struct ip6_hdr);
        update_hip_checksum_ipv6(ipv6);
        update_ipv6_header(ipv6, len);
        break;
    default:
        HIP_ERROR("Unknown IP version. %i, expected 4 or 6.\n",
                  ctx->ip_version);
        break;
    }

    ctx->ipq_packet->data_len = len;
}

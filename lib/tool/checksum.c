/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Checksum functions
 *
 * @author Miika Komu <miika@iki.fi>
 * @note check if some of the checksum algos are redundant
 */

#define _BSD_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "lib/core/debug.h"
#include "lib/core/protodefs.h"
#include "checksum.h"

struct pseudo_header {
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    uint8_t       zero;
    uint8_t       protocol;
    uint16_t      packet_length;
};

struct pseudo_v6 {
    struct in6_addr src;
    struct in6_addr dst;
    uint16_t        length;
    uint16_t        zero1;
    uint8_t         zero2;
    uint8_t         next;
};

/** @todo this is redundant with struct pseudo_v6 */
struct pseudo_header6 {
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    uint32_t      packet_length;
    unsigned char zero[3];
    uint8_t       next_hdr;
};

/**
 * Generate the IPv4 header checksum
 *
 * @param s     source address
 * @param d     destination address
 * @param c     data
 * @param len length
 * @param protocol protocol
 * @return the calculated IPv4 header checksum
 */
uint16_t ipv4_checksum(uint8_t protocol, void *s, void *d, void *c,
                       uint16_t len)
{
    uint8_t *src  = s;
    uint8_t *dst  = d;
    uint8_t *data = c;
    uint16_t word16;
    uint32_t sum;
    uint16_t i;

    /* initialize sum to zero */
    sum = 0;

    /* make 16 bit words out of every two adjacent 8 bit words and */
    /* calculate the sum of all 16 vit words */
    for (i = 0; i < len; i = i + 2) {
        word16 = (((uint16_t) (data[i] << 8)) & 0xFF00) +
                 (((uint16_t) data[i + 1]) & 0xFF);
        sum = sum + (unsigned long) word16;
    }
    /* add the TCP pseudo header which contains:
     * the IP source and destination addresses, */
    for (i = 0; i < 4; i = i + 2) {
        word16 = ((src[i] << 8) & 0xFF00) + (src[i + 1] & 0xFF);
        sum    = sum + word16;
    }
    for (i = 0; i < 4; i = i + 2) {
        word16 = ((dst[i] << 8) & 0xFF00) + (dst[i + 1] & 0xFF);
        sum    = sum + word16;
    }
    /* the protocol number and the length of the TCP packet */
    sum = sum + protocol + len;

    /* keep only the last 16 bits of the 32 bit calculated sum
     * and add the carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Take the one's complement of sum */
    sum = ~sum;
    return htons((unsigned short) sum);
}

/**
 * calculate IPv6 checksum
 *
 * @param protocol the protocol
 * @param src source address
 * @param dst destination address
 * @param data the data to checksum
 * @param len the length of the data
 * @return the calculated checksum
 */
uint16_t ipv6_checksum(uint8_t protocol,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       void *data, uint16_t len)
{
    uint32_t         chksum = 0;
    struct pseudo_v6 pseudo;
    memset(&pseudo, 0, sizeof(struct pseudo_v6));

    pseudo.src    = *src;
    pseudo.dst    = *dst;
    pseudo.length = htons(len);
    pseudo.next   = protocol;

    chksum  = inchksum(&pseudo, sizeof(struct pseudo_v6));
    chksum += inchksum(data, len);

    chksum  = (chksum >> 16) + (chksum & 0xffff);
    chksum +=  chksum >> 16;

    chksum = (uint16_t) (~chksum);
    if (chksum == 0) {
        chksum = 0xffff;
    }

    return chksum;
}

/** calculate an IP checksum
 *
 * @param ip_hdr    packet to be checksumed
 * @param ip_hl     header length field inside the header
 * @return          the IP checksum
 * @note taken from  RFC 1071 section 4.1
 */
uint16_t checksum_ip(struct ip *ip_hdr, const unsigned int ip_hl)
{
    uint16_t        checksum = 0;
    unsigned long   sum      = 0;
    int             count    = ip_hl * 4;
    unsigned short *p        = (unsigned short *) ip_hdr;

    /*
     * this checksum algorithm can be found
     * in RFC 1071 section 4.1
     */

    /* one's complement sum 16-bit words of data */
    while (count > 1) {
        sum   += *p++;
        count -= 2;
    }
    /* add left-over byte, if any */
    if (count > 0) {
        sum += (unsigned char) *p;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    /* take the one's complement of the sum */
    checksum = (uint16_t) (~sum);

    return checksum;
}

/**
 * yet another checksummer
 *
 * @param data the data to checksum
 * @param length the length of the data
 * @return the calculated checksum
 */
uint16_t inchksum(const void *data, uint32_t length)
{
    long            sum  = 0;
    const uint16_t *wrd  = data;
    long            slen = (long) length;

    while (slen > 1) {
        sum  += *wrd++;
        slen -= 2;
    }

    if (slen > 0) {
        sum += *((const uint8_t *) wrd);
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t) sum;
}

/**
 * Calculates the checksum of a HIP packet with pseudo-header.
 *
 * @param data a pointer to a hip_common structure
 * @param src  The source address of the packet as a sockaddr_in or
 *             sockaddr_in6 structure in network byte order.
 *             IPv6 mapped addresses are not supported.
 * @param dst  The destination address of the packet as a sockaddr_in or
 *             sockaddr_in6 structure in network byte order.
 *             IPv6 mapped addresses are not supported.
 * @return     the checksum
 * @note       Checksumming is from Boeing's HIPD.
 */
uint16_t hip_checksum_packet(char *data, struct sockaddr *src,
                             struct sockaddr *dst)
{
    uint16_t              checksum = 0;
    unsigned long         sum      = 0;
    int                   count    = 0, length = 0;
    unsigned short       *p        = NULL; /* 16-bit */
    struct pseudo_header  pseudoh;
    struct pseudo_header6 pseudoh6;
    uint32_t              src_network, dst_network;
    struct in6_addr      *src6, *dst6;
    struct hip_common    *hiph = (struct hip_common *) data;

    if (src->sa_family == AF_INET) {
        /* IPv4 checksum based on UDP-- Section 6.1.2 */
        src_network = ((struct sockaddr_in *) src)->sin_addr.s_addr;
        dst_network = ((struct sockaddr_in *) dst)->sin_addr.s_addr;

        memset(&pseudoh, 0, sizeof(struct pseudo_header));
        memcpy(&pseudoh.src_addr, &src_network, 4);
        memcpy(&pseudoh.dst_addr, &dst_network, 4);
        pseudoh.protocol      = IPPROTO_HIP;
        length                = (hiph->payload_len + 1) * 8;
        pseudoh.packet_length = htons(length);

        count = sizeof(struct pseudo_header);                 /* count always even number */
        p     = (unsigned short *) &pseudoh;
    } else {
        /* IPv6 checksum based on IPv6 pseudo-header */
        src6 = &((struct sockaddr_in6 *) src)->sin6_addr;
        dst6 = &((struct sockaddr_in6 *) dst)->sin6_addr;

        memset(&pseudoh6, 0, sizeof(struct pseudo_header6));
        memcpy(&pseudoh6.src_addr[0], src6, 16);
        memcpy(&pseudoh6.dst_addr[0], dst6, 16);
        length                 = (hiph->payload_len + 1) * 8;
        pseudoh6.packet_length = htonl(length);
        pseudoh6.next_hdr      = IPPROTO_HIP;

        count = sizeof(struct pseudo_header6);                  /* count always even number */
        p     = (unsigned short *) &pseudoh6;
    }
    /*
     * this checksum algorithm can be found
     * in RFC 1071 section 4.1
     */

    /* sum the pseudo-header */
    /* count and p are initialized above per protocol */
    while (count > 1) {
        sum   += *p++;
        count -= 2;
    }

    /* one's complement sum 16-bit words of data */
    HIP_DEBUG("Checksumming %d bytes of data.\n", length);
    count = length;
    p     = (unsigned short *) data;
    while (count > 1) {
        sum   += *p++;
        count -= 2;
    }
    /* add left-over byte, if any */
    if (count > 0) {
        sum += (unsigned char) *p;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    /* take the one's complement of the sum */
    checksum = ~sum;

    return checksum;
}

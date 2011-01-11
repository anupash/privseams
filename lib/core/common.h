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
 * @author: Rene Hummen <rene.hummen@rwth-aachen.de>
 * @author  Mircea Gherzan <mircea.gherzan@rwth-aachen.de>
 */

#ifndef HIP_LIB_CORE_COMMON_H
#define HIP_LIB_CORE_COMMON_H

#define _BSD_SOURCE

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

/** unused attribute marking */
#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

/** marking for RVS-specific function parameters */
#ifdef CONFIG_HIP_RVS
#define RVS
#else
#define RVS UNUSED
#endif

/** marking for firewall function parameters */
#ifdef CONFIG_HIP_FIREWALL
#define HIPFW
#else
#define HIPFW UNUSED
#endif

/** marking for OPPORTUNISTIC-specific function parameters */
#ifdef CONFIG_HIP_OPPORTUNISTIC
#define OPP
#else
#define OPP UNUSED
#endif

/** marking for DEBUG-specific function parameters */
#ifdef CONFIG_HIP_DEBUG
#define DBG
#else
#define DBG UNUSED
#endif
/*********** ESP structures *************/

struct hip_esp {
    uint32_t esp_spi;
    uint32_t esp_seq;
} __attribute__ ((packed));

struct hip_esp_tail {
    uint8_t esp_padlen;
    uint8_t esp_next;
} __attribute__ ((packed));

/* maximum packet size of a packet to be sent on the wire */
#define MAX_PACKET_SIZE         1500

/* see bug id 592138
 *
 * @note if you want to make this smaller, you have to change also
 *       /proc/sys/net/ipv6/conf/default/mtu, but it will have a
 *       negative impact on non-HIP IPv6 connectivity. */
#define MIN_HIP_MTU             1280

/* change this when support for a cipher with bigger block size is added */
#define CIPHER_BLOCK_SIZE       AES_BLOCK_SIZE

/* IP version translation from IPv4 to IPv6 takes another 20 bytes */
#define IPV4_TO_IPV6            (sizeof(struct ip6_hdr) - sizeof(struct ip))

/* max. ESP padding as defined in RFC ???
 *
 * @note this allows to hide the actual payload length */
#define MAX_ESP_PADDING         255
/* this is the the max. ESP padding as needed by the cipher
 *
 * @note calculated as max. block-size - 1 */
#define CIPHER_ESP_PADDING      CIPHER_BLOCK_SIZE - 1
/* in the max packet size case we don't want to use any padding
 * -> the payload should fill the whole last block */
#define NO_ESP_PADDING          0
/* if we do IP version translation from IPv4 to IPv6 we get another IPV4_TO_IPV6
 * bytes. Consider this in the last block. */
#define OPTIMAL_ESP_PADDING CIPHER_BLOCK_SIZE - (IPV4_TO_IPV6 % CIPHER_BLOCK_SIZE)
/* change this if you want to use another padding */
#define ESP_PADDING             OPTIMAL_ESP_PADDING

/* overhead added by encapsulating the application packet in
 * an ESP packet
 *
 * @note ESP payload includes app's packet starting at transport layer
 *       -> transport layer header is part of MTU
 * @note additional space for possible IP4 -> IPv6 conversion, UDP encapsulation,
 *       ESP header, max. initialization vector for a cipher, max. allowed padding,
 *       ESP tail, ESP authentication part */
#define BEET_OVERHEAD           IPV4_TO_IPV6 \
    + sizeof(struct udphdr) + sizeof(struct hip_esp) \
    + AES_BLOCK_SIZE + ESP_PADDING \
    + sizeof(struct hip_esp_tail) + EVP_MAX_MD_SIZE
/* maximum allowed packet size coming from the application */

#define HIP_MTU                 MAX_PACKET_SIZE - (BEET_OVERHEAD)

#define HIP_HIT_DEV_MTU         HIP_MTU >= MIN_HIP_MTU ? HIP_MTU : MIN_HIP_MTU

#endif /* HIP_LIB_CORE_COMMON_H */

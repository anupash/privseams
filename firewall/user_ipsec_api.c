/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * This implementation provides the API for userspace IPsec.
 *
 * @brief API for the userspace IPsec functionality
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "esp_prot_api.h"
#include "firewall_defines.h"
#include "lsi.h"
#include "user_ipsec_esp.h"
#include "user_ipsec_fw_msg.h"
#include "user_ipsec_sadb.h"
#include "user_ipsec_api.h"


#define USER_IPSEC_INACTIVE 0
#define USER_IPSEC_ACTIVE 1

/* this is the maximum buffer-size needed for an userspace ipsec esp packet
 * including the initialization vector for ESP and the hash value of the
 * ESP protection extension */
#define MAX_ESP_PADDING     255
#define ESP_PACKET_SIZE     (HIP_MAX_PACKET + sizeof(struct udphdr) \
                             + sizeof(struct hip_esp) \
                             + AES_BLOCK_SIZE \
                             + MAX_ESP_PADDING \
                             + sizeof(struct hip_esp_tail) \
                             + EVP_MAX_MD_SIZE) \
    + MAX_HASH_LENGTH


/* this is the ESP packet we are about to build */
static unsigned char *esp_packet = NULL;
/* the original packet before ESP decryption */
static unsigned char *decrypted_packet = NULL;

/* sockets needed in order to reinject the ESP packet into the network stack */
static int raw_sock_v4 = 0;
static int raw_sock_v6 = 0;
/* allows us to make sure that we only init ones */
static int is_init = 0;
/* 0 = hipd does not know that userspace ipsec on */
static int init_hipd = 0;

/**
 * triggers user ipsec init message for hipd
 *
 * @return 0 on success, -1 otherwise
 */
static int hip_fw_userspace_ipsec_init_hipd(void)
{
    int err = 0;

    if (!is_init) {
        HIP_IFEL(send_userspace_ipsec_to_hipd(USER_IPSEC_ACTIVE), -1,
                 "hipd is not responding\n");

        HIP_DEBUG("hipd userspace ipsec activated\n");
        init_hipd = 1;
    }

out_err:

    return err;
}

/**
 * initiates the raw sockets required for packet re-inejection
 *
 * @return 0 on success, -1 otherwise
 */
static int init_raw_sockets(void)
{
    int err = 0, on = 1;

    // open IPv4 raw socket
    raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    HIP_IFEL(raw_sock_v4 < 0, -1,
             "ipv4_raw_socket socket() error for raw socket\n");

    // this option allows us to add the IP header ourselves
    HIP_IFEL(setsockopt(raw_sock_v4, IPPROTO_IP, IP_HDRINCL, (char *) &on,
                        sizeof(on)) < 0, -1,
             "setsockopt() error for IPv4 raw socket\n");

    // open IPv6 raw socket, no options needed here
    raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    HIP_IFEL(raw_sock_v6 < 0, -1,
             "ipv6_raw_socket socket() error for raw socket\n");

    // this option allows us to add the IP header ourselves
    HIP_IFEL(setsockopt(raw_sock_v6, IPPROTO_IPV6, IP_HDRINCL, (char *) &on,
                        sizeof(on)) < 0, -1,
             "setsockopt() error for IPv6 raw socket\n");

out_err:
    return err;
}

/**
 * initializes the sadb, packet buffers and the sockets and notifies
 * the hipd about the activation of userspace ipsec
 *
 * @return  0, if correct, else != 0
 */
int userspace_ipsec_init(void)
{
    int err = 0;

    HIP_DEBUG("\n");

    if (!is_init) {
        // init sadb
        HIP_IFEL(hip_sadb_init(), -1, "failed to init sadb\n");

        HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);

        // allocate memory for the packet buffers
        HIP_IFEL(!(esp_packet = malloc(ESP_PACKET_SIZE)), -1,
                 "failed to allocate memory");
        HIP_IFEL(!(decrypted_packet = malloc(ESP_PACKET_SIZE)),
                 -1, "failed to allocate memory");

        // create required sockets
        HIP_IFEL(init_raw_sockets(), -1, "raw sockets");

        // activate userspace ipsec in hipd
        HIP_DEBUG("switching hipd to userspace ipsec...\n");
        hip_fw_userspace_ipsec_init_hipd();

        is_init = 1;

        HIP_DEBUG("userspace IPsec successfully initialised\n");
    }

out_err:
    return err;
}

/**
 * uninits the sadb, frees packet buffers and notifies
 * the hipd about the deactivation of userspace ipsec
 *
 * @return 0, if correct, else != 0
 */
int userspace_ipsec_uninit(void)
{
    int err = 0;

    // deactivate userspace ipsec in hipd
    HIP_DEBUG("switching hipd to kernel-mode ipsec...\n");

    if ((err = send_userspace_ipsec_to_hipd(USER_IPSEC_INACTIVE))) {
        HIP_ERROR("failed to notify hipd about userspace ipsec deactivation\n");
    }

    hip_sadb_uninit();

    // close sockets used for reinjection
    if (raw_sock_v4) {
        close(raw_sock_v4);
    }
    if (raw_sock_v6) {
        close(raw_sock_v6);
    }

    // free the members
    free(esp_packet);
    free(decrypted_packet);

    return err;
}

/**
 * prepares the context for performing the ESP transformation
 *
 * @param ctx   the firewall context of the packet to be processed
 * @return      0, if correct, else != 0
 */
int hip_fw_userspace_ipsec_output(const struct hip_fw_context *ctx)
{
    // entry matching the peer HIT
    struct hip_sa_entry *entry = NULL;
    // the routable addresses as used in HIPL
    struct in6_addr         preferred_local_addr;
    struct in6_addr         preferred_peer_addr;
    struct sockaddr_storage preferred_peer_sockaddr;
    struct timeval          now;
    uint16_t                esp_packet_len = 0;
    int                     out_ip_version = 0;
    int                     err            = 0;
    uint16_t srcport, destport;

    /* we should only get HIT addresses here
     * LSI have been handled by LSI module before and converted to HITs */
    HIP_ASSERT(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst));

    HIP_DEBUG("original packet length: %u \n", ctx->ipq_packet->data_len);

    HIP_DEBUG_HIT("src_hit", &ctx->src);
    HIP_DEBUG_HIT("dst_hit", &ctx->dst);

    gettimeofday(&now, NULL);

    // SAs directing outwards are indexed with local and peer HIT
    entry = hip_sa_entry_find_outbound(&ctx->src, &ctx->dst);

    // create new SA entry, if none exists yet
    if (entry == NULL) {
        HIP_DEBUG("triggering BEX...\n");

        /* no SADB entry -> trigger base exchange providing src and dst hit as
         * used by the application */

        /* Provide source and destination ports.
         * This is used by the signaling module and included in the user-BEX message.
         * TODO: this should be done somewhere else (modularization) */
        if(ctx->transport_hdr.tcp) {
            srcport=ntohs(ctx->transport_hdr.tcp->source);
            destport=ntohs(ctx->transport_hdr.tcp->dest);
        } else {
            // TODO: how can protocols like ICMP(v6) without port information be handled?
            HIP_DEBUG("SIGNALING: Cannot get port information from packet.\n");
            srcport = 0;
            destport = 0;
        }

        HIP_IFEL(hip_trigger_bex(&ctx->src, &ctx->dst, NULL, NULL, NULL, NULL, srcport, destport),
                 -1, "trigger bex\n");

        // as we don't buffer the packet right now, we have to drop it
        // due to not routable addresses
        err = 1;
        // don't process this message any further
        goto out_err;
    }

    HIP_DEBUG("matching SA entry found\n");

    /* get preferred routable addresses */
    memcpy(&preferred_local_addr, &entry->src_addr, sizeof(struct in6_addr));
    memcpy(&preferred_peer_addr, &entry->dst_addr, sizeof(struct in6_addr));

    HIP_DEBUG_HIT("preferred_local_addr", &preferred_local_addr);
    HIP_DEBUG_HIT("preferred_peer_addr", &preferred_peer_addr);

    // check preferred addresses for the address type of the output
    if (IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
        && IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr)) {
        HIP_DEBUG("out_ip_version is IPv4\n");
        out_ip_version = 4;
    } else if (!IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
               && !IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr)) {
        HIP_DEBUG("out_ip_version is IPv6\n");
        out_ip_version = 6;
    } else {
        HIP_ERROR("bad address combination\n");

        err = -1;
        goto out_err;
    }

    // encrypt transport layer and create new packet
    HIP_IFEL(hip_beet_mode_output(ctx, entry, &preferred_local_addr,
                                  &preferred_peer_addr, esp_packet,
                                  &esp_packet_len),
             1, "failed to create ESP packet");

    // create sockaddr for sendto
    hip_addr_to_sockaddr(&preferred_peer_addr, &preferred_peer_sockaddr);

    // reinsert the esp packet into the network stack
    if (out_ip_version == 4) {
        err = sendto(raw_sock_v4, esp_packet, esp_packet_len, 0,
                     (struct sockaddr *) &preferred_peer_sockaddr,
                     hip_sockaddr_len(&preferred_peer_sockaddr));
    } else {
        err = sendto(raw_sock_v6, esp_packet, esp_packet_len, 0,
                     (struct sockaddr *) &preferred_peer_sockaddr,
                     hip_sockaddr_len(&preferred_peer_sockaddr));
    }

    if (err < esp_packet_len) {
        HIP_DEBUG("sendto() failed\n");
        err = -1;
    } else {
        HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
        HIP_DEBUG("dropping original packet...\n");

        // update SA statistics for replay protection etc
        entry->bytes             += err;
        entry->usetime.tv_sec     = now.tv_sec;
        entry->usetime.tv_usec    = now.tv_usec;
        entry->usetime_ka.tv_sec  = now.tv_sec;
        entry->usetime_ka.tv_usec = now.tv_usec;

        // the original packet has to be dropped
        err = 1;
    }

    // now do some esp token maintenance operations
    HIP_IFEL(esp_prot_sadb_maintenance(entry), -1,
             "esp protection extension maintenance operations failed\n");

out_err:
    return err;
}

/**
 * prepares the context for performing the ESP transformation
 *
 * @param ctx   the firewall context of the packet to be processed
 * @return      0, if correct, else != 0
 */
int hip_fw_userspace_ipsec_input(const struct hip_fw_context *ctx)
{
    struct hip_esp         *esp_hdr = NULL;
    struct sockaddr_storage local_sockaddr;
    // entry matching the SPI
    struct hip_sa_entry *entry = NULL;
    struct timeval       now;
    uint16_t             decrypted_packet_len = 0;
    uint32_t             spi                  = 0;
    int                  err                  = 0;

    gettimeofday(&now, NULL);

    /* get ESP header of input packet
     * UDP encapsulation is handled in firewall already */
    esp_hdr = ctx->transport_hdr.esp;
    spi     = ntohl(esp_hdr->esp_spi);

    // lookup corresponding SA entry by dst_addr and SPI
    HIP_IFEL(!(entry = hip_sa_entry_find_inbound(&ctx->dst, spi)), -1,
             "no SA entry found for dst_addr and SPI\n");
    HIP_DEBUG("matching SA entry found\n");

    HIP_DEBUG_HIT("src hit: ", &entry->inner_src_addr);
    HIP_DEBUG_HIT("dst hit: ", &entry->inner_dst_addr);

    // decrypt the packet and create a new HIT-based one
    HIP_IFEL(hip_beet_mode_input(ctx, entry, decrypted_packet,
                                 &decrypted_packet_len), 1,
             "failed to recreate original packet\n");

    // create sockaddr for sendto
    hip_addr_to_sockaddr(&entry->inner_dst_addr, &local_sockaddr);

    // re-insert the original HIT-based (-> IPv6) packet into the network stack
    err = sendto(raw_sock_v6, decrypted_packet, decrypted_packet_len, 0,
                 (struct sockaddr *) &local_sockaddr,
                 hip_sockaddr_len(&local_sockaddr));
    if (err < decrypted_packet_len) {
        HIP_DEBUG("sendto() failed\n");
        err = -1;
    } else {
        HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
        HIP_DEBUG("dropping ESP packet...\n");

        entry->bytes             += err;
        entry->usetime.tv_sec     = now.tv_sec;
        entry->usetime.tv_usec    = now.tv_usec;
        entry->usetime_ka.tv_sec  = now.tv_sec;
        entry->usetime_ka.tv_usec = now.tv_usec;

        // the original packet has to be dropped
        err = 1;
    }

out_err:
    return err;
}

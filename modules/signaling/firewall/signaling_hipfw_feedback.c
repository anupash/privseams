/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "config.h"

#include "lib/core/crypto.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/tool/pk.h"
#include "lib/tool/nlink.h"
#include "lib/tool/checksum.h"

#include "firewall/helpers.h"

#include "signaling_hipfw_feedback.h"
#include "modules/signaling/lib/signaling_x509_api.h"
#include "modules/signaling/lib/signaling_common_builder.h"

/* The identity of the firewall */
static RSA            *rsa_key  = NULL;
static EC_KEY         *priv_key = NULL;
static X509           *cert     = NULL;
static struct in6_addr our_hit;

/* Sockets for output */
static int        hipfw_nat_sock_output_udp = 0;
UNUSED static int hipfw_raw_sock_output_v4  = 0;
UNUSED static int hipfw_raw_sock_output_v6  = 0;

struct rtnl_handle hipfw_nl_route;

static int set_cloexec_flag(int desc, int value)
{
    int oldflags = fcntl(desc, F_GETFD, 0);
    /* If reading the flags failed, return error indication now.*/
    if (oldflags < 0) {
        return oldflags;
    }
    /* Set just the flag we want to set. */

    if (value != 0) {
        oldflags |=  FD_CLOEXEC;
    } else {
        oldflags &= ~FD_CLOEXEC;
    }
    /* Store modified flag word in the descriptor. */
    return fcntl(desc, F_SETFD, oldflags);
}

static int select_source_address(struct in6_addr *src, const struct in6_addr *dst)
{
    int             err        = 0;
    int             family     = AF_INET;
    struct idxmap  *idxmap[16] = { 0 };
    struct in6_addr lpback     = IN6ADDR_LOOPBACK_INIT;

    HIP_DEBUG_IN6ADDR("dst", dst);

    /* Required for loopback connections */
    if (!ipv6_addr_cmp(dst, &lpback)) {
        ipv6_addr_copy(src, dst);
        goto out_err;
    }

    HIP_IFEL(hip_iproute_get(&hipfw_nl_route, src, dst, NULL, NULL, family, idxmap), -1, "Finding ip route failed\n");

    HIP_DEBUG_IN6ADDR("src", src);

out_err:
    return err;
}

static int init_raw_sock_v4(int proto)
{
    int on = 1, off = 0, err = 0;
    int sock;

    sock = socket(AF_INET, SOCK_RAW, proto);
    set_cloexec_flag(sock, 1);
    HIP_IFEL(sock <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* RECV_ERR is off because it is not handled properly by hipd
     * (message length is -1 and this causes msg reading problems) */
    err = setsockopt(sock, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

    return sock;

out_err:
    return -1;
}

/**
 * Initialize the middlebox firewall application.
 * This sets up the firewall's policies.
 *
 * @param policy_file   the configuration file (in libconfig format) that specifies
 *                      the firewall's policy. If NULL, a default policy is used.
 *
 * @return              0 on success, negative on error
 */
int signaling_hipfw_feedback_init(const char *key_file, const char *cert_file)
{
    int err = 0;

    /* Load the host identity */
    load_rsa_private_key(key_file, &rsa_key);
    //load_ecdsa_private_key(key_file, &priv_key);
    HIP_DEBUG("Successfully Loaded the MiddleBox RSA key. Should not crash anymore.\n");

    cert = load_x509_certificate(cert_file);
    //hip_any_key_to_hit(priv_key, &our_hit, 0, HIP_HI_ECDSA);
    hip_any_key_to_hit(rsa_key, &our_hit, 0, HIP_HI_RSA);
    HIP_INFO_HIT("Our hit: ", &our_hit);

    /* Sockets */
    hipfw_nat_sock_output_udp = init_raw_sock_v4(IPPROTO_UDP);
    if (hipfw_nat_sock_output_udp > 0) {
        HIP_DEBUG("Successfully initialized nat output socket. \n");
    } else {
        HIP_DEBUG("Failed to bind output socket. \n");
    }

    if (rtnl_open_byproto(&hipfw_nl_route,
                          RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
                          | RTMGRP_IPV4_IFADDR | IPPROTO_IP,
                          NETLINK_ROUTE) < 0) {
        err = 1;
        HIP_ERROR("Routing socket error: %s\n", strerror(errno));
        goto out_err;
    } else {
        HIP_DEBUG("Successfully opened netlink socket \n");
    }

    /* flush ip table rules to not catch our own notify... */
    system_print("iptables -D HIPFW-OUTPUT 1");
    system_print("iptables -D HIPFW-OUTPUT 1");

out_err:
    return err;
}

/**
 * Uninitialize the middlebox firewall application.
 * So far, there's nothing to be done.
 *
 * @return 0 on success, negative on error
 */
int signaling_hipfw_feedback_uninit(void)
{
    HIP_DEBUG("Uninit signaling firewall feedback module \n");
    EC_KEY_free(priv_key);
    RSA_free(rsa_key);
    X509_free(cert);
    return 0;
}

static int send_raw_from_one_src(const struct in6_addr *local_addr,
                                 const struct in6_addr *peer_addr,
                                 const in_port_t src_port,
                                 const in_port_t dst_port,
                                 struct hip_common *msg)
{
    int                     err = 0, sa_size, sent, len = 0, dupl, try_again, udp = 0;
    struct sockaddr_storage src, dst;
    int                     src_is_ipv4 = 0, dst_is_ipv4 = 0, memmoved = 0;
    struct sockaddr_in6    *src6        = NULL, *dst6 = NULL;
    struct sockaddr_in     *src4        = NULL, *dst4 = NULL;
    struct in6_addr         my_addr;
    /* Points either to v4 or v6 raw sock */
    int hipfw_raw_sock_output = 0;

    /* Verify the existence of obligatory parameters. */
    HIP_ASSERT(peer_addr != NULL && msg != NULL);

    HIP_DEBUG("Sending %s packet\n",
              hip_message_type_name(hip_get_msg_type(msg)));
    HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
    HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
    HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
    HIP_DUMP_MSG(msg);

    //check msg length
    if (!hip_check_network_msg_len(msg)) {
        err = -EMSGSIZE;
        HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
        goto out_err;
    }

    dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
    len         = hip_get_msg_total_len(msg);

    /* Some convinient short-hands to avoid too much casting (could be
     * an union as well) */
    src6 = (struct sockaddr_in6 *) &src;
    dst6 = (struct sockaddr_in6 *) &dst;
    src4 = (struct sockaddr_in *) &src;
    dst4 = (struct sockaddr_in *) &dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    if (dst_port && dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 UDP socket\n");
        hipfw_raw_sock_output = hipfw_nat_sock_output_udp;
        sa_size               = sizeof(struct sockaddr_in);
        udp                   = 1;
    } else if (dst_is_ipv4) {
        HIP_DEBUG("Using IPv4 raw socket\n");
        //hipfw_raw_sock_output = hipfw_raw_sock_output_v4;
        //sa_size             = sizeof(struct sockaddr_in);
    } else {
        HIP_DEBUG("Using IPv6 raw socket\n");
        //hipfw_raw_sock_output = hipfw_raw_sock_output_v6;
        //sa_size             = sizeof(struct sockaddr_in6);
    }

    if (local_addr) {
        HIP_DEBUG("local address given\n");

        memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
    } else {
        HIP_DEBUG("no local address, selecting one\n");
        HIP_IFEL(select_source_address(&my_addr, peer_addr), -1,
                 "Cannot find source address\n");
    }

    src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

    if (src_is_ipv4) {
        IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
        src4->sin_family = AF_INET;
        HIP_DEBUG_INADDR("src4", &src4->sin_addr);
    } else {
        memcpy(&src6->sin6_addr, &my_addr,
               sizeof(struct in6_addr));
        src6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
    }

    if (dst_is_ipv4) {
        IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
        dst4->sin_family = AF_INET;

        HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
    } else {
        memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
        dst6->sin6_family = AF_INET6;
        HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
    }

    if (src6->sin6_family != dst6->sin6_family) {
        /* @todo: Check if this may cause any trouble.
         * It happens every time we send update packet that contains few locators in msg, one is
         * the IPv4 address of the source, another is IPv6 address of the source. But even if one of
         * them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all
         * updates are dropped.  by Andrey "laser".
         *
         */
        err = -1;
        HIP_ERROR("Source and destination address families differ\n");
        goto out_err;
    }

    hip_zero_msg_checksum(msg);
    if (!udp) {
        msg->checksum = hip_checksum_packet((char *) msg,
                                            (struct sockaddr *) &src,
                                            (struct sockaddr *) &dst);
    }


    /* Handover may cause e.g. on-link duplicate address detection
     * which may cause bind to fail. */

    HIP_IFEL(bind(hipfw_raw_sock_output, (struct sockaddr *) &src, sa_size),
             -1, "Binding to raw sock failed\n");

    /* For some reason, neither sendmsg or send (with bind+connect)
     * do not seem to work properly. Thus, we use just sendto() */

    len = hip_get_msg_total_len(msg);

    if (udp) {
        struct udphdr *uh = (struct udphdr *) msg;

        /* Insert 32 bits of zero bytes between UDP and HIP */
        memmove(((char *) msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr), msg, len);
        memset(((char *) msg), 0, HIP_UDP_ZERO_BYTES_LEN  + sizeof(struct udphdr));
        len += HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);

        uh->source = htons(src_port);
        uh->dest   = htons(dst_port);
        uh->len    = htons(len);
        uh->check  = 0;
        memmoved   = 1;
    }

    for (dupl = 0; dupl < 1; dupl++) {
        for (try_again = 0; try_again < 2; try_again++) {
            sent = sendto(hipfw_raw_sock_output, msg, len, 0,
                          (struct sockaddr *) &dst, sa_size);
            if (sent != len) {
                HIP_ERROR("Could not send the all requested" \
                          " data (%d/%d)\n", sent, len);
                HIP_DEBUG("strerror %s\n", strerror(errno));
                sleep(2);
            } else {
                HIP_DEBUG("sent=%d/%d ipv4=%d\n",
                          sent, len, dst_is_ipv4);
                HIP_DEBUG("Packet sent ok\n");
                break;
            }
        }
    }
out_err:

    /* Reset the interface to wildcard or otherwise receiving
     * broadcast messages fails from the raw sockets. A better
     * solution would be to have separate sockets for sending
     * and receiving because we cannot receive a broadcast while
     * sending */
    if (dst_is_ipv4) {
        src4->sin_addr.s_addr = INADDR_ANY;
        src4->sin_family      = AF_INET;
        sa_size               = sizeof(struct sockaddr_in);
    } else {
        struct in6_addr any = IN6ADDR_ANY_INIT;
        src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&src6->sin6_addr, &any);
        sa_size = sizeof(struct sockaddr_in6);
    }
    bind(hipfw_raw_sock_output, (struct sockaddr *) &src, sa_size);

    if (udp && memmoved) {
        /* Remove 32 bits of zero bytes between UDP and HIP */
        len -= HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);
        memmove((char *) msg, ((char *) msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr),
                len);
        memset(((char *) msg) + len, 0,
               HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr));
    }

    if (err) {
        HIP_ERROR("strerror: %s\n", strerror(errno));
    }

    return err;
}

static int send_pkt(const struct in6_addr *local_addr,
                    const struct in6_addr *peer_addr,
                    const in_port_t src_port,
                    const in_port_t dst_port,
                    struct hip_common *msg)
{
    return send_raw_from_one_src(local_addr, peer_addr, src_port, dst_port, msg);
}

/**
 * Build and send a notification about failed connection establishment.
 *
 * @param reason    the reason why the authentication failed
 */
int signaling_hipfw_send_connection_failed_ntf(struct hip_common *common,
                                               UNUSED struct tuple *tuple,
                                               const struct hip_fw_context *ctx,
                                               const int reason,
                                               const struct signaling_connection *conn)
{
    int                err      = 0;
    uint16_t           mask     = 0;
    struct hip_common *msg_buf  = NULL;
    struct hip_common *msg_buf2 = NULL;
    unsigned char     *buf;
    int                cert_len = 0;

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the notify packet\n");
    hip_build_network_hdr(msg_buf, HIP_NOTIFY, mask, &our_hit, &common->hits);
    HIP_IFEL(!(msg_buf2 = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the notify packet\n");
    hip_build_network_hdr(msg_buf2, HIP_NOTIFY, mask, &our_hit, &common->hitr);

    /* Append certificate */
    HIP_IFEL((cert_len = signaling_X509_to_DER(cert, &buf)) < 0,
             -1, "Could not get DER encoding of certificate\n");
    HIP_IFEL(hip_build_param_cert(msg_buf, 0, 1, 1, HIP_CERT_X509V3, buf, cert_len),
             -1, "Could not build cert parameter\n");
    HIP_IFEL(hip_build_param_cert(msg_buf2, 0, 1, 1, HIP_CERT_X509V3, buf, cert_len),
             -1, "Could not build cert parameter\n");
    free(buf);

    /* Append notification parameter */
    signaling_build_param_connection_fail(msg_buf, reason);
    signaling_build_param_connection_fail(msg_buf2, reason);


    /* Append connection identifier */
    signaling_build_param_connection_identifier(msg_buf, conn);
    signaling_build_param_connection_identifier(msg_buf2, conn);
    /* Append hits */
    HIP_IFEL(hip_build_param_contents(msg_buf, &common->hitr, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg_buf2, &common->hits, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");

    /* Sign the packet */
    HIP_IFEL(hip_ecdsa_sign(priv_key, msg_buf),
             -1, "Could not sign notification for source host \n");
    HIP_IFEL(hip_ecdsa_sign(priv_key, msg_buf2),
             -1, "Could not sign notification for destination host\n");

    /* Send to source and destination of the connection */
    if (send_pkt(NULL, &ctx->src, 10500, 10500, msg_buf)) {
        HIP_ERROR("Could not notify the source of a connection reject \n");
    }
    free(msg_buf);
    if (send_pkt(NULL, &ctx->dst, 10500, 10500, msg_buf2)) {
        HIP_ERROR("Could not notify the destination of a connection reject \n");
    }
    free(msg_buf2);

out_err:
    return err;
}

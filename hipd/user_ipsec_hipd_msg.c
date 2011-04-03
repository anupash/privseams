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
 * Messaging required for the userspace IPsec implementation of the hipfw
 *
 * @brief userspace IPsec hipd <-> hipfw communication
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"
#include "lib/tool/xfrmapi.h"
#include "esp_prot_hipd_msg.h"
#include "hipd.h"
#include "init.h"
#include "user_ipsec_sadb_api.h"
#include "user_ipsec_hipd_msg.h"


/**
 * handles a userspace ipsec activation message sent by the fw
 *
 * @param msg   the message sent by the firewall
 * @return      0, if ok, != 0 else
 */
int hip_userspace_ipsec_activate(const struct hip_common *msg)
{
    const struct hip_tlv_common *param = NULL;
    int                          err   = 0, activate = 0;

    // process message and store anchor elements in the db
    param    = hip_get_param(msg, HIP_PARAM_INT);
    activate = *((const int *) hip_get_param_contents_direct(param));

    // set global variable
    hip_use_userspace_ipsec = activate;
    HIP_DEBUG("userspace ipsec set to %i\n", activate);

    /* remove the policies from the kernel-mode IPsec when switching to userspace,
     * otherwise app-packets will still be captured and processed by the kernel
     *
     * we don't have to to this when we switch back to kernel-mode, as it will
     * only be the case when the firewall is shut down
     * -> firewall might already be closed when user-message arrives */
    if (hip_use_userspace_ipsec) {
        HIP_DEBUG("flushing all ipsec policies in the kernel...\n");
        hip_flush_all_policy();
        HIP_DEBUG("flushing all ipsec SAs in the kernel...\n");
        hip_flush_all_sa();
    }

    return err;
}

/** creates a user-message to add a SA to userspace IPsec
 *
 * @param saddr          outer globally routable source ip address
 * @param daddr          outer globally routable destination ip address
 * @param src_hit    inner source address
 * @param dst_hit    inner destination address
 * @param spi               ipsec spi for demultiplexing
 * @param ealg              crypto transform to be used for the SA
 * @param enckey           raw encryption key
 * @param authkey          raw authentication key
 * @param retransmission    notification if this event is due to retransmission
 * @param direction         represents inbound or outbound direction
 * @param update            notification if this event derives from an update
 * @param entry             host association entry for this connection
 * @return                  the msg, NULL if an error occurred
 */
struct hip_common *create_add_sa_msg(const struct in6_addr *saddr,
                                     const struct in6_addr *daddr,
                                     const struct in6_addr *src_hit,
                                     const struct in6_addr *dst_hit,
                                     const uint32_t spi, const int ealg,
                                     const struct hip_crypto_key *enckey,
                                     const struct hip_crypto_key *authkey,
                                     const int retransmission,
                                     const int direction, const int update,
                                     struct hip_hadb_state *entry)
{
    struct hip_common *msg = NULL;
    int                err = 0;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "alloc memory for adding sa entry\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_IPSEC_ADD_SA, 0), -1,
             "build hdr failed\n");

    HIP_DEBUG_IN6ADDR("Source IP address: ", saddr);
    HIP_IFEL(hip_build_param_contents(msg, saddr,
                                      HIP_PARAM_IPV6_ADDR,
                                      sizeof(struct in6_addr)), -1,
             "build param contents failed\n");

    HIP_DEBUG_IN6ADDR("Destination IP address : ", daddr);
    HIP_IFEL(hip_build_param_contents(msg, daddr,
                                      HIP_PARAM_IPV6_ADDR,
                                      sizeof(struct in6_addr)), -1,
             "build param contents failed\n");

    HIP_DEBUG_HIT("Source HIT: ", src_hit);
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1,
             "build param contents failed\n");

    HIP_DEBUG_HIT("Destination HIT: ", dst_hit);
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT,
                                      sizeof(struct in6_addr)), -1,
             "build param contents failed\n");

    HIP_DEBUG("the spi value is : %x \n", spi);
    HIP_IFEL(hip_build_param_contents(msg, &spi, HIP_PARAM_UINT,
                                      sizeof(uint32_t)), -1,
             "build param contents failed\n");

    HIP_DEBUG("the nat_mode value is %u \n", entry->nat_mode);
    HIP_IFEL(hip_build_param_contents(msg, &entry->nat_mode, HIP_PARAM_UINT,
                                      sizeof(uint8_t)), -1,
             "build param contents failed\n");

    HIP_DEBUG("the local_port value is %u \n", entry->local_udp_port);
    HIP_IFEL(hip_build_param_contents(msg, &entry->local_udp_port,
                                      HIP_PARAM_UINT, sizeof(uint16_t)), -1, "build param contents failed\n");

    HIP_DEBUG("the peer_port value is %u \n", entry->peer_udp_port);
    HIP_IFEL(hip_build_param_contents(msg, &entry->peer_udp_port,
                                      HIP_PARAM_UINT, sizeof(uint16_t)), -1, "build param contents failed\n");

    // params needed by the esp protection extension
    HIP_IFEL(esp_prot_sa_add(entry, msg, direction, update), -1,
             "failed to add esp prot params\n");

    HIP_HEXDUMP("crypto key :", enckey, sizeof(struct hip_crypto_key));
    HIP_IFEL(hip_build_param_contents(msg,
                                      enckey,
                                      HIP_PARAM_KEYS,
                                      sizeof(struct hip_crypto_key)), -1,
             "build param contents failed\n");

    HIP_HEXDUMP("authen key :", authkey, sizeof(struct hip_crypto_key));
    HIP_IFEL(hip_build_param_contents(msg,
                                      authkey,
                                      HIP_PARAM_KEYS,
                                      sizeof(struct hip_crypto_key)), -1,
             "build param contents failed\n");

    HIP_DEBUG("ealg value is %d \n", ealg);
    HIP_IFEL(hip_build_param_contents(msg, &ealg, HIP_PARAM_INT,
                                      sizeof(int)), -1,
             "build param contents failed\n");

    HIP_DEBUG("retransmission value is %d \n", retransmission);
    HIP_IFEL(hip_build_param_contents(msg, &retransmission,
                                      HIP_PARAM_INT, sizeof(int)), -1,
             "build param contents failed\n");

    HIP_DEBUG("the direction value is %d \n", direction);
    HIP_IFEL(hip_build_param_contents(msg, &direction,
                                      HIP_PARAM_INT,
                                      sizeof(int)), -1,
             "build param contents failed\n");

    HIP_DEBUG("the update value is %d \n", update);
    HIP_IFEL(hip_build_param_contents(msg, &update, HIP_PARAM_INT,
                                      sizeof(int)), -1,
             "build param contents failed\n");

out_err:
    if (err) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

/** creates a user-message to delete a SA from userspace IPsec
 *
 * @param spi       ipsec spi for demultiplexing
 * @param peer_addr  outer globally routable source ip address
 * @param dst_addr  outer globally routable destination ip address
 * @param family    protocol family of above addresses
 * @param src_port  local port for this host association
 * @param dst_port  peer port for this host association
 * @return          the msg, NULL if an error occured
 */
struct hip_common *create_delete_sa_msg(const uint32_t spi,
                                        const struct in6_addr *peer_addr,
                                        const struct in6_addr *dst_addr,
                                        const int family,
                                        const int src_port,
                                        const int dst_port)
{
    struct hip_common *msg = NULL;
    int                err = 0;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "alloc memory for adding sa entry\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_IPSEC_DELETE_SA, 0), -1,
             "build hdr failed\n");

    HIP_DEBUG("spi value: %u\n", spi);
    HIP_IFEL(hip_build_param_contents(msg, &spi, HIP_PARAM_UINT,
                                      sizeof(uint32_t)), -1, "build param contents failed\n");

    HIP_DEBUG_IN6ADDR("peer address: ", peer_addr);
    HIP_IFEL(hip_build_param_contents(msg, peer_addr, HIP_PARAM_IPV6_ADDR,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");

    HIP_DEBUG_IN6ADDR("destination address: ", dst_addr);
    HIP_IFEL(hip_build_param_contents(msg, dst_addr, HIP_PARAM_IPV6_ADDR,
                                      sizeof(struct in6_addr)), -1, "build param contents failed\n");

    HIP_DEBUG("family: %i\n", family);
    HIP_IFEL(hip_build_param_contents(msg, &family, HIP_PARAM_INT,
                                      sizeof(int)), -1, "build param contents failed\n");

    HIP_DEBUG("src_port: %i\n", src_port);
    HIP_IFEL(hip_build_param_contents(msg, &src_port, HIP_PARAM_INT,
                                      sizeof(int)), -1, "build param contents failed\n");

    HIP_DEBUG("src_port: %i\n", dst_port);
    HIP_IFEL(hip_build_param_contents(msg, &dst_port, HIP_PARAM_INT,
                                      sizeof(int)), -1, "build param contents failed\n");

out_err:
    if (err) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

/**
 * create a user-message to flush all SAs from userspace IPsec
 *
 * @return      the msg, NULL if an error occured
 */
struct hip_common *create_flush_all_sa_msg(void)
{
    struct hip_common *msg = NULL;
    int                err = 0;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "alloc memory for adding sa entry\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_IPSEC_FLUSH_ALL_SA, 0), -1,
             "build hdr failed\n");

    // this triggers the flushing without specifying any parameters

out_err:
    if (err) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

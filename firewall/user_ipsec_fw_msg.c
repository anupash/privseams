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
 * Inter-process communication with the hipd for userspace IPsec
 *
 * @brief Inter-process communication with the hipd for userspace IPsec
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "esp_prot_fw_msg.h"
#include "firewall.h"
#include "user_ipsec_sadb.h"
#include "user_ipsec_fw_msg.h"


#define DEFAULT_LIFETIME 0 /* place holder as timeout not implemented yet */

/**
 * sends a userspace ipsec (de-)activation user-message to the hipd
 *
 * @param activate 1 - activate, 0 - deactivate
 * @return 0, if message sent and received ok, != 0 else
 */
int send_userspace_ipsec_to_hipd(const int activate)
{
    int                err = 0;
    struct hip_common *msg = NULL;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "alloc memory for adding sa entry\n");

    hip_msg_init(msg);

    /* send this message on activation or for deactivation when -I is specified */
    if (activate || hip_kernel_ipsec_fallback) {
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_USERSPACE_IPSEC, 0), -1,
                 "build hdr failed\n");

        HIP_IFEL(hip_build_param_contents(msg, &activate,
                                          HIP_PARAM_INT,
                                          sizeof(unsigned int)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("sending userspace ipsec (de-)activation to hipd...\n");
    } else {
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_RST, 0), -1,
                 "build hdr failed\n");

        HIP_DEBUG("sending close all connections to hipd...\n");
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
             "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
    HIP_DEBUG("send_recv msg succeeded\n");

    HIP_DEBUG("userspace ipsec activated\n");

out_err:
    free(msg);
    return err;
}

/**
 * handles a SA add request sent by the hipd
 *
 * @param msg the received message
 * @return 0, if message sent and received ok, != 0 else
 */
int handle_sa_add_request(const struct hip_common *msg)
{
    const struct hip_tlv_common *param            = NULL;
    const struct in6_addr       *src_addr         = NULL, *dst_addr = NULL;
    const struct in6_addr       *src_hit          = NULL, *dst_hit = NULL;
    uint32_t                     spi              = 0;
    int                          ealg             = 0, err = 0;
    const struct hip_crypto_key *enc_key          = NULL, *auth_key = NULL;
    int                          retransmission   = 0, direction = 0, update = 0;
    uint16_t                     local_port       = 0, peer_port = 0;
    uint8_t                      encap_mode       = 0, esp_prot_transform = 0;
    uint32_t                     hash_item_length = 0;
    uint16_t                     esp_num_anchors;
    unsigned char                esp_prot_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];

    /* get all attributes from the message */

    param    = hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
    src_addr = hip_get_param_contents_direct(param);
    HIP_DEBUG_IN6ADDR("Source IP address: ", src_addr);

    param    = hip_get_next_param(msg, param);
    dst_addr = hip_get_param_contents_direct(param);
    HIP_DEBUG_IN6ADDR("Destination IP address : ", dst_addr);

    param   = hip_get_param(msg, HIP_PARAM_HIT);
    src_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Source Hit: ", src_hit);

    param   = hip_get_next_param(msg, param);
    dst_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

    param = hip_get_param(msg, HIP_PARAM_UINT);
    spi   = *((const uint32_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the spi value is : 0x%lx \n", spi);

    param      = hip_get_next_param(msg, param);
    encap_mode = *((const uint8_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the nat_mode value is %u \n", encap_mode);

    param      = hip_get_next_param(msg, param);
    local_port = *((const uint16_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the local_port value is %u \n", local_port);

    param     = hip_get_next_param(msg, param);
    peer_port = *((const uint16_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the peer_port value is %u \n", peer_port);

    /* parse the esp protection extension parameters */
    HIP_IFEL(esp_prot_handle_sa_add_request(msg, &esp_prot_transform,
                                            &esp_num_anchors, esp_prot_anchors, &hash_item_length),
             -1, "failed to retrieve esp prot anchor\n");

    param   = hip_get_param(msg, HIP_PARAM_KEYS);
    enc_key = hip_get_param_contents_direct(param);
    HIP_HEXDUMP("crypto key:", enc_key, sizeof(struct hip_crypto_key));

    param    = hip_get_next_param(msg, param);
    auth_key = hip_get_param_contents_direct(param);
    HIP_HEXDUMP("auth key:", auth_key, sizeof(struct hip_crypto_key));

    param = hip_get_param(msg, HIP_PARAM_INT);
    ealg  = *((const int *) hip_get_param_contents_direct(param));
    HIP_DEBUG("ealg value is %d \n", ealg);

    param          =  hip_get_next_param(msg, param);
    retransmission = *((const int *) hip_get_param_contents_direct(param));
    HIP_DEBUG("already_acquired value is %d \n", retransmission);

    param     =  hip_get_next_param(msg, param);
    direction = *((const int *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the direction value is %d \n", direction);

    param  =  hip_get_next_param(msg, param);
    update = *((const int *) hip_get_param_contents_direct(param));
    HIP_DEBUG("the update value is %d \n", update);

    HIP_IFEL(hip_sadb_add(direction, spi, BEET_MODE, src_addr, dst_addr,
                          src_hit, dst_hit, encap_mode, local_port, peer_port, ealg,
                          auth_key, enc_key, DEFAULT_LIFETIME, esp_prot_transform,
                          hash_item_length, esp_num_anchors, esp_prot_anchors,
                          retransmission, update),
             -1, "failed to add user_space IPsec security association\n");

out_err:
    return err;
}

/**
 * handles a SA delete request sent by the hipd
 *
 * @param msg the received message
 * @return 0, if message sent and received ok, != 0 else
 */
int handle_sa_delete_request(const struct hip_common *msg)
{
    const struct hip_tlv_common *param     = NULL;
    uint32_t                     spi       = 0;
    const struct in6_addr       *peer_addr = NULL;
    const struct in6_addr       *dst_addr  = NULL;
    int                          err       = 0;

    /* get all attributes from the message */

    param = hip_get_param(msg, HIP_PARAM_UINT);
    spi   = *((const uint32_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("spi value: 0x%lx \n", spi);

    param     = hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
    peer_addr = hip_get_param_contents_direct(param);
    HIP_DEBUG_IN6ADDR("peer address: ", peer_addr);

    param    = hip_get_next_param(msg, param);
    dst_addr = hip_get_param_contents_direct(param);
    HIP_DEBUG_IN6ADDR("dst address: ", dst_addr);

    /* work-around due to broken sa_delete in hipd */
    /** @todo remove when fixed */
    if (ipv6_addr_is_hit(peer_addr) || spi == 0) {
        // drop these cases
        HIP_DEBUG("this is an inconsistent case, DROP\n");

        err = 0;
        goto out_err;
    }

    /* the only useful information here are the spi and peer address */
    hip_sadb_delete(peer_addr, spi);

out_err:
    return err;
}

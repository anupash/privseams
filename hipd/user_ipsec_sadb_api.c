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
 * Provides the API used by the hipd to set up and maintain the
 * userspace IPsec state in the hipfw.
 *
 * @brief API used by the hipd to set up and maintain userspace IPsec state
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "lib/core/debug.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"
#include "user.h"
#include "user_ipsec_hipd_msg.h"
#include "user_ipsec_sadb_api.h"


/** generic send function used to send the below created messages
 *
 * @param msg   the message to be sent
 * @return      0, if correct, else != 0
 */
static int hip_userspace_ipsec_send_to_fw(const struct hip_common *msg)
{
    struct sockaddr_in6 hip_fw_addr;
    struct in6_addr     loopback = in6addr_loopback;
    int                 err      = 0;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_fw_addr.sin6_addr, &loopback);

    err = hip_sendto_user(msg, (struct sockaddr *) &hip_fw_addr);
    if (err < 0) {
        HIP_ERROR("sending of message to firewall failed\n");

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("sending of message to firewall successful\n");

        // this is needed if we want to use HIP_IFEL
        err = 0;
    }

out_err:
    return err;
}

/** adds a new SA entry for the specified direction to the sadb in userspace ipsec
 * @note  If you make changes to this function, please change also hip_add_sa()
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
 * @return                  0, if correct, otherwise -1
 */
uint32_t hip_userspace_ipsec_add_sa(const struct in6_addr *saddr,
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

    HIP_ASSERT(spi != 0);

    HIP_IFEL(entry->disable_sas == 1, 0, "SA creation disabled\n");

    if (direction == HIP_SPI_DIRECTION_OUT) {
        entry->outbound_sa_count++;
    } else {
        entry->inbound_sa_count++;
    }

    HIP_IFEL(!(msg = create_add_sa_msg(saddr, daddr, src_hit, dst_hit, spi, ealg, enckey,
                                       authkey, retransmission, direction, update, entry)), -1,
             "failed to create add_sa message\n");

    HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

out_err:
    return err;
}

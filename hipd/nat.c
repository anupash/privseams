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
 * This file defines extensions to Host Identity Protocol (HIP) to support
 * traversal of Network Address Translator (NAT) middleboxes.
 *
 * The traversal mechanism tunnels HIP control and data traffic over UDP
 * and enables HIP initiators which may be behind NATs to contact HIP
 * responders which may be behind another NAT. Three basic cases exist for NAT
 * traversal. In the first case, only the initiator of a HIP base exchange is
 * located behind a NAT. In the second case, only the responder of a HIP base
 * exchange is located behind a NAT. In the third case, both parties are
 * located behind (different) NATs. The use rendezvous server is mandatory
 * when the responder is behind a NAT.
 *
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-02.txt">
 *          draft-schmitt-hip-nat-traversal-02</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    All Doxygen comments have been added in version 1.1.
 */

#define _BSD_SOURCE

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/state.h"
#include "hadb.h"
#include "hipd.h"
#include "output.h"
#include "user.h"
#include "nat.h"

static int nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;

/**
 * Sends an NAT Keep-Alive packet.
 *
 * Sends an UPDATE packet with nothing but @c HMAC parameter in it to the peer's
 * preferred address. If the @c entry is @b not in state ESTABLISHED or if there
 * is no NAT between this host and the peer (@c entry->nat_mode = 0), then no
 * packet is sent. The packet is send on UDP with source and destination ports
 * set as @c hip_nat_udp_port.
 *
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param opaque   this parameter is not used (but it's needed).
 * @return         zero on success, or negative error value on error.
 * @note           If the state of @c entry is not ESTABLISHED or if
 *                 @c entry->nat_mode = 0 this function still returns zero
 *                 because these conditions are not errors. Negative error
 *                 value is only returned when the creation of the new UPDATE
 *                 message fails in some way.
 */
static int hip_nat_send_keep_alive(struct hip_hadb_state *entry,
                                   UNUSED void *opaque)
{
    int                err = 0;
    struct hip_common *msg = NULL;

    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "Alloc\n");

    /* Check that the host association is in correct state and that there is
     * a NAT between this host and the peer. Note, that there is no error
     * (err is set to zero) if the condition does not hold. We just don't
     * send the packet in that case. */
    if (entry->state != HIP_STATE_ESTABLISHED) {
        HIP_DEBUG("Not sending NAT keepalive state=%s\n", hip_state_str(entry->state));
        goto out_err;
    }

    if (!(entry->nat_mode)) {
        HIP_DEBUG("No nat between the localhost and the peer\n");
        goto out_err;
    }

    if (!IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
        HIP_DEBUG("Not IPv4 address, skip NAT keepalive\n");
        goto out_err;
    }

    hip_build_network_hdr(msg, HIP_NOTIFY,
                          0, &entry->hit_our,
                          &entry->hit_peer);

    /* Calculate the HIP header length */
    hip_calc_hdr_len(msg);

    /* Send the UPDATE packet using hip_get_nat_udp_port() as source and destination ports.
     * Only outgoing traffic acts refresh the NAT port state. We could
     * choose to use other than hip_get_nat_udp_port() as source port, but we must use hip_get_nat_udp_port()
     * as destination port. However, because it is recommended to use
     * hip_get_nat_udp_port() as source port also, we choose to do so here. */
    hip_send_pkt(&entry->our_addr, &entry->peer_addr,
                 entry->local_udp_port, entry->peer_udp_port, msg,
                 entry, 0);

out_err:
    free(msg);
    return err;
}

/**
 * Refreshes the port state of all NATs related to this host.
 *
 * Refreshes the port state of all NATs between current host and all its peer
 * hosts by calling hip_nat_send_keep_alive() for each host association in
 * the host association database.
 *
 * @return zero on success, or negative error value on error.
 */
int hip_nat_refresh_port(void)
{
    int err = 0;

    if (!hip_nat_status) {
        return 0;
    }

    if (nat_keep_alive_counter < 0) {
        HIP_DEBUG("Sending Keep-Alives to NAT.\n");
        HIP_IFEL(hip_for_each_ha(hip_nat_send_keep_alive, NULL),
                 -1, "for_each_ha() err.\n");

        nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
    } else {
        nat_keep_alive_counter--;
    }

out_err:
    return err;
}

/**
 * Get HIP NAT status.
 * TODO doxygen header
 */
hip_transform_suite hip_get_nat_mode(struct hip_hadb_state *entry)
{
    if (entry) {
        return entry->nat_mode;
    }
    return hip_nat_status;
}

/**
 * Sets NAT status "on" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param mode     nat mode
 * @return         zero.
 * @note           the status is changed just for the parameter host
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
static int hip_ha_set_nat_mode(struct hip_hadb_state *entry, void *mode)
{
    int err = 0;
    if (entry && mode != HIP_NAT_MODE_NONE) {
        entry->nat_mode = *((hip_transform_suite *) mode);
        HIP_DEBUG("NAT status of host association %p: %d\n",
                  entry, entry->nat_mode);
    }
    return err;
}

/**
 * Sets NAT status
 *
 * Sets NAT mode for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */
int hip_user_nat_mode(int nat_mode)
{
    int err = 0, nat;
    HIP_DEBUG("hip_user_nat_mode() invoked. mode: %d\n", nat_mode);

    nat = nat_mode;
    switch (nat) {
    case HIP_MSG_SET_NAT_PLAIN_UDP:
        nat = HIP_NAT_MODE_PLAIN_UDP;
        break;
    case HIP_MSG_SET_NAT_NONE:
        nat = HIP_NAT_MODE_NONE;
        break;
    default:
        err = -1;
        HIP_OUT_ERR(-1, "Unknown nat mode %d\n", nat_mode);
    }
    HIP_IFEL(hip_for_each_ha(hip_ha_set_nat_mode, &nat), 0,
             "Error from for_each_ha().\n");
    //set the nat mode for the host
    hip_nat_status = nat;


    HIP_DEBUG("hip_user_nat_mode() end. mode: %d\n", hip_nat_status);

out_err:
    return err;
}

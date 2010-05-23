/** @file
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
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-02.txt">
 *          draft-schmitt-hip-nat-traversal-02</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    All Doxygen comments have been added in version 1.1.
 */

#include "nat.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "user.h"
#include "lib/core/debug.h"


/** A transmission function set for NAT traversal. */
/** File descriptor of socket used for hip control packet NAT traversal on
 *  UDP/IPv4. Defined in hipd.c */
/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. Defined in hipd.c */

static int hip_ha_set_nat_mode(hip_ha_t *entry, void *mode);

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

    HIP_DEBUG("Sending Keep-Alives to NAT.\n");
    HIP_IFEL(hip_for_each_ha(hip_nat_send_keep_alive, NULL),
             -1, "for_each_ha() err.\n");

out_err:
    return err;
}

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
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero on success, or negative error value on error.
 * @note           If the state of @c entry is not ESTABLISHED or if
 *                 @c entry->nat_mode = 0 this function still returns zero
 *                 because these conditions are not errors. Negative error
 *                 value is only returned when the creation of the new UPDATE
 *                 message fails in some way.
 */
int hip_nat_send_keep_alive(hip_ha_t *entry, void *not_used)
{
    int err                = 0;
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


    entry->hadb_misc_func->
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
    entry->hadb_xmit_func->
    hip_send_pkt(&entry->our_addr, &entry->peer_addr,
                 entry->local_udp_port, entry->peer_udp_port, msg,
                 entry, 0);

out_err:
    if (msg) {
        free(msg);
    }

    return err;
}

/**
 * get the NAT mode for a host association
 *
 *
 * Similar to hip_ha_set, but skip the setting when RVS mode is on, this
 * function is for ICE code
 *
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @return         the value of the NAT mode.
 */
hip_transform_suite_t hip_nat_get_control(hip_ha_t *entry)
{
    return hip_get_nat_mode(entry);
}

/**
 * Set the NAT mode for a host association
 *
 *
 * Similar to hip_ha_set_nat_mode, but skip the setting when RVS mode is on, this
 * function is for ICE code
 *
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param mode     a integer for NAT mode.
 * @return         zero on success.
 */
hip_transform_suite_t hip_nat_set_control(hip_ha_t *entry, hip_transform_suite_t mode)
{
    hip_ha_set_nat_mode(entry, &mode);

    return 0;
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
        HIP_IFEL(1, -1, "Unknown nat mode %d\n", nat_mode);
    }
    HIP_IFEL(hip_for_each_ha(hip_ha_set_nat_mode, (void *) &nat), 0,
             "Error from for_each_ha().\n");
    //set the nat mode for the host
    hip_nat_status = nat;


    HIP_DEBUG("hip_user_nat_mode() end. mode: %d\n", hip_nat_status);

out_err:
    return err;
}

/**
 * Get HIP NAT status.
 * TODO doxygen header
 */
hip_transform_suite_t hip_get_nat_mode(hip_ha_t *entry)
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
static int hip_ha_set_nat_mode(hip_ha_t *entry, void *mode)
{
    int err = 0;
    if (entry && mode != HIP_NAT_MODE_NONE) {
        hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
        entry->nat_mode = *((hip_transform_suite_t *) mode);
        HIP_DEBUG("NAT status of host association %p: %d\n",
                  entry, entry->nat_mode);
    }
    return err;
}

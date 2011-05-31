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
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP)
 *
 * @author Baris Boyvat <baris#boyvat.com>
 * @author Rene Hummen
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "hipd/cookie.h"
#include "hipd/hadb.h"
#include "hipd/hidb.h"
#include "hipd/hipd.h"
#include "hipd/input.h"
#include "hipd/maintenance.h"
#include "hipd/netdev.h"
#include "hipd/nsupdate.h"
#include "hipd/output.h"
#include "hipd/pkt_handling.h"
#include "hipd/user.h"
#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/modularization.h"
#include "lib/core/prefix.h"
#include "lib/core/state.h"
#include "lib/core/performance.h"
#include "update_builder.h"
#include "update_locator.h"
#include "update_param_handling.h"
#include "update.h"

/**
 * Prepare the creation of a new UPDATE packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *             the packet handling (received message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database).
 *
 * @return always returns zero
 */
static int hip_prepare_update_response(UNUSED const uint8_t packet_type,
                                       UNUSED const uint32_t ha_state,
                                       struct hip_packet_context *ctx)
{
    hip_msg_init(ctx->output_msg);

    hip_build_network_hdr(ctx->output_msg,
                          HIP_UPDATE,
                          0,
                          &ctx->hadb_entry->hit_our,
                          &ctx->hadb_entry->hit_peer);

    return 0;
}

/**
 * Choose a sensible source address for an UPDATE packet with LOCATOR
 *
 * @param ha the related host association
 * @param src_addr currently unused
 * @param dst_addr the destination address
 * @param new_src_addr the chosen source address
 * @return zero on success or negative on failure
 */
static int hip_select_local_addr_for_first_update(const struct hip_hadb_state *const ha,
                                                  const struct in6_addr *const src_addr,
                                                  const struct in6_addr *const dst_addr,
                                                  struct in6_addr *const new_src_addr)
{
    int                     err = 0, c;
    struct sockaddr_storage ss;
    struct netdev_address  *na  = NULL;
    LHASH_NODE             *n   = NULL, *t = NULL;
    const struct in6_addr  *in6 = NULL;

    if (IN6_IS_ADDR_V4MAPPED(&ha->our_addr)) {
        ss.ss_family = AF_INET;
        IPV6_TO_IPV4_MAP(&ha->our_addr, &(((struct sockaddr_in *) &ss)->sin_addr));
    } else {
        ss.ss_family = AF_INET6;
        ipv6_addr_copy(&((struct sockaddr_in6 *) &ss)->sin6_addr, &ha->our_addr);
    }

    /* Ask a route from the kernel first */
    if (hip_select_source_address(new_src_addr, dst_addr) == 0) {
        HIP_DEBUG("Using default route address\n");
        goto out_err;
    }

    /* Use previous hadb source address if it still exists */
    if (hip_exists_address_in_list((struct sockaddr *) &ss, -1) &&
        are_addresses_compatible(&ha->our_addr, dst_addr)) {
        HIP_DEBUG("Reusing hadb old source address\n");
        ipv6_addr_copy(new_src_addr, &ha->our_addr);
        goto out_err;
    }

    /* Last resort: use any address from the local list */
    list_for_each_safe(n, t, addresses, c) {
        na  = list_entry(n);
        in6 = hip_cast_sa_addr((struct sockaddr *) &na->addr);
        if (are_addresses_compatible(in6, dst_addr)) {
            HIP_DEBUG("Reusing a local address from the list\n");
            ipv6_addr_copy(new_src_addr, in6);
            goto out_err;
        }
    }

    HIP_ERROR("Failed to find source address\n");
    err = -1;

out_err:

    if (err == 0) {
        HIP_DEBUG_IN6ADDR("selected source address", src_addr);
    }

    return err;
}

/**
 * Check if UPDATE sequence and acknowledgment numbers are as expected.
 *
 * @param packet_type the packet type
 * @param ha_state the HA state
 * @param ctx the packet context
 * @return zero on success or negative on failure
 */
static int hip_check_update_freshness(UNUSED const uint8_t packet_type,
                                      UNUSED const uint32_t ha_state,
                                      struct hip_packet_context *ctx)
{
    struct update_state  *localstate         = NULL;
    const struct hip_seq *seq                = NULL;
    const struct hip_ack *ack                = NULL;
    uint32_t              seq_update_id      = 0;
    uint32_t              ack_peer_update_id = 0;
    int                   err                = 0;

    /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
     * the implementation MAY reply with an ICMP Parameter Problem. */
    HIP_IFEL(!ctx->hadb_entry,
             -1,
             "No host association database entry found.\n");

    HIP_IFEL(!(localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                                "update")),
             -1,
             "failed to look up UPDATE-specific state\n");

    /* RFC 5201 Section 6.12: Receiving UPDATE Packets */
    HIP_DEBUG("previous incoming update id=%u\n", localstate->update_id_in);
    HIP_DEBUG("previous outgoing update id=%u\n",
              hip_update_get_out_id(localstate));

    // check freshness of seq, if available
    seq = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ);
    if (seq) {
        seq_update_id = ntohl(seq->update_id);
        HIP_DEBUG("SEQ parameter found with Update ID %u.\n", seq_update_id);

        // old updates are bad updates (may be replayed)
        if (localstate->update_id_in != 0 &&
            seq_update_id < localstate->update_id_in) {
            HIP_DEBUG("Update ID (%u) in the SEQ parameter is before "
                      "previous Update ID (%u). Dropping the packet.\n",
                      seq_update_id,
                      localstate->update_id_in);
            err = -1;
            goto out_err;
        }
    }

    // check freshness of ack, if available
    ack = hip_get_param(ctx->input_msg, HIP_PARAM_ACK);
    if (ack) {
        ack_peer_update_id = ntohl(ack->peer_update_id);
        HIP_DEBUG("ACK parameter found with peer Update ID %u.\n",
                  ack_peer_update_id);

        // we only want acks for our most current update
        if (ack_peer_update_id != hip_update_get_out_id(localstate)) {
            HIP_DEBUG("Update ID (%u) in the ACK parameter is not "
                      "equal to the last outgoing Update ID (%u). "
                      "Dropping the packet.\n",
                      ack_peer_update_id,
                      hip_update_get_out_id(localstate));
            err = -1;
            goto out_err;
        }
    }

out_err:
    ctx->error = err;
    return err;
}

/**
 * Check a received UPDATE packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *            the packet handling (received message, source and destination
 *            address, the ports and the corresponding entry from the host
 *            association database).
 *
 * @return zero on success, non-negative on error.
 */
static int hip_check_update_packet(UNUSED const uint8_t packet_type,
                                   UNUSED const uint32_t ha_state,
                                   struct hip_packet_context *ctx)
{
    int err = 0;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_UPDATE\n");
    hip_perf_start_benchmark(perf_set, PERF_UPDATE);
#endif

    /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
     * the implementation MAY reply with an ICMP Parameter Problem. */
    HIP_IFEL(!ctx->hadb_entry, -1, "No host association database entry found.\n");

    /* The HMAC parameter covers the same parts of a packet as the PK signature.
     * Therefore, we can omit the signature check at the end-host. */
    HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                    &ctx->hadb_entry->hip_hmac_in),
             -1,
             "HMAC validation on UPDATE failed.\n");

out_err:
    ctx->error = err;
    return err;
}

/**
 * Send an UPDATE packet depending on the update type.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *            the packet handling (received message, source and destination
 *            address, the ports and the corresponding entry from the host
 *            association database).
 *
 * @return zero on success, or negative error value on error.
 */
static int hip_send_update_packet(UNUSED const uint8_t packet_type,
                                  UNUSED const uint32_t ha_state,
                                  struct hip_packet_context *ctx)
{
    int                  err        = 0;
    struct in6_addr     *dst_addr   = NULL;
    struct update_state *localstate = NULL;

    switch (hip_classify_update_type(ctx->input_msg)) {
    case FIRST_UPDATE_PACKET:
        // send challenge to all advertised locators
        localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "update");

        for (unsigned i = 0; i < localstate->valid_locators; i++) {
            dst_addr = &localstate->addresses_to_send_echo_request[i];

            if (!are_addresses_compatible(&ctx->dst_addr, dst_addr)) {
                continue;
            }

            HIP_DEBUG_IN6ADDR("Sending echo requests from", &ctx->dst_addr);
            HIP_DEBUG_IN6ADDR("to", dst_addr);

            err = hip_send_pkt(&ctx->dst_addr,
                               dst_addr,
                               (ctx->hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                               ctx->hadb_entry->peer_udp_port,
                               ctx->output_msg,
                               ctx->hadb_entry,
                               1);
        }
        break;
    case THIRD_UPDATE_PACKET:
        // mobility update is concluded after 3rd packet has been received
        break;
    default:
        // send a response to default peer IP
        err = hip_send_pkt(&ctx->hadb_entry->our_addr,
                           &ctx->hadb_entry->peer_addr,
                           (ctx->hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                           ctx->hadb_entry->peer_udp_port,
                           ctx->output_msg,
                           ctx->hadb_entry,
                           1);
    }

    return err;
}

/**
 * publish the locator set of the local host to all peers
 *
 * @return zero on success or negative on failure
 */
static int hip_trigger_update_for_all_peers(void)
{
    int                    err  = 0, i = 0;
    struct hip_hadb_state *ha   = NULL;
    LHASH_NODE            *item = NULL, *tmp = NULL;

    // Go through all the peers and send update packets
    list_for_each_safe(item, tmp, hadb_hit, i) {
        ha = list_entry(item);

        if (ha->hastate == HIP_HASTATE_VALID &&
            ha->state == HIP_STATE_ESTABLISHED) {
            err = hip_trigger_update(ha);
            if (err) {
                break;
            }
        }
    }

    /* Update DNS data in hit-to-ip domain name. This is done after
     * sending UPDATE packets. See the discussion for the reasoning:
     * http://www.freelists.org/post/hipl-users/HIP-UPDATE-select-error-Interrupted-system-call,2 */
    if (hip_get_nsupdate_status()) {
        nsupdate(0);
    }

    if (hip_locator_status == HIP_MSG_SET_LOCATOR_ON) {
        hip_recreate_all_precreated_r1_packets();
    }

    return err;
}

/**
 * Update the port and IP address information.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *             the packet handling (received message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database).
 *
 * @return zero on success, or negative error value on error.
 */
static int hip_set_active_addresses(UNUSED const uint8_t packet_type,
                                    UNUSED const uint32_t ha_state,
                                    struct hip_packet_context *ctx)
{
    const enum update_types update_type = hip_classify_update_type(ctx->input_msg);

    // don't update IPsec SAs and SPs for 1st UPDATE packet
    if (update_type == SECOND_UPDATE_PACKET ||
        update_type == THIRD_UPDATE_PACKET) {
        /* set local UDP port just in case the original communications
         * changed from raw to UDP or vice versa */
        ctx->hadb_entry->local_udp_port = ctx->msg_ports.dst_port;
        /* @todo: a workaround for bug id 592200 */
        ctx->hadb_entry->peer_udp_port = ctx->msg_ports.src_port;

        ctx->hadb_entry->our_addr  = ctx->dst_addr;
        ctx->hadb_entry->peer_addr = ctx->src_addr;
    }

    return 0;
}

/**
 * Update the IPsec security associations of the current connection.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *            the packet handling (received message, source and destination
 *            address, the ports and the corresponding entry from the host
 *            association database).
 *
 * @return zero on success, or negative error value on error.
 */
static int hip_update_ipsec_sa(UNUSED const uint8_t packet_type,
                               UNUSED const uint32_t ha_state,
                               struct hip_packet_context *ctx)
{
    enum update_types update_type = UNKNOWN_UPDATE_PACKET;

    update_type = hip_classify_update_type(ctx->input_msg);

    // don't update IPsec SAs and SPs for 1st UPDATE packet
    if (update_type == SECOND_UPDATE_PACKET ||
        update_type == THIRD_UPDATE_PACKET) {
        if (hip_create_or_update_security_associations_and_sp(ctx->hadb_entry,
                                                              &ctx->src_addr,
                                                              &ctx->dst_addr)) {
            HIP_ERROR("Failed to update IPsec SAs and SPs\n");
            return -1;
        }
    }

    return 0;
}

/**
 * Check if update should be sent.
 *
 * @return 0 on success, else negative value
 */
static int hip_update_maintenance(void)
{
    int err = 0;

    if (address_change_time_counter == 0) {
        address_change_time_counter = -1;

        HIP_DEBUG("Triggering UPDATE\n");
        err = hip_trigger_update_for_all_peers();

        if (err) {
            HIP_ERROR("Error sending UPDATE\n");
        }
    } else if (address_change_time_counter > 0) {
        HIP_DEBUG("Delay mobility triggering (count %d)\n",
                  address_change_time_counter - 1);
        address_change_time_counter--;
    }

    return err;
}

/**
 * Initialize an update_state instance.
 *
 * Allocates the required memory and sets the members to the start values.
 *
 * @note The allocated memory is free'd with hip_update_uninit_state(). The
 *       item_name parameter used for registering or getting this update_state
 *       instance must be the same in both functions. In this case it is "update".
 *
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
static int hip_update_init_state(struct modular_state *state)
{
    struct update_state *update_state = NULL;

    if (!(update_state = malloc(sizeof(struct update_state)))) {
        HIP_ERROR("Error on allocating memory for a update state instance.\n");
        return -1;
    }

    update_state->update_state   = 0;
    update_state->valid_locators = 0;
    update_state->update_id_out  = 0;
    update_state->update_id_in   = 0;

    return lmod_add_state_item(state, update_state, "update");
}

/**
 * Free memory that was allocated in the update_state instance.
 *
 * @note The item_name parameter for the lmod_get_state_item() call has to be
 *       the same as the one it was registered with in hip_update_init_state().
 *       In this case it is "update".
 *
 * @param state Pointer to the modular state data structure.
 *
 * @return Success =  0
 *         Error   = -1
 */
static void hip_update_uninit_state(struct modular_state *const state)
{
    struct update_state *update_state = NULL;

    update_state = lmod_get_state_item(state, "update");
    if (update_state != NULL) {
        update_state->valid_locators = 0;
    }
}

/**
 * Transition the connection state based on a successful update.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *             the packet handling (received message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database).
 *
 * @return zero on success, or negative error value on error.
 */
static int hip_update_change_state(UNUSED const uint8_t packet_type,
                                   UNUSED const uint32_t ha_state,
                                   struct hip_packet_context *ctx)
{
    /* RFC 5201 Section 4.4.2, Table 5: According to the state processes
     * listed, the state is moved from R2_SENT to ESTABLISHED if an
     * UPDATE packet is received */
    if (ctx->hadb_entry->state == HIP_STATE_R2_SENT) {
        HIP_DEBUG("Received UPDATE in state %s, moving to ESTABLISHED.\n",
                  hip_state_str(ctx->hadb_entry->state));
        ctx->hadb_entry->state = HIP_STATE_ESTABLISHED;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_UPDATE\n");
    hip_perf_stop_benchmark(perf_set, PERF_UPDATE);
    hip_perf_write_benchmark(perf_set, PERF_UPDATE);
#endif

    return 0;
}

/**
 * Thin wrapper function around hip_send_locators_to_all_peers. Needed for
 * registration as user message handle function.
 *
 * @param msg unused, needed due to type check of handle functions
 * @param src unused, needed due to type check of handle functions
 *
 * @return zero on success or negative on failure
 */
static int hip_update_manual_update(UNUSED struct hip_common *msg,
                                    UNUSED struct sockaddr_in6 *src)
{
    HIP_DEBUG("Manual UPDATE triggered.\n");
    return hip_trigger_update_for_all_peers();
}

/**
 * Getter for the sequence number value.
 *
 * @note RFC 5201 Section 5.2.13:
 *       Notice that the section says 'The Update ID is an unsigned quantity,
 *       initialized by a host to zero upon moving to ESTABLISHED state' and
 *       'The Update ID is incremented by one before each new UPDATE that is
 *       sent by the host; the first UPDATE packet originated by a host has
 *       an Update ID of 0'. Therefore we initialize the Update ID with 0 and
 *       increment this value before a new UPDATE packet is sent. Because the
 *       first UPDATE packet should contain 0 as value, we need to decrement
 *       the packet value by one for each UPDATE packet.
 *
 * @param state    Pointer to the update state.
 *
 * @return The next UPDATE out ID if state is set, -1 on error
 */
uint32_t hip_update_get_out_id(const struct update_state *const state)
{
    if (state) {
        return state->update_id_out - 1;
    } else {
        return -1;
    }
}

/**
 * Classify an UPDATE packet by means of contained parameters.
 *
 * @param hip_msg The update message to be classified.
 * @return member of enum update_types
 */
enum update_types hip_classify_update_type(const struct hip_common *const hip_msg)
{
    const struct hip_esp_info      *esp_info      = NULL;
    const struct hip_locator       *locator       = NULL;
    const struct hip_seq           *seq           = NULL;
    const struct hip_ack           *ack           = NULL;
    const struct hip_echo_request  *echo_request  = NULL;
    const struct hip_echo_response *echo_response = NULL;

    /* RFC 5206: End-Host Mobility and Multihoming.
     * Mandatory parameters from 3.2.1. Mobility with a Single SA Pair
     * (No Rekeying) */
    esp_info      = hip_get_param(hip_msg, HIP_PARAM_ESP_INFO);
    locator       = hip_get_param(hip_msg, HIP_PARAM_LOCATOR);
    seq           = hip_get_param(hip_msg, HIP_PARAM_SEQ);
    ack           = hip_get_param(hip_msg, HIP_PARAM_ACK);
    echo_request  = hip_get_param(hip_msg, HIP_PARAM_ECHO_REQUEST_SIGN);
    echo_response = hip_get_param(hip_msg, HIP_PARAM_ECHO_RESPONSE_SIGN);

    if (esp_info && locator && seq) {
        return FIRST_UPDATE_PACKET;
    } else if (esp_info && seq && ack && echo_request) {
        return SECOND_UPDATE_PACKET;
    } else if (ack && echo_response) {
        return THIRD_UPDATE_PACKET;
    } else {
        return UNKNOWN_UPDATE_PACKET;
    }
}

/**
 * Trigger the update for a specific connection.
 *
 * @param hadb_entry    the association state of the connection to be updated
 * @return 0 on success, negative value in case of an error
 */
int hip_trigger_update(struct hip_hadb_state *const hadb_entry)
{
    struct hip_common                 *locator_update_packet = NULL;
    struct hip_common                 *locator_msg           = NULL;
    struct hip_locator_info_addr_item *locators              = NULL;
    struct update_state               *localstate            = NULL;
    struct in6_addr                    local_addr;
    int                                err        = 0;
    const int                          retransmit = 1;

    localstate = lmod_get_state_item(hadb_entry->hip_modular_state, "update");

    HIP_IFEL(!(locator_update_packet = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the update packet\n");

    hip_build_network_hdr(locator_update_packet,
                          HIP_UPDATE,
                          0,
                          &hadb_entry->hit_our,
                          &hadb_entry->hit_peer);

    HIP_IFEL(hip_build_param_esp_info(locator_update_packet,
                                      hadb_entry->current_keymat_index,
                                      hadb_entry->spi_inbound_current,
                                      hadb_entry->spi_inbound_current),
             -1, "Building of ESP_INFO param failed\n");

    HIP_IFEL(!(locator_msg = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the packet\n");
    HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

    HIP_IFEL(hip_build_param_locator(locator_update_packet,
                                     locators,
                                     address_count),
             -1, "failed to build locator parameter\n");

    localstate->update_id_out++;
    HIP_DEBUG("outgoing UPDATE ID=%u\n", hip_update_get_out_id(localstate));
    HIP_IFEL(hip_build_param_seq(locator_update_packet,
                                 hip_update_get_out_id(localstate)),
             -1, "Building of SEQ parameter failed\n");

    hip_mac_and_sign_packet(locator_update_packet, hadb_entry);

    HIP_IFEL(hip_select_local_addr_for_first_update(hadb_entry,
                                                    &hadb_entry->our_addr,
                                                    &hadb_entry->peer_addr,
                                                    &local_addr),
             -1, "No source address found for first update\n");
    HIP_DEBUG_IN6ADDR("Sending update from", &local_addr);
    HIP_DEBUG_IN6ADDR("to", &hadb_entry->peer_addr);

    err = hip_send_pkt(&local_addr,
                       &hadb_entry->peer_addr,
                       (hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       hadb_entry->peer_udp_port,
                       locator_update_packet,
                       hadb_entry,
                       retransmit);

out_err:
    free(locator_update_packet);
    free(locator_msg);
    return err;
}

/**
 * Initialization function for update module.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_update_init(void)
{
    int err = 0;

    HIP_IFEL(lmod_register_state_init_function(&hip_update_init_state),
             -1,
             "Error on registering update state init function.\n");

    HIP_IFEL(lmod_register_state_uninit_function(&hip_update_uninit_state),
             -1,
             "Error on registering update state uninit function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_I1_SENT,
                                          &hip_handle_locator, 31500),
             -1, "Error on registering LOCATOR handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_I2_SENT,
                                          &hip_handle_locator, 31500),
             -1, "Error on registering LOCATOR handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_CLOSING,
                                          &hip_handle_locator, 31500),
             -1, "Error on registering LOCATOR handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_CLOSED,
                                          &hip_handle_locator, 31500),
             -1, "Error on registering LOCATOR handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_check_update_freshness,
                                          20000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_check_update_packet,
                                          20100),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_prepare_update_response,
                                          20200),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_add_esp_info_param,
                                          20300),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_handle_esp_info_param,
                                          20400),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_handle_locator_parameter,
                                          20500),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_add_seq_param,
                                          20600),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_handle_seq_param,
                                          20700),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_add_echo_request_param,
                                          20800),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_handle_echo_request_param,
                                          20900),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_mac_and_sign_handler,
                                          29900),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_send_update_packet,
                                          30000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_update_ipsec_sa,
                                          30500),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_set_active_addresses,
                                          31000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_update_change_state,
                                          40000),
             -1, "Error on registering UPDATE handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_check_update_freshness,
                                          20000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_check_update_packet,
                                          20100),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_prepare_update_response,
                                          20200),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_add_esp_info_param,
                                          20300),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_handle_esp_info_param,
                                          20400),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_handle_locator_parameter,
                                          20500),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_add_seq_param,
                                          20600),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_handle_seq_param,
                                          20700),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_add_echo_request_param,
                                          20800),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_handle_echo_request_param,
                                          20900),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_mac_and_sign_handler,
                                          29900),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_send_update_packet,
                                          30000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_update_ipsec_sa,
                                          30500),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_set_active_addresses,
                                          31000),
             -1, "Error on registering UPDATE handle function.\n");

    HIP_IFEL(hip_user_register_handle(HIP_MSG_MANUAL_UPDATE_PACKET,
                                      &hip_update_manual_update,
                                      20000),
             -1, "Error on registering UPDATE user message handle function.\n");

/* FIXME: Implement handle function for HIP_MSG_LOCATOR_GET to replace this. */
#if 0
case HIP_MSG_LOCATOR_GET:
    HIP_DEBUG("Got a request for locators\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_LOCATOR_GET, 0), -1,
             "Failed to build user message header.: %s\n",
             strerror(err));
    if ((err = hip_build_locators_old(msg, 0)) < 0) {
        HIP_DEBUG("LOCATOR parameter building failed\n");
    }

#endif

    HIP_IFEL(hip_register_maint_function(&hip_update_maintenance, 40000),
             -1,
             "Error on registering UPDATE maintenance function.\n");

out_err:
    return err;
}

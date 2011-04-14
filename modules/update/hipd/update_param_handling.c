/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University.
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
 * This file implements parameter handling functionality specific to
 * UPDATE packets for the Host Identity Protocol (HIP)
 *
 * @author  Rene Hummen
 */

#include <string.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "update_locator.h"
#include "update_param_handling.h"


/**
 * Removes all the addresses from the addresses_to_send_echo_request list
 * and deallocates them.
 * @param state pointer to a host association
 */
static void hip_remove_addresses_to_send_echo_request(struct update_state *state)
{
    int              i       = 0;
    LHASH_NODE      *item    = NULL, *tmp = NULL;
    struct in6_addr *address = NULL;

    list_for_each_safe(item, tmp, state->addresses_to_send_echo_request, i) {
        address = list_entry(item);
        list_del(address, state->addresses_to_send_echo_request);
        free(address);
    }
}

/**
 * Print all IP addresses where an update packet should be sent to.
 *
 * @param ha    pointer to a host association
 */
static void hip_print_addresses_to_send_update_request(struct hip_hadb_state *ha)
{
    int                  i          = 0;
    LHASH_NODE          *item       = NULL, *tmp = NULL;
    struct in6_addr     *address    = NULL;
    struct update_state *localstate = NULL;

    localstate = lmod_get_state_item(ha->hip_modular_state, "update");

    HIP_DEBUG("Addresses to send update:\n");
    list_for_each_safe(item, tmp, localstate->addresses_to_send_echo_request, i) {
        address = list_entry(item);
        HIP_DEBUG_IN6ADDR("", address);
    }
}

/**
 * process a LOCATOR paramter
 *
 * @param ha the related host association
 * @param src_addr the source address where the locator arrived from
 * @param locator the LOCATOR parameter
 * @return zero on success or negative on failure
 */
int hip_handle_locator_parameter(struct hip_hadb_state *ha,
                                 const struct in6_addr *src_addr,
                                 struct hip_locator *locator)
{
    int                                err                  = 0;
    int                                locator_addr_count   = 0;
    int                                i                    = 0;
    int                                src_addr_included    = 0;
    union hip_locator_info_addr       *locator_info_addr    = NULL;
    struct hip_locator_info_addr_item *locator_address_item = NULL;
    struct in6_addr                   *peer_addr            = 0;
    struct update_state               *localstate           = NULL;

    HIP_IFEL(!locator, -1, "locator is NULL");

    locator_addr_count = hip_get_locator_addr_item_count(locator);

    HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
              locator_addr_count, hip_get_param_total_len(locator));

    // Empty the addresses_to_send_echo_request list before adding the
    // new addresses
    localstate = lmod_get_state_item(ha->hip_modular_state, "update");
    HIP_DEBUG("hip_get_state_item returned localstate: %p\n", localstate);
    hip_remove_addresses_to_send_echo_request(localstate);

    locator_address_item =  (struct hip_locator_info_addr_item *) (locator + 1);
    for (i = 0; i < locator_addr_count; i++) {
        locator_info_addr = hip_get_locator_item(locator_address_item, i);

        peer_addr = malloc(sizeof(struct in6_addr));
        if (!peer_addr) {
            HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
            return -1;
        }

        ipv6_addr_copy(peer_addr, hip_get_locator_item_address(locator_info_addr));

        list_add(peer_addr, localstate->addresses_to_send_echo_request);

        HIP_DEBUG_IN6ADDR("Comparing", src_addr);
        HIP_DEBUG_IN6ADDR("to ", peer_addr);

        if (ipv6_addr_cmp(src_addr, peer_addr) == 0) {
            src_addr_included = 1;
        }
    }

    if (!src_addr_included) {
        HIP_DEBUG("Preferred address was not in locator (NAT?)\n");

        peer_addr = malloc(sizeof(struct in6_addr));
        if (!peer_addr) {
            HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
            return -1;
        }

        ipv6_addr_copy(peer_addr, src_addr);
        list_add(peer_addr, localstate->addresses_to_send_echo_request);
    }

    hip_print_addresses_to_send_update_request(ha);

out_err:
    return err;
}

/**
 * This function stores the LOCATOR parameter into the hadb entry
 * of a connection in question. The whole LOCATOR is stored and
 * handled later as the LOCATOR is received before the connection
 * state has reached ESTABLISHED (UPDATEs are not allowed before
 * the state is ESTABLISHED) and the address verification is
 * handled later during the BEX (after receiving the R2).
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
int hip_handle_locator(UNUSED const uint8_t packet_type,
                       UNUSED const uint32_t ha_state,
                       struct hip_packet_context *ctx)
{
    const struct hip_locator *locator = NULL;
    int                       n_addrs = 0, loc_size = 0, err = 0;

    locator = hip_get_param(ctx->input_msg, HIP_PARAM_LOCATOR);
    if (locator) {
        n_addrs  = hip_get_locator_addr_item_count(locator);
        loc_size = sizeof(struct hip_locator) +
                   (n_addrs * sizeof(struct hip_locator_info_addr_item));
        HIP_IFEL(!(ctx->hadb_entry->locator = malloc(loc_size)),
                 -1, "Malloc for entry->locators failed\n");
        memcpy(ctx->hadb_entry->locator, locator, loc_size);
    } else {
        HIP_DEBUG("R1 did not have locator\n");
    }

out_err:
    return err;
}

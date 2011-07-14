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

#include <stdbool.h>
#include <openssl/rand.h>
#include <string.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "update_builder.h"
#include "update_locator.h"
#include "update_param_handling.h"


/**
 * Add an address to the addresses_to_send_echo_request container.
 *
 * @param state points to the update_state object to manipulate.
 * @param addr the address to add to @a state as a locator.
 * @return true if the address has been added successfully, false otherwise.
 */
static bool hip_add_address_to_send_echo_request(struct update_state *const state,
                                                 const struct in6_addr addr)
{
    if (state->valid_locators < ARRAY_SIZE(state->addresses_to_send_echo_request)) {
        state->addresses_to_send_echo_request[state->valid_locators] = addr;
        state->valid_locators++;
        return true;
    } else {
        return false;
    }
}

/**
 * Removes all addresses from the addresses_to_send_echo_request container.
 *
 * @param state pointer to a host association
 */
static void hip_remove_addresses_to_send_echo_request(struct update_state *const state)
{
    state->valid_locators = 0;
}

/**
 * Print all IP addresses where an update packet should be sent to.
 *
 * @param ha    pointer to a host association
 */
static void hip_print_addresses_to_send_update_request(const struct hip_hadb_state *const ha)
{
    const struct update_state *const localstate = lmod_get_state_item(ha->hip_modular_state, "update");

    HIP_DEBUG("Addresses to send update:\n");
    for (unsigned i = 0; i < localstate->valid_locators; i++) {
        HIP_DEBUG_IN6ADDR("", &localstate->addresses_to_send_echo_request[i]);
    }
}

/**
 * Add ESP_INFO parameter to second update packet.
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
int hip_add_esp_info_param(UNUSED const uint8_t packet_type,
                           UNUSED const uint32_t ha_state,
                           struct hip_packet_context *ctx)
{
    if (hip_classify_update_type(ctx->input_msg) == FIRST_UPDATE_PACKET) {
        if (hip_build_param_esp_info(ctx->output_msg,
                                     ctx->hadb_entry->current_keymat_index,
                                     ctx->hadb_entry->spi_inbound_current,
                                     ctx->hadb_entry->spi_inbound_current)) {
            HIP_ERROR("Building of ESP_INFO param failed\n");
            return -1;
        }
    }

    return 0;
}

/**
 * Handle ESP_INFO parameter in first and second update packet.
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
int hip_handle_esp_info_param(UNUSED const uint8_t packet_type,
                              UNUSED const uint32_t ha_state,
                              struct hip_packet_context *ctx)
{
    const struct hip_esp_info *esp_info    = NULL;
    const enum update_types    update_type = hip_classify_update_type(ctx->input_msg);

    if (update_type == FIRST_UPDATE_PACKET ||
        update_type == SECOND_UPDATE_PACKET) {
        if (!(esp_info = hip_get_param(ctx->input_msg, HIP_PARAM_ESP_INFO))) {
            HIP_ERROR("No ESP_INFO parameter found\n");
            return -1;
        }

        // set the new spi value for the association
        // TODO add rekeying functionality here
        ctx->hadb_entry->spi_outbound_new = ntohl(esp_info->new_spi);
    }

    return 0;
}

/**
 * Add SEQ parameter to second update packet.
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
int hip_add_seq_param(UNUSED const uint8_t packet_type,
                      UNUSED const uint32_t ha_state,
                      struct hip_packet_context *ctx)
{
    struct update_state *localstate = NULL;
    int                  err        = 0;

    if (hip_classify_update_type(ctx->input_msg) == FIRST_UPDATE_PACKET) {
        HIP_IFEL(!(localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                                    "update")),
                 -1, "failed to look up update state\n");
        localstate->update_id_out++;
        HIP_DEBUG("outgoing UPDATE ID=%u\n", hip_update_get_out_id(localstate));
        HIP_IFEL(hip_build_param_seq(ctx->output_msg,
                                     hip_update_get_out_id(localstate)),
                 -1,
                 "Building of SEQ parameter failed\n");
    }

out_err:
    return err;
}

/**
 * Handle SEQ parameter in first and second update packet.
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
int hip_handle_seq_param(UNUSED const uint8_t packet_type,
                         UNUSED const uint32_t ha_state,
                         struct hip_packet_context *ctx)
{
    const struct hip_seq   *seq         = NULL;
    const enum update_types update_type = hip_classify_update_type(ctx->input_msg);
    struct update_state    *localstate  = NULL;
    int                     err         = 0;

    if (update_type == FIRST_UPDATE_PACKET ||
        update_type == SECOND_UPDATE_PACKET) {
        HIP_IFEL(!(seq = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ)),
                 -1, "SEQ parameter not found\n");

        HIP_IFEL(!(localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                                    "update")),
                 -1, "failed to look up update state\n");

        // progress update sequence to currently processed update
        if (localstate->update_id_in < ntohl(seq->update_id)) {
            localstate->update_id_in = ntohl(seq->update_id);
        }

        HIP_IFEL(hip_build_param_ack(ctx->output_msg, ntohl(seq->update_id)),
                 -1, "Building of ACK parameter failed\n");
    }

out_err:
    return err;
}

/**
 * Add ECHO_REQUEST parameter to second update packet.
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
int hip_add_echo_request_param(UNUSED const uint8_t packet_type,
                               UNUSED const uint32_t ha_state,
                               struct hip_packet_context *ctx)
{
    int err = 0;

    if (hip_classify_update_type(ctx->input_msg) == FIRST_UPDATE_PACKET) {
        // Randomize the echo response opaque data before sending ECHO_REQUESTS.
        // Notice that we're using the same opaque value for the identical
        // UPDATE packets sent between different address combinations.
        RAND_bytes(ctx->hadb_entry->echo_data,
                   sizeof(ctx->hadb_entry->echo_data));

        HIP_HEXDUMP("ECHO_REQUEST in the host association",
                    ctx->hadb_entry->echo_data,
                    sizeof(ctx->hadb_entry->echo_data));
        if (hip_build_param_echo(ctx->output_msg,
                                 ctx->hadb_entry->echo_data,
                                 sizeof(ctx->hadb_entry->echo_data),
                                 1, 1)) {
            HIP_ERROR("Building of ECHO_REQUEST failed\n");
            return -1;
        }
    }

    return err;
}

/**
 * Handle ECHO_REQUEST_SIGNED parameter.
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
int hip_handle_echo_request_sign_param(UNUSED const uint8_t packet_type,
                                       UNUSED const uint32_t ha_state,
                                       struct hip_packet_context *ctx)
{
    const struct hip_echo_request *echo_request = NULL;
    int                            err          = 0;

    if (!(echo_request = hip_get_param(ctx->input_msg,
                                       HIP_PARAM_ECHO_REQUEST_SIGN))) {
        HIP_DEBUG("no ECHO_REQUEST_SIGN parameter in UPDATE packet, skipping\n");

        /* This condition is no error! There simply was no request by the peer
         * to add a ECHO_RESPONSE_SIGN parameter to the outbound message. */
        return 0;
    }

    HIP_DEBUG("echo opaque data len=%d\n",
              hip_get_param_contents_len(echo_request));
    HIP_HEXDUMP("ECHO_REQUEST_SIGN ",
                (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                hip_get_param_contents_len(echo_request));
    HIP_IFEL(hip_build_param_echo(ctx->output_msg,
                                  (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_len(echo_request), 1, 0),
             -1, "Building of ECHO_RESPONSE_SIGN failed\n");

out_err:
    return err;
}

/**
 * Handle ECHO_REQUEST_UNSIGNED parameter.
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
int hip_handle_echo_request_param(UNUSED const uint8_t packet_type,
                                  UNUSED const uint32_t ha_state,
                                  struct hip_packet_context *ctx)
{
    const struct hip_echo_request *echo_request = NULL;
    int                            err          = 0;

    if (!(echo_request = hip_get_param(ctx->input_msg,
                                       HIP_PARAM_ECHO_REQUEST))) {
        HIP_DEBUG("no ECHO_REQUEST parameter in UPDATE packet, skipping\n");

        /* This condition is no error! There simply was no request by the peer
         * to add a ECHO_RESPONSE parameter to the outbound message. */
        return 0;
    }

    HIP_DEBUG("echo opaque data len=%d\n",
              hip_get_param_contents_len(echo_request));
    HIP_HEXDUMP("ECHO_REQUEST ",
                (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                hip_get_param_contents_len(echo_request));
    HIP_IFEL(hip_build_param_echo(ctx->output_msg,
                                  (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_len(echo_request), 0, 0),
             -1, "Building of ECHO_RESPONSE failed\n");

out_err:
    return err;
}

/**
 * Handle LOCATOR parameter in first update packet.
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
int hip_handle_locator_parameter(UNUSED const uint8_t packet_type,
                                 UNUSED const uint32_t ha_state,
                                 struct hip_packet_context *ctx)
{
    int                                locator_addr_count   = 0;
    int                                src_addr_included    = 0;
    union hip_locator_info_addr       *locator_info_addr    = NULL;
    struct hip_locator_info_addr_item *locator_address_item = NULL;
    struct update_state               *localstate           = NULL;
    struct hip_locator                *locator              = NULL;

    if (hip_classify_update_type(ctx->input_msg) == FIRST_UPDATE_PACKET) {
        if (!(locator = hip_get_param_readwrite(ctx->input_msg,
                                                HIP_PARAM_LOCATOR))) {
            HIP_ERROR("no LOCATOR parameter found\n");
            return -1;
        }

        locator_addr_count = hip_get_locator_addr_item_count(locator);

        HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
                  locator_addr_count, hip_get_param_total_len(locator));

        // Empty the addresses_to_send_echo_request list before adding the
        // new addresses
        localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                         "update");

        HIP_DEBUG("hip_get_state_item returned localstate: %p\n", localstate);
        hip_remove_addresses_to_send_echo_request(localstate);

        locator_address_item =  (struct hip_locator_info_addr_item *) (locator + 1);

        for (int i = 0; i < locator_addr_count; i++) {
            locator_info_addr = hip_get_locator_item(locator_address_item, i);
            const struct in6_addr *const peer_addr = hip_get_locator_item_address(locator_info_addr);

            if (!hip_add_address_to_send_echo_request(localstate, *peer_addr)) {
                HIP_ERROR("Adding an address to the container for update locators failed!\n");
                return -1;
            }

            HIP_DEBUG_IN6ADDR("Comparing", &ctx->src_addr);
            HIP_DEBUG_IN6ADDR("to ", peer_addr);

            if (ipv6_addr_cmp(&ctx->src_addr, peer_addr) == 0) {
                src_addr_included = 1;
            }
        }

        if (!src_addr_included) {
            HIP_DEBUG("Preferred address was not in locator (NAT?)\n");

            if (!hip_add_address_to_send_echo_request(localstate, ctx->src_addr)) {
                HIP_ERROR("Adding an address to the container for update locators failed!\n");
                return -1;
            }
        }

        hip_print_addresses_to_send_update_request(ctx->hadb_entry);
    }

    return 0;
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

        /* this handle function is called during BEX, there should be no
         * locators yet. */
        HIP_ASSERT(!ctx->hadb_entry->locator);

        HIP_IFEL(!(ctx->hadb_entry->locator = malloc(loc_size)),
                 -1, "Malloc for entry->locators failed\n");
        memcpy(ctx->hadb_entry->locator, locator, loc_size);
    } else {
        HIP_DEBUG("R1 did not have locator\n");
    }

out_err:
    return err;
}

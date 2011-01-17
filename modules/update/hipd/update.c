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
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP)
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>

#include "config.h"
#include "hipd/cookie.h"
#include "hipd/esp_prot_hipd_msg.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/input.h"
#include "hipd/maintenance.h"
#include "hipd/netdev.h"
#include "hipd/nsupdate.h"
#include "hipd/output.h"
#include "hipd/pisa.h"
#include "hipd/pkt_handling.h"
#include "hipd/user.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/performance.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/solve.h"
#include "lib/core/modularization.h"
#include "update_builder.h"
#include "update_legacy.h"
#include "update.h"

enum update_types { UNKNOWN_PACKET, FIRST_PACKET, SECOND_PACKET, THIRD_PACKET };

struct update_state {
    /** A kludge to get the UPDATE retransmission to work.
     *  @todo Remove this kludge. */
    int update_state;

    /** This "linked list" includes the locators we recieved in the initial
     * UPDATE packet. Locators are stored as "struct in6_addr *"s.
     *
     * Hipd sends UPDATE packets including ECHO_REQUESTS to all these
     * addresses.
     *
     * Notice that there's a hack that a hash table is used as a linked list
     * here but this is common allover HIPL and it doesn't seem to cause
     * performance problems.
     */
    HIP_HASHTABLE *addresses_to_send_echo_request;

    /** Stored outgoing UPDATE ID counter. */
    uint32_t update_id_out;
    /** Stored incoming UPDATE ID counter. */
    uint32_t update_id_in;
};

/**
 * Retrieve a pointer to the first locator in a LOCATOR parameter
 *
 * @param locator a pointer a LOCATOR parameter
 * @return a pointer to the first locator in the LOCATOR parameter
 */
static struct hip_locator_info_addr_item *hip_get_locator_first_addr_item(struct hip_locator *locator)
{
    return (struct hip_locator_info_addr_item *) (locator + 1);
}

/**
 * build locators in an UPDATE message
 *
 * @param locator_msg the message where the LOCATOR should be appended
 * @param locators an extra pointer that will point to the LOCATOR
 * @return zero on success or negative on failure
 */
int hip_create_locators(struct hip_common *locator_msg,
                        struct hip_locator_info_addr_item **locators)
{
    int                 err = 0;
    struct hip_locator *loc = NULL;

    hip_msg_init(locator_msg);
    HIP_IFEL(hip_build_user_hdr(locator_msg,
                                HIP_MSG_SET_LOCATOR_ON, 0), -1,
             "Failed to add user header\n");
    HIP_IFEL(hip_build_locators_old(locator_msg),
             -1,
             "Failed to build locators\n");
    loc = hip_get_param_readwrite(locator_msg, HIP_PARAM_LOCATOR);
    hip_print_locator_addresses(locator_msg);
    *locators = hip_get_locator_first_addr_item(loc);

out_err:
    return err;
}

/**
 * hip_update_get_out_id
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
 * @param *state    Pointer to the update state.
 *
 * @return The next UPDATE out ID if state is set, -1 on error
 */
static inline uint32_t hip_update_get_out_id(struct update_state *state)
{
    if (state) {
        return state->update_id_out - 1;
    } else {
        return -1;
    }
}

/**
 * construct any UPDATE message based on an incoming UPDATE packet
 *
 * @param received_update_packet the received UPDATE packet if any
 * @param ha the related host association
 * @param update_packet_to_send a preallocated message where the UPDATE
 *                              packet will be written
 * @param locators the locators of the local host
 * @param type the type of the incoming packet
 * @return zero on success or negative on failure
 *
 * @todo : should we implement base draft update with ifindex 0 stuff ??
 * @todo :  Divide this function into more pieces, handle_spi, handle_seq, etc
 * @todo : Remove the uncommented lines?
 */
static int hip_create_update_msg(struct hip_common *received_update_packet,
                                 struct hip_hadb_state *ha,
                                 struct hip_common *update_packet_to_send,
                                 struct hip_locator_info_addr_item *locators,
                                 int type)
{
    int                            err              = 0;
    uint32_t                       esp_info_old_spi = 0, esp_info_new_spi = 0;
    uint16_t                       mask             = 0;
    const struct hip_seq          *seq              = NULL;
    const struct hip_echo_request *echo_request     = NULL;
    struct update_state           *localstate       = NULL;

    HIP_DEBUG("Creating the UPDATE packet\n");

    if (type != HIP_UPDATE_LOCATOR) {
        HIP_DEBUG("UPDATE without locators\n");
    }

    hip_build_network_hdr(update_packet_to_send,
                          HIP_UPDATE,
                          mask,
                          &ha->hit_our,
                          &ha->hit_peer);

    // Add ESP_INFO
    if (type == HIP_UPDATE_LOCATOR      ||
        type == HIP_UPDATE_ECHO_REQUEST ||
        type == HIP_UPDATE_ESP_ANCHOR_ACK) {
        // Handle SPI numbers
        esp_info_old_spi = ha->spi_inbound_current;
        esp_info_new_spi = ha->spi_inbound_current;

        HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
                  esp_info_old_spi, esp_info_new_spi);

        HIP_IFEL(hip_build_param_esp_info(update_packet_to_send,
                                          ha->current_keymat_index,
                                          esp_info_old_spi, esp_info_new_spi),
                 -1, "Building of ESP_INFO param failed\n");
    }

    // Add LOCATOR
    if (type == HIP_UPDATE_LOCATOR) {
        HIP_DEBUG("locators = 0x%p locator_count = %d\n", locators, address_count);
        err = hip_build_param_locator(update_packet_to_send, locators, address_count);
    }

#ifdef CONFIG_HIP_MIDAUTH
    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (received_update_packet && type == HIP_UPDATE_ECHO_REQUEST) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet), -1,
                 "Building of Challenge_Response failed\n");
    } else {
        HIP_DEBUG("msg is NULL, midauth parameters not included in reply\n");
    }

    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet), -1,
                 "Building of Challenge_Response failed\n");
    }
#endif

    // Add SEQ
    if (type == HIP_UPDATE_LOCATOR      ||
        type == HIP_UPDATE_ECHO_REQUEST ||
        type == HIP_UPDATE_ESP_ANCHOR) {
        localstate = lmod_get_state_item(ha->hip_modular_state, "update");
        localstate->update_id_out++;
        HIP_DEBUG("outgoing UPDATE ID=%u\n", hip_update_get_out_id(localstate));
        /** @todo Handle this case. */
        HIP_IFEL(hip_build_param_seq(update_packet_to_send,
                                     hip_update_get_out_id(localstate)),
                 -1,
                 "Building of SEQ parameter failed\n");

        /************************************************/
    }

    // Add ACK
    if (type == HIP_UPDATE_ECHO_REQUEST  ||
        type == HIP_UPDATE_ECHO_RESPONSE ||
        type == HIP_UPDATE_ESP_ANCHOR_ACK) {
        HIP_IFEL(!(seq = hip_get_param(received_update_packet,
                                       HIP_PARAM_SEQ)),
                 -1, "SEQ not found\n");

        HIP_IFEL(hip_build_param_ack(update_packet_to_send,
                                     ntohl(seq->update_id)),
                 -1, "Building of ACK failed\n");
    }

    if (type == HIP_UPDATE_ESP_ANCHOR) {
        HIP_IFEL(esp_prot_update_add_anchor(update_packet_to_send, ha),
                 -1, "failed to add esp_prot anchor element\n");
    }

#ifdef CONFIG_HIP_MIDAUTH

    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(hip_build_param(update_packet_to_send, ha->our_pub), -1,
                 "Building of host id failed\n");
    }

    if (type == HIP_UPDATE_ECHO_REQUEST) {
        char *midauth_cert = hip_pisa_get_certificate();

        HIP_IFEL(hip_build_param(update_packet_to_send, ha->our_pub), -1,
                 "Building of host id failed\n");

        /* For now we just add some random data to see if it works */
        HIP_IFEL(hip_build_param_cert(update_packet_to_send,
                                      1,
                                      1,
                                      1,
                                      1,
                                      midauth_cert,
                                      strlen(midauth_cert)),
                 -1,
                 "Building of cert failed\n");
    }

#endif

    /* Add ECHO_REQUEST (signed)
     * Notice that ECHO_REQUEST is same for the identical UPDATE packets
     * sent between different address combinations.
     */
    if (type == HIP_UPDATE_ECHO_REQUEST) {
        HIP_HEXDUMP("ECHO_REQUEST in the host association",
                    ha->echo_data, sizeof(ha->echo_data));
        HIP_IFEL(hip_build_param_echo(update_packet_to_send,
                                      ha->echo_data,
                                      sizeof(ha->echo_data),
                                      1,
                                      1),
                 -1,
                 "Building of ECHO_REQUEST failed\n");
    }

    /* Add ECHO_RESPONSE (signed) */
    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        echo_request = hip_get_param(received_update_packet,
                                     HIP_PARAM_ECHO_REQUEST_SIGN);
        HIP_IFEL(!echo_request, -1, "ECHO REQUEST not found!\n");

        HIP_DEBUG("echo opaque data len=%d\n",
                  hip_get_param_contents_len(echo_request));
        HIP_HEXDUMP("ECHO_REQUEST ",
                    (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                    hip_get_param_contents_len(echo_request));
        HIP_IFEL(hip_build_param_echo(update_packet_to_send,
                                      (const uint8_t *) echo_request + sizeof(struct hip_tlv_common),
                                      hip_get_param_contents_len(echo_request), 1, 0),
                 -1, "Building of ECHO_RESPONSE failed\n");
    }

    // Add HMAC
    HIP_IFEL(hip_build_param_hmac_contents(update_packet_to_send,
                                           &ha->hip_hmac_out), -1, "Building of HMAC failed\n");

    // Add SIGNATURE
    HIP_IFEL(ha->sign(ha->our_priv_key, update_packet_to_send), -EINVAL,
             "Could not sign UPDATE. Failing\n");


out_err:
    return err;
}

/**
 * deliver an UPDATE packet to the network
 *
 * @param update_packet_to_send the packet to deliver
 * @param ha host association
 * @param src_addr the source address to use for sending
 * @param dst_addr the destination address to use for sending
 * @return zero on success or negative on failure
 */
static int hip_send_update_pkt(struct hip_common *update_packet_to_send,
                               struct hip_hadb_state *ha,
                               const struct in6_addr *src_addr,
                               const struct in6_addr *dst_addr)
{
    int       err        = 0;
    const int retransmit = 1;

    /** @todo set the local address unverified for that dst_hit(); */
    err = hip_send_pkt(src_addr,
                       dst_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       retransmit);

    return err;
}

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
 * choose a sensible source address for an UPDATE packet with LOCATOR
 *
 * @param ha the related host association
 * @param src_addr currently unused
 * @param dst_addr the destination address
 * @param new_src_addr the chosen source address
 * @return zero on success or negative on failure
 */
static int hip_select_local_addr_for_first_update(const struct hip_hadb_state *ha,
                                                  const struct in6_addr *src_addr,
                                                  const struct in6_addr *dst_addr,
                                                  struct in6_addr *new_src_addr)
{
    int                     err = 0, c;
    struct sockaddr_storage ss;
    struct netdev_address  *na  = NULL;
    LHASH_NODE             *n   = NULL, *t = NULL;
    const struct in6_addr  *in6 = NULL;

    memset(&ss, 0, sizeof(ss));
    memset(new_src_addr, 0, sizeof(*new_src_addr));

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
 * a wrapper function to handle any incoming UPDATE packet
 *
 * @param received_update_packet the received UPDATE packet if any
 * @param ha the related host association
 * @param src_addr the source address of the received packet
 * @param dst_addr the destination address of the received packet
 * @param locators the locators of the local host
 * @param type the type of the received packet
 * @return zero on success or negative on failure
 *
 * @todo locators should be sent to the whole verified addresses?
 */
int hip_send_update_to_one_peer(struct hip_common *received_update_packet,
                                struct hip_hadb_state *ha,
                                struct in6_addr *src_addr,
                                struct in6_addr *dst_addr,
                                struct hip_locator_info_addr_item *locators,
                                int type)
{
    int                  err                   = 0, i = 0;
    LHASH_NODE          *item                  = NULL, *tmp = NULL;
    struct hip_common   *update_packet_to_send = NULL;
    struct update_state *localstate            = NULL;
    struct in6_addr      local_addr;

    HIP_IFEL(!(update_packet_to_send = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the update packet\n");
    err = hip_create_update_msg(received_update_packet, ha,
                                update_packet_to_send, locators, type);
    if (err) {
        goto out_err;
    }

    switch (type) {
    case HIP_UPDATE_LOCATOR:
        HIP_IFEL(hip_select_local_addr_for_first_update(ha,
                                                        src_addr,
                                                        dst_addr,
                                                        &local_addr),
                 -1,
                 "No source address found for first update\n");
        HIP_DEBUG_IN6ADDR("Sending update from", &local_addr);
        HIP_DEBUG_IN6ADDR("to", dst_addr);

        hip_send_update_pkt(update_packet_to_send, ha, &local_addr,
                            dst_addr);

        break;
    case HIP_UPDATE_ECHO_RESPONSE:
        HIP_DEBUG_IN6ADDR("Sending update from", src_addr);
        HIP_DEBUG_IN6ADDR("to", dst_addr);

        hip_send_update_pkt(update_packet_to_send, ha, src_addr,
                            dst_addr);

        break;
    case HIP_UPDATE_ECHO_REQUEST:
        localstate = lmod_get_state_item(ha->hip_modular_state, "update");

        // Randomize the echo response opaque data before sending ECHO_REQUESTS.
        // Notice that we're using the same opaque value for the identical
        // UPDATE packets sent between different address combinations.
        RAND_bytes(ha->echo_data, sizeof(ha->echo_data));

        list_for_each_safe(item, tmp, localstate->addresses_to_send_echo_request, i) {
            dst_addr = list_entry(item);

            if (!are_addresses_compatible(src_addr, dst_addr)) {
                continue;
            }

            HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
            HIP_DEBUG_IN6ADDR("to", dst_addr);

            hip_send_update_pkt(update_packet_to_send, ha,
                                src_addr, dst_addr);
        }

        break;
    case HIP_UPDATE_ESP_ANCHOR:
    case HIP_UPDATE_ESP_ANCHOR_ACK:
        // TODO re-implement sending of esp prot anchors
        HIP_DEBUG_IN6ADDR("Sending update from", src_addr);
        HIP_DEBUG_IN6ADDR("to", dst_addr);

        hip_send_update_pkt(update_packet_to_send, ha, src_addr, dst_addr);
        break;
    }

out_err:
    free(update_packet_to_send);
    return err;
}

/**
 * publish the locator set of the local host to all peers
 *
 * @return zero on success or negative on failure
 */
static int hip_send_locators_to_all_peers(void)
{
    int                                err = 0, i = 0;
    struct hip_locator_info_addr_item *locators;
    struct hip_hadb_state             *ha          = NULL;
    struct hip_common                 *locator_msg = NULL;
    LHASH_NODE                        *item        = NULL, *tmp = NULL;

    HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the packet\n");
    HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

    // Go through all the peers and send update packets
    list_for_each_safe(item, tmp, hadb_hit, i) {
        ha = list_entry(item);

        if (ha->hastate == HIP_HASTATE_VALID &&
            ha->state == HIP_STATE_ESTABLISHED) {
            err = hip_send_update_to_one_peer(NULL,
                                              ha,
                                              &ha->our_addr,
                                              &ha->peer_addr,
                                              locators,
                                              HIP_UPDATE_LOCATOR);
            if (err) {
                goto out_err;
            }
        }
    }

out_err:
    /* Update DNS data in hit-to-ip domain name. This is done after
     * sending UPDATE packets. See the discussion for the reasoning:
     * http://www.freelists.org/post/hipl-users/HIP-UPDATE-select-error-Interrupted-system-call,2 */
    if (hip_get_nsupdate_status()) {
        nsupdate(0);
    }

    if (hip_locator_status == HIP_MSG_SET_LOCATOR_ON) {
        hip_recreate_all_precreated_r1_packets();
    }
    free(locator_msg);
    return err;
}

/**
 * Retrieve a locator address item from a list.
 *
 * @param item_list a pointer to the first item in the list
 * @param idx       the index of the item in the list
 * @return          the locator addres item
 */
static union hip_locator_info_addr *hip_get_locator_item(void *item_list,
                                                         int idx)
{
    int                                i = 0;
    struct hip_locator_info_addr_item *temp;
    char                              *result;
    result = item_list;


    for (i = 0; i <= idx - 1; i++) {
        temp = (struct hip_locator_info_addr_item *) result;
        if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI ||
            temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            result += sizeof(struct hip_locator_info_addr_item);
        } else {
            result += sizeof(struct hip_locator_info_addr_item2);
        }
    }
    return (union hip_locator_info_addr *) result;
}

/**
 * retrieve a IP address from a locator item structure
 *
 * @param item      a pointer to the item
 * @return a pointer to the IP address
 */
static struct in6_addr *hip_get_locator_item_address(void *item)
{
    struct hip_locator_info_addr_item *temp;


    temp = item;
    if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
        return &temp->address;
    } else if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
        return &temp->address;
    } else {
        return &((struct hip_locator_info_addr_item2 *) temp)->address;
    }
}

/**
 * Retrieve the number of locators inside a LOCATOR parameter.
 * Type 1 and 2 parameters are supported.
 *
 * @param locator a LOCATOR parameter
 * @return the number of locators
 */
int hip_get_locator_addr_item_count(const struct hip_locator *locator)
{
    const char *address_pointer = (const char *) (locator + 1);
    int         loc_count       = 0;
    uint8_t     type;

    while (address_pointer <
           ((const char *) locator) + hip_get_param_contents_len(locator)) {
        type = ((const struct hip_locator_info_addr_item *)
                address_pointer)->locator_type;

        if (type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
            address_pointer += sizeof(struct hip_locator_info_addr_item2);
            loc_count       += 1;
        } else if (type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI
                   || type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            address_pointer += sizeof(struct hip_locator_info_addr_item);
            loc_count       += 1;
        } else {
            address_pointer += sizeof(struct hip_locator_info_addr_item);
        }
    }
    return loc_count;
}

/**
 * process a LOCATOR paramter
 *
 * @param ha the related host association
 * @param src_addr the source address where the locator arrived from
 * @param locator the LOCATOR parameter
 * @return zero on success or negative on failure
 */
static int hip_handle_locator_parameter(struct hip_hadb_state *ha,
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

    locator_address_item =  hip_get_locator_first_addr_item(locator);
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
 * Classifies an UPDATE packet by means of contained parameters.
 *
 * @param esp_info      esp_info parameter of currently received packet
 * @param locator       locator parameter of currently received packet
 * @param seq           sequence parameter of currently received packet
 * @param ack           acknowledgement parameter of currently received packet
 * @param echo_request  echo_request parameter of currently received packet
 * @param echo_response echo_response parameter of currently received packet
 * @return member of enum update_types
 */
static enum update_types hip_classify_update_type(const struct hip_esp_info *esp_info,
                                                  const struct hip_locator *locator,
                                                  const struct hip_seq *seq,
                                                  const struct hip_ack *ack,
                                                  const struct hip_echo_request *echo_request,
                                                  const struct hip_echo_response *echo_response)
{
    if (esp_info && locator && seq) {
        return FIRST_PACKET;
    } else if (esp_info && seq && ack && echo_request) {
        return SECOND_PACKET;
    } else if (ack && echo_response) {
        return THIRD_PACKET;
    } else {
        return UNKNOWN_PACKET;
    }
}

/**
 * process the first UPDATE packet (i.e. with a LOCATOR parameter)
 *
 * @param ctx           the packet context
 * @param esp_info      esp_info parameter of currently received packet
 * @param locator       locator parameter of currently received packet
 * @param seq           sequence parameter of currently received packet
 * @return zero on success or negative on failure
 */
static int hip_handle_first_update_packet(struct hip_packet_context *ctx,
                                          const struct hip_esp_info *esp_info,
                                          struct hip_locator *locator,
                                          const struct hip_seq *seq)
{
    struct update_state *localstate = NULL;
    int                  err        = 0;

    HIP_IFEL(!(localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                                "update")),
             -1,
             "failed to look up UPDATE-specific state\n");

    HIP_IFEL(hip_handle_locator_parameter(ctx->hadb_entry,
                                          &ctx->src_addr,
                                          locator),
             -1,
             "failed to process LOCATOR parameter\n");

    // set the new spi value for the association
    ctx->hadb_entry->spi_outbound_new = ntohl(esp_info->new_spi);

    // progress update sequence to currently processed update
    if (localstate->update_id_in < ntohl(seq->update_id)) {
        localstate->update_id_in = ntohl(seq->update_id);
    }

    HIP_IFEL(hip_send_update_to_one_peer(ctx->input_msg,
                                         ctx->hadb_entry,
                                         &ctx->dst_addr,
                                         &ctx->src_addr,
                                         NULL,
                                         HIP_UPDATE_ECHO_REQUEST),
             -1,
             "failed to send UPDATE\n");

out_err:
    return err;
}

/**
 * process the second UPDATE packet (i.e. with echo request)
 *
 * @param ctx           the packet context
 * @param esp_info      esp_info parameter of currently received packet
 * @param seq           sequence parameter of currently received packet
 * @return zero on success or negative on failure
 */
static int hip_handle_second_update_packet(struct hip_packet_context *ctx,
                                           const struct hip_esp_info *esp_info,
                                           const struct hip_seq *seq)
{
    struct update_state *localstate = NULL;
    int                  err        = 0;

    HIP_IFEL(!(localstate = lmod_get_state_item(ctx->hadb_entry->hip_modular_state,
                                                "update")),
             -1,
             "failed to look up UPDATE-specific state\n");

    // set active addresses
    ipv6_addr_copy(&ctx->hadb_entry->our_addr,
                   &ctx->dst_addr);
    ipv6_addr_copy(&ctx->hadb_entry->peer_addr,
                   &ctx->src_addr);

    // set the new spi value for the association
    ctx->hadb_entry->spi_outbound_new = ntohl(esp_info->new_spi);

    // progress update sequence to currently processed update
    if (localstate->update_id_in < ntohl(seq->update_id)) {
        localstate->update_id_in = ntohl(seq->update_id);
    }

    HIP_IFEL(hip_send_update_to_one_peer(ctx->input_msg,
                                         ctx->hadb_entry,
                                         &ctx->dst_addr,
                                         &ctx->src_addr,
                                         NULL,
                                         HIP_UPDATE_ECHO_RESPONSE),
             -1,
             "failed to send UPDATE\n");

out_err:
    return err;
}

/**
 * process the third update (i.e. with echo response)
 *
 * @param ctx the packet context
 * @return zero on success or negative on failure
 */
static void hip_handle_third_update_packet(struct hip_packet_context *ctx)
{
    // set active addresses
    ipv6_addr_copy(&ctx->hadb_entry->our_addr,
                   &ctx->dst_addr);
    ipv6_addr_copy(&ctx->hadb_entry->peer_addr,
                   &ctx->src_addr);
}

static int hip_update_ipsec_sa(UNUSED const uint8_t packet_type,
                               UNUSED const uint32_t ha_state,
                               struct hip_packet_context *ctx)
{
    int err = 0;

    // don't update IPsec SAs and SPs for 1st UPDATE packet
    if (!hip_get_param(ctx->input_msg, HIP_PARAM_LOCATOR)) {
        HIP_IFEL(hip_create_or_update_security_associations_and_sp(ctx->hadb_entry,
                                                                   &ctx->src_addr,
                                                                   &ctx->dst_addr),
                 -1, "failed to update IPsec SAs and SPs\n");
    }

out_err:
    return err;
}

/**
 * Thin wrapper function around hip_send_locators_to_all_peers. Needed for
 * registration as user message handle function.
 *
 * @param *msg unused, needed due to type check of handle functions
 * @param *src unused, needed due to type check of handle functions
 *
 * @return zero on success or negative on failure
 */
static int hip_update_manual_update(UNUSED struct hip_common *msg,
                                    UNUSED struct sockaddr_in6 *src)
{
    HIP_DEBUG("Manual UPDATE triggered.\n");
    return hip_send_locators_to_all_peers();
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
        err = hip_send_locators_to_all_peers();

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
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
static int hip_update_init_state(struct modular_state *state)
{
    int                  err          = 0;
    struct update_state *update_state = NULL;

    HIP_IFEL(!(update_state = malloc(sizeof(struct update_state))),
             -1,
             "Error on allocating memory for a update state instance.\n");

    update_state->update_state                   = 0;
    update_state->addresses_to_send_echo_request = hip_linked_list_init();
    update_state->update_id_out                  = 0;
    update_state->update_id_in                   = 0;

    err = lmod_add_state_item(state, update_state, "update");

out_err:
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
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
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
 * Process an received and checked UPDATE packet.
 *
 * @param packet_type the packet type
 * @param ha_state the HA state
 * @param ctx the packet context
 * @return zero on success or negative on failure
 */
static int hip_handle_update_packet(UNUSED const uint8_t packet_type,
                                    UNUSED const uint32_t ha_state,
                                    struct hip_packet_context *ctx)
{
    const struct hip_esp_info      *esp_info      = NULL;
    struct hip_locator             *locator       = NULL;
    const struct hip_seq           *seq           = NULL;
    const struct hip_ack           *ack           = NULL;
    const struct hip_echo_request  *echo_request  = NULL;
    const struct hip_echo_response *echo_response = NULL;
    enum update_types               update_type   = UNKNOWN_PACKET;
    int                             err           = 0;

    /* RFC 5206: End-Host Mobility and Multihoming.
     * Mandatory parameters from 3.2.1. Mobility with a Single SA Pair
     * (No Rekeying) */
    esp_info      = hip_get_param(ctx->input_msg, HIP_PARAM_ESP_INFO);
    locator       = hip_get_param_readwrite(ctx->input_msg, HIP_PARAM_LOCATOR);
    seq           = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ);
    ack           = hip_get_param(ctx->input_msg, HIP_PARAM_ACK);
    echo_request  = hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_REQUEST_SIGN);
    echo_response = hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_RESPONSE_SIGN);

    /* set local UDP port just in case the original communications
     * changed from raw to UDP or vice versa */
    ctx->hadb_entry->local_udp_port = ctx->msg_ports.dst_port;
    /* @todo: a workaround for bug id 592200 */
    ctx->hadb_entry->peer_udp_port = ctx->msg_ports.src_port;

    update_type = hip_classify_update_type(esp_info,
                                           locator,
                                           seq,
                                           ack,
                                           echo_request,
                                           echo_response);
    switch (update_type) {
    case FIRST_PACKET:
        err = hip_handle_first_update_packet(ctx,
                                             esp_info,
                                             locator,
                                             seq);
        break;
    case SECOND_PACKET:
        err = hip_handle_second_update_packet(ctx,
                                              esp_info,
                                              seq);
        break;
    case THIRD_PACKET:
        hip_handle_third_update_packet(ctx);
        break;
    default:
        if (esp_prot_update_type(ctx->input_msg)
            == ESP_PROT_FIRST_UPDATE_PACKET) {
            esp_prot_handle_first_update_packet(ctx->input_msg,
                                                ctx->hadb_entry,
                                                &ctx->src_addr,
                                                &ctx->dst_addr);
        } else if (esp_prot_update_type(ctx->input_msg)
                   == ESP_PROT_SECOND_UPDATE_PACKET) {
            esp_prot_handle_second_update_packet(ctx->hadb_entry,
                                                 &ctx->src_addr,
                                                 &ctx->dst_addr);
        } else {
            HIP_ERROR("UPDATE packet unknown\n");
            err = -1;
            goto out_err;
        }
    }

out_err:
    ctx->error = err;
    return err;
}

static int hip_update_change_state(UNUSED const uint8_t packet_type,
                                   UNUSED const uint32_t ha_state,
                                   struct hip_packet_context *ctx)
{
    int err = 0;

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
                                          &hip_handle_update_packet,
                                          30000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &hip_update_ipsec_sa,
                                          30500),
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
                                          &hip_handle_update_packet,
                                          30000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_update_ipsec_sa,
                                          30500),
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

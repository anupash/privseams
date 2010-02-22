/** @file
 * The header file for update.c
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @version 0.1
 * @date    3.5.2009
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPD_UPDATE_H
#define HIP_HIPD_UPDATE_H

#include "lib/core/builder.h"
#include "hipd/hadb.h"

struct update_state {
    /** A kludge to get the UPDATE retransmission to work.
        @todo Remove this kludge. */
    int update_state;

    /** Update function set.
        @note Do not modify this value directly. Use
        hip_hadb_set_handle_function_set() instead. */
    hip_update_func_set_t *hadb_update_func;

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
    uint32_t                     update_id_out;
    /** Stored incoming UPDATE ID counter. */
    uint32_t                     update_id_in;
};

/**
 * Sends all the locators from our active source address to the active
 * destination addresses of all peers.
 *
 * Notice that the update packet is sent between only one active address pair
 * between two peers. When shotgun is implemented this will change.
 *
 * @return 0 if succeeded, error number otherwise
 */
int hip_send_locators_to_all_peers(void);

/**
 * Handles a received update packet.
 *
 * @param msg: received update packet
 * @param src_addr: source address from which this received update packet was sent
 * @param dst_addr: destination address to which this received update packet was sent
 * @param ha: corresponding host association between the peers update packets was
 *  transmitted
 * @param sinfo: port information for the received update packet
 *
 * @return 0 if succeeded, error number otherwise
 */
int hip_receive_update(struct hip_packet_context *ctx);

int hip_create_locators(hip_common_t *locator_msg,
                        struct hip_locator_info_addr_item **locators);

int hip_send_locators_to_one_peer(hip_common_t *received_update_packet,
                                  struct hip_hadb_state *ha,
                                  struct in6_addr *src_addr,
                                  struct in6_addr *dst_addr,
                                  struct hip_locator_info_addr_item *locators,
                                  int type);

int hip_update_init(void);

struct update_state *hip_update_init_state(void);

#endif /* HIP_HIPD_UPDATE_H */

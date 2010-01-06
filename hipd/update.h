/** @file
 * The header file for update.c
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @version 0.1
 * @date    3.5.2009
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#include "libhipcore/builder.h"
#include "hadb.h"

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
int hip_receive_update(hip_common_t* msg, in6_addr_t *src_addr,
        in6_addr_t *dst_addr, hip_ha_t *ha, hip_portpair_t *sinfo);

int hip_create_locators(hip_common_t* locator_msg,
			struct hip_locator_info_addr_item **locators);

int hip_send_locators_to_one_peer(hip_common_t* received_update_packet,
				  struct hip_hadb_state *ha, struct in6_addr *src_addr,
				  struct in6_addr *dst_addr, struct hip_locator_info_addr_item *locators,
				  int type);

#endif /* HIP_UPDATE_H */

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

#include <stdint.h>
#include "lib/core/protodefs.h"

int hip_create_locators(hip_common_t *locator_msg,
                        struct hip_locator_info_addr_item **locators);

int hip_send_locators_to_all_peers(void);

int hip_send_update_to_one_peer(hip_common_t *received_update_packet,
                                struct hip_hadb_state *ha,
                                struct in6_addr *src_addr,
                                struct in6_addr *dst_addr,
                                struct hip_locator_info_addr_item *locators,
                                int type);

int hip_update_init(void);

#endif /* HIP_HIPD_UPDATE_H */

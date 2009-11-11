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

#include "builder.h"
#include "hadb.h"

int hip_send_update_locator();

int hip_receive_update(hip_common_t* msg, in6_addr_t *src_addr,
        in6_addr_t *dst_addr, hip_ha_t *entry, hip_portpair_t *sinfo);

int hip_build_locators_old(struct hip_common *, uint32_t spi, hip_transform_suite_t ice);

int hip_update_send_echo_old(hip_ha_t *entry,
			 uint32_t spi_out,
			 struct hip_peer_addr_list_item *addr);


#endif /* HIP_UPDATE_H */
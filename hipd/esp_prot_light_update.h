/*
 * esp_prot_light_update.h
 *
 *  Created on: Oct 13, 2008
 *      Author: chilli
 */

#ifndef ESP_PROT_LIGHT_UPDATE_H_
#define ESP_PROT_LIGHT_UPDATE_H_

#include "builder.h"

int esp_prot_send_light_update(hip_ha_t *entry, int anchor_offset, unsigned char *secret,
		int secret_length, unsigned char *branch_nodes, int branch_length);
int esp_prot_receive_light_update(hip_common_t *msg, in6_addr_t *src_addr,
	       in6_addr_t *dst_addr, hip_ha_t *entry, hip_portpair_t *sinfo);
int esp_prot_send_light_ack(hip_ha_t *entry, in6_addr_t *src_addr, in6_addr_t *dst_addr,
		uint32_t spi);


#endif /* ESP_PROT_LIGHT_UPDATE_H_ */

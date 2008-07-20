/*
 * esp_prot_msg.h
 *
 *  Created on: Jul 20, 2008
 *      Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef ESP_PROT_MSG_H_
#define ESP_PROT_MSG_H_

#include <inttypes.h>

int send_esp_protection_to_hipd(int active);
int send_anchor_list_update_to_hipd(uint8_t transform);
int send_next_anchor_to_hipd(unsigned char *anchor, uint8_t transform);

#endif /* ESP_PROT_MSG_H_ */

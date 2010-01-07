/**
 * References to the hash structures stored in the BEX store of the hipfw
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_ANCHORDB_H_
#define ESP_PROT_ANCHORDB_H_

#include "libhipcore/protodefs.h"


void anchor_db_init(void);
void anchor_db_uninit(void);
int anchor_db_update(const struct hip_common *msg);
int anchor_db_get_num_anchors(const uint8_t transform);
unsigned char * anchor_db_get_anchor(const uint8_t transform);
int anchor_db_get_anchor_length(const uint8_t transform);
int anchor_db_get_hash_item_length(const uint8_t transform);

#endif /*ESP_PROT_ANCHORDB_H_*/

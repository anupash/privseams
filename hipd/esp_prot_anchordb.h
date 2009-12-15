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

#include "esp_prot_common.h"
#include "hashchain_store.h"
#include "builder.h"

/** inits the anchorDB */
void anchor_db_init(void);

/** uninits the anchorDB */
void anchor_db_uninit(void);

/** handles a user-message sent by the firewall when the bex-store is updated
 *
 * @param	msg the user-message sent by fw
 * @return	0 if ok, != 0 else
 */
int anchor_db_update(struct hip_common *msg);

/** returns number of elements for the given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	number of elements
 */
int anchor_db_get_num_anchors(uint8_t transform);

/* returns an unused anchor element for the given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	anchor, NULL if empty */
unsigned char * anchor_db_get_anchor(uint8_t transform);

/** returns the anchor-length for a given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	anchor-length, 0 for UNUSED transform
 */
int anchor_db_get_anchor_length(uint8_t transform);

/** returns the hash-item-length for a given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	hash-item-length, 0 for UNUSED transform
 */
int anchor_db_get_hash_item_length(uint8_t transform);

#endif /*ESP_PROT_ANCHORDB_H_*/

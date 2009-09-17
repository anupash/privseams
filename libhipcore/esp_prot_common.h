/*
 * Defines necessary TPA parameters used by both hipfw and hipd
 *
 * Description:
 *
 * Authors:
 * - Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 * Licence: GNU/GPL
 */

#ifndef EXT_ESP_PROT_COMMON_H_
#define EXT_ESP_PROT_COMMON_H_

#include <inttypes.h>

/* the maximum number of TPA transforms */
#define MAX_NUM_ESP_PROT_TFMS				256

/** defines the maximum number of parallel hash chains to be
 * used in a single IPsec security association
 */
#define MAX_NUM_PARALLEL_HCHAINS			10

#define HCSTORE_MAX_HCHAINS_PER_ITEM		100

#define MAX_HTREE_DEPTH						20


/* this is a special purpose transform representing no hash token to be used */
#define ESP_PROT_TFM_UNUSED					0


/** checks if the passed transform is one of our locally preferred transforms
 *
 * @param	num_transforms amount of transforms contained in the array
 * @param	preferred_transforms the transforms against which should be checked
 * @param	transform the ESP protection extension transform to be checked
 * @return	index in the preferred_transforms array, -1 if no match found
 */
int esp_prot_check_transform(int num_transforms, uint8_t *preferred_transforms,
		uint8_t transform);

#endif /*EXT_ESP_PROT_COMMON_H_*/

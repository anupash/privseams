#ifndef EXT_ESP_PROT_COMMON_H_
#define EXT_ESP_PROT_COMMON_H_

#include <inttypes.h>

#define ESP_PROT_TFM_UNUSED			0
#define ESP_PROT_TFM_SHA1_20		1
/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS				1
/* for first dimension of hash_lengths[][] */
#define NUM_HASH_FUNCTIONS			1
/* for second dimension of hash_lengths[][] */
#define NUM_HASH_LENGTHS			1

// changed for measurements
#if 0
/* IDs for all supported transforms
 *
 * @note If you change these, make sure to also change the helper defines
 *       NUM_* and to set up hash_functions[] and hash_lengths[][] in esp_prot.h
 *       accordingly. Ensure to add new hash-functions in the end of the transforms
 *       list and pay attention to the order of the hash-lengths for each function.
 */
#define ESP_PROT_TFM_UNUSED			0
#define ESP_PROT_TFM_SHA1_8			1
#define ESP_PROT_TFM_SHA1_16		2
#define ESP_PROT_TFM_SHA1_20		3
#define ESP_PROT_TFM_MD5_8			4
#define ESP_PROT_TFM_MD5_16			5

 /**** helper defines for the index boundaries of the static arrays defined below ****/

/* When adding a new transform, make sure to also add it in esp_prot_common.h.
 * Ensure to add new hash-functions in the end of hash_functions[] and keep the
 * same order of the hash-lengths in hash_lengths[][] as in the define list for the
 * transforms in esp_prot_common.h. */

/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS				5
/* for first dimension of hash_lengths[][] */
#define NUM_HASH_FUNCTIONS			2
/* for second dimension of hash_lengths[][] */
#define NUM_HASH_LENGTHS			3
#endif

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

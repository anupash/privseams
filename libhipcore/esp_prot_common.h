#ifndef EXT_ESP_PROT_COMMON_H_
#define EXT_ESP_PROT_COMMON_H_

#include <inttypes.h>

/* the maximum numbers for arrays used for the different modes */
#define MAX_NUM_TRANSFORMS					10
#define MAX_NUM_PARALLEL_HCHAINS			10
#define HCSTORE_MAX_HCHAINS_PER_ITEM		100
#define MAX_HTREE_DEPTH						20
#define MAX_RING_BUFFER_SIZE				128

/* this is a special purpose transform representing no hash token to be used */
#define ESP_PROT_TFM_UNUSED					0
#define ESP_PROT_TFM_PLAIN					1
#define ESP_PROT_TFM_PARALLEL				2
#define ESP_PROT_TFM_CUMULATIVE				3
#define ESP_PROT_TFM_PARA_CUMUL				4
#define ESP_PROT_TFM_TREE					5
#define ESP_PROT_TFM_TREE_CHAIN				6

int esp_prot_check_transform(const int num_transforms, const uint8_t *preferred_transforms,
		const uint8_t transform);

#endif /*EXT_ESP_PROT_COMMON_H_*/

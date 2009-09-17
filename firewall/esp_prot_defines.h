/*
 * esp_prot_defines.h
 *
 *  Created on: 07.04.2009
 *      Author: chilli
 */

#ifndef ESP_PROT_DEFINES_H_
#define ESP_PROT_DEFINES_H_

#include "hashchain.h"

/* defines the default tolerance when verifying hash-chain elements
 *
 * @note set to the preferred anti-replay window size of ESP */
#define DEFAULT_VERIFY_WINDOW 			64
/* if unused hchain element count of the active_hchain falls below
 * this threshold (% of max count), it will trigger the setup of
 * a new next_hchain */
#define REMAIN_HASHES_TRESHOLD			0.5

// switch to use parallel hchains for authentication
#define PARALLEL_HCHAINS_MODE			1
/* the number of parallel hash chain to be used
 * when parallel hash chain authentication is active
 */
#define NUM_PARALLEL_HCHAINS			6

// switch to use cumulative authentication TPA
#define CUMULATIVE_AUTH_MODE			0
/* size of the buffer for cumulative authentication
 *
 * NOTE: should not be set higher than IPsec replay window
 * 		 -> packet would be dropped anyway then
 */
#define RINGBUF_SIZE					64
#define NUM_LINEAR_ELEMENTS				1
#define NUM_RANDOM_ELEMENTS				0



/* as using different hchain lengths for bex is not supported in esp_prot,
 * we can set a default length statically */
#define DEFAULT_HCHAIN_LENGTH_ID	0
 /* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS	1
/* number of hierarchies used to link hchains in the BEX store */
#define NUM_BEX_HIERARCHIES			1
/* number of hierarchies used to link hchains in the update store */
#define NUM_UPDATE_HIERARCHIES		4



/* max amount of hchains that can be stored per hchain_item
 *
 * @note we are using a list here, so we might also use some other
 *       mechanism to stop the hcstore_refill() */
#define HCSTORE_NUM_HCHAINS_PER_ITEM	8

/* determines when to refill a store
 *
 * @note this is a reverse threshold -> 1 - never refill, 0 - always
 */
#define HCSTORE_REFILL_THRESHOLD			0.5



/* offset of the hash-tree-based mode of operation */
#define ESP_PROT_TFM_HTREE_OFFSET	192
/* hash chains have transforms > 0 and <= 128 */
#define ESP_PROT_TFM_SHA1_20		1
/* hash trees have transforms > 128 and <= 255 */
#define ESP_PROT_TFM_SHA1_20_TREE	1 + ESP_PROT_TFM_HTREE_OFFSET
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


/* packet information required by the cumulative authentication of TPA */
struct esp_cumulative_item
{
	uint32_t seq; /* current sequence of the IPsec SA */
	unsigned char packet_hash[MAX_HASH_LENGTH];
} __attribute__ ((packed));

typedef struct esp_cumulative_item esp_cumulative_item_t;

#endif /* ESP_PROT_DEFINES_H_ */

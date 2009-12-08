/*
 * esp_prot_defines.h
 *
 *  Created on: 07.04.2009
 *      Author: Rene Hummen
 */

#ifndef ESP_PROT_DEFINES_H_
#define ESP_PROT_DEFINES_H_

#include "hashchain.h"


/* as using different hchain lengths for bex is not supported in esp_prot,
 * we can set a default length statically */
#define DEFAULT_HCHAIN_LENGTH_ID	0
 /* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS	1
/* number of hierarchies used to link hchains in the BEX store */
#define NUM_BEX_HIERARCHIES			1

/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS				1
/* for first dimension of hash_lengths[][] */
#define NUM_HASH_FUNCTIONS			1
/* for second dimension of hash_lengths[][] */
#define NUM_HASH_LENGTHS			1


/* packet information required by the cumulative authentication of TPA */
struct esp_cumulative_item
{
	uint32_t seq; /* current sequence of the IPsec SA */
	unsigned char packet_hash[MAX_HASH_LENGTH];
} __attribute__ ((packed));

typedef struct esp_cumulative_item esp_cumulative_item_t;

#endif /* ESP_PROT_DEFINES_H_ */

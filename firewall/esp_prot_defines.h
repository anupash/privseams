/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_FIREWALL_ESP_PROT_DEFINES_H
#define HIP_FIREWALL_ESP_PROT_DEFINES_H

#include <stdint.h>

#include "lib/core/hashchain.h"


/* as using different hchain lengths for bex is not supported in esp_prot,
 * we can set a default length statically */
#define DEFAULT_HCHAIN_LENGTH_ID                0
/* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS               1
/* number of hierarchies used to link hchains in the BEX store */
#define NUM_BEX_HIERARCHIES                     1

/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS                          1
/* for first dimension of hash_lengths[][] */
#define NUM_HASH_FUNCTIONS                      1
/* for second dimension of hash_lengths[][] */
#define NUM_HASH_LENGTHS                        1

/* packet information required by the cumulative authentication of TPA */
struct esp_cumulative_item {
    uint32_t      seq; /* current sequence of the IPsec SA */
    unsigned char packet_hash[MAX_HASH_LENGTH];
} __attribute__ ((packed));

typedef struct esp_cumulative_item esp_cumulative_item_t;

#endif /* HIP_FIREWALL_ESP_PROT_DEFINES_H */

/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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

/**
 * @file
 * Stores a number of pre-created hash structures and supports HHL-based
 * linking of hash structures in different hierarchy levels.
 *
 * @brief Store for pre-created hash structures
 */

#ifndef HIP_LIB_CORE_HASHCHAIN_STORE_H
#define HIP_LIB_CORE_HASHCHAIN_STORE_H

#include "linkedlist.h"
#include "hashchain.h"


/* max amount of different hash-functions that can be stored */
#define MAX_FUNCTIONS                   5
/* max amount of different hash lengths that can be stored */
#define MAX_NUM_HASH_LENGTH             5
/* this includes the BEX-item */
#define MAX_NUM_HCHAIN_LENGTH   5
// max number of hierarchies for which hchains can be linked
#define MAX_NUM_HIERARCHIES             100


struct hchain_shelf {
    /* number of different hchain lengths currently used for this
     * (hash-function, hash_length)-combination */
    unsigned num_hchain_lengths;
    /* the different hchain lengths */
    unsigned hchain_lengths[MAX_NUM_HCHAIN_LENGTH];
    /* number of hierarchies in this shelf */
    unsigned num_hierarchies[MAX_NUM_HCHAIN_LENGTH];
    /* hchains with the respective hchain length */
    struct hip_ll hchains[MAX_NUM_HCHAIN_LENGTH][MAX_NUM_HIERARCHIES];
};

struct hchain_store {
    /* determines at which volume a store item should be refilled */
    double refill_threshold;
    /* number of hash structures stored per item, when it is full */
    unsigned num_hchains_per_item;
    /* amount of currently used hash-functions */
    unsigned num_functions;
    /* pointer to the hash-function used to create and verify the hchain
     *
     * @note params: (in_buffer, in_length, out_buffer)
     * @note out_buffer should be size MAX_HASH_LENGTH */
    hash_function hash_functions[MAX_FUNCTIONS];
    /* amount of different hash_lengths per hash-function */
    unsigned num_hash_lengths[MAX_FUNCTIONS];
    /* length of the hashes, of which the respective hchain items consist */
    unsigned hash_lengths[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
    /* contains hchains and meta-information about how to process them */
    struct hchain_shelf hchain_shelves[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
};

int hcstore_init(struct hchain_store *hcstore,
                 const int num_hchains_per_item,
                 const double refill_threshold);
void hcstore_uninit(struct hchain_store *hcstore, const int use_hash_trees);
int hcstore_register_function(struct hchain_store *hcstore,
                              const hash_function hash_function);
int hcstore_register_hash_length(struct hchain_store *hcstore,
                                 const int function_id,
                                 const int hash_length);
int hcstore_register_hash_item_length(struct hchain_store *hcstore,
                                      const int function_id,
                                      const int hash_length_id,
                                      const int hitem_length);
int hcstore_register_hash_item_hierarchy(struct hchain_store *hcstore,
                                         const int function_id,
                                         const int hash_length_id,
                                         const int hitem_length,
                                         const int addtional_hierarchies);
int hcstore_refill(struct hchain_store *hcstore, const int use_hash_trees);
void *hcstore_get_hash_item(struct hchain_store *hcstore,
                            const int function_id,
                            const int hash_length_id,
                            const int hchain_length);
void *hcstore_get_item_by_anchor(struct hchain_store *hcstore,
                                 const int function_id,
                                 const int hash_length_id,
                                 const int hierarchy_level,
                                 const unsigned char *anchor,
                                 const int use_hash_trees);
hash_function hcstore_get_hash_function(struct hchain_store *hcstore,
                                        const int function_id);
int hcstore_get_hash_length(struct hchain_store *hcstore,
                            const int function_id,
                            const int hash_length_id);

#endif /* HIP_LIB_CORE_HASHCHAIN_STORE_H */

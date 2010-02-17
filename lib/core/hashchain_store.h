/**
 * @file firewall/hashchain_store.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Stores a number of pre-created hash structures and supports HHL-based
 * linking of hash structures in different hierarchy levels.
 *
 * @brief Store for pre-created hash structures
 *
 * @author Tobias Heer <heer@tobobox.de>
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
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


typedef struct hchain_shelf {
    /* number of different hchain lengths currently used for this
     * (hash-function, hash_length)-combination */
    int      num_hchain_lengths;
    /* the different hchain lengths */
    int      hchain_lengths[MAX_NUM_HCHAIN_LENGTH];
    /* number of hierarchies in this shelf */
    int      num_hierarchies[MAX_NUM_HCHAIN_LENGTH];
    /* hchains with the respective hchain length */
    hip_ll_t hchains[MAX_NUM_HCHAIN_LENGTH][MAX_NUM_HIERARCHIES];
} hchain_shelf_t;

typedef struct hchain_store {
    /* determines at which volume a store item should be refilled */
    double refill_threshold;
    /* number of hash structures stored per item, when it is full */
    int    num_hchains_per_item;
    /* amount of currently used hash-functions */
    int    num_functions;
    /* pointer to the hash-function used to create and verify the hchain
     *
     * @note params: (in_buffer, in_length, out_buffer)
     * @note out_buffer should be size MAX_HASH_LENGTH */
    hash_function_t hash_functions[MAX_FUNCTIONS];
    /* amount of different hash_lengths per hash-function */
    int             num_hash_lengths[MAX_FUNCTIONS];
    /* length of the hashes, of which the respective hchain items consist */
    int             hash_lengths[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
    /* contains hchains and meta-information about how to process them */
    hchain_shelf_t  hchain_shelves[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
} hchain_store_t;

int hcstore_init(hchain_store_t *hcstore,
                 const int num_hchains_per_item,
                 const double refill_threshold);
void hcstore_uninit(hchain_store_t *hcstore, const int use_hash_trees);
int hcstore_register_function(hchain_store_t *hcstore,
                              const hash_function_t hash_function);
int hcstore_register_hash_length(hchain_store_t *hcstore,
                                 const int function_id,
                                 const int hash_length);
int hcstore_register_hash_item_length(hchain_store_t *hcstore,
                                      const int function_id,
                                      const int hash_length_id,
                                      const int hitem_length);
int hcstore_register_hash_item_hierarchy(hchain_store_t *hcstore,
                                         const int function_id,
                                         const int hash_length_id,
                                         const int hitem_length,
                                         const int addtional_hierarchies);
int hcstore_refill(hchain_store_t *hcstore, const int use_hash_trees);
void *hcstore_get_hash_item(hchain_store_t *hcstore,
                            const int function_id,
                            const int hash_length_id,
                            const int hchain_length);
void *hcstore_get_item_by_anchor(hchain_store_t *hcstore,
                                 const int function_id,
                                 const int hash_length_id,
                                 const int hierarchy_level,
                                 const unsigned char *anchor,
                                 const int use_hash_trees);
hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore,
                                          const int function_id);
int hcstore_get_hash_length(hchain_store_t *hcstore,
                            const int function_id,
                            const int hash_length_id);

#endif /* HIP_LIB_CORE_HASHCHAIN_STORE_H */

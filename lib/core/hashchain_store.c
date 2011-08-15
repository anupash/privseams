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

#include <string.h>

#include "debug.h"
#include "hashtree.h"
#include "ife.h"
#include "linkedlist.h"
#include "hashchain_store.h"

/** helper function to free a hash chain
 *
 * @param       hchain the the hash chain to be freed
 */
static void hcstore_free_hchain(void *hchain)
{
    hchain_free(hchain);
}

/** helper function to free a hash tree
 *
 * @param       htree the the hash tree to be freed
 */
static void hcstore_free_htree(void *htree)
{
    htree_free(htree);
}

/** initializes a new hash item store
 *
 * @param       hcstore the store to be initialized
 * @param       num_hchains_per_item number of hash items per hierarchy level
 * @param       refill_threshold the threshold below which a hierarchy level will be refilled
 * @return      always returns 0
 */
int hcstore_init(struct hchain_store *hcstore,
                 const int num_hchains_per_item,
                 const double refill_threshold)
{
    int err = 0, i, j, g, h;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(num_hchains_per_item >= 0);
    HIP_ASSERT(refill_threshold >= 0 && refill_threshold <= 1);

    // set global values
    hcstore->num_hchains_per_item = num_hchains_per_item;
    hcstore->refill_threshold     = refill_threshold;

    hcstore->num_functions = 0;

    for (i = 0; i < MAX_FUNCTIONS; i++) {
        hcstore->hash_functions[i]   = NULL;
        hcstore->num_hash_lengths[i] = 0;

        for (j = 0; j < MAX_NUM_HASH_LENGTH; j++) {
            hcstore->hash_lengths[i][j]                      = 0;
            hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

            for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++) {
                hcstore->hchain_shelves[i][j].hchain_lengths[g]  = 0;
                hcstore->hchain_shelves[i][j].num_hierarchies[g] = 0;

                for (h = 0; h < MAX_NUM_HIERARCHIES; h++) {
                    hip_ll_init(&hcstore->hchain_shelves[i][j].hchains[g][h]);
                }
            }
        }
    }

    HIP_DEBUG("hash-chain store initialized\n");

    return err;
}

/** un-initializes a hash structure store
 *
 * @param       hcstore the store to be un-initialized
 * @param       use_hash_trees indicates whether hash chains or hash trees are stored
 */
void hcstore_uninit(struct hchain_store *hcstore, const int use_hash_trees)
{
    int i, j, g, h;

    HIP_ASSERT(hcstore != NULL);

    hcstore->num_functions = 0;

    for (i = 0; i < MAX_FUNCTIONS; i++) {
        hcstore->hash_functions[i]   = NULL;
        hcstore->num_hash_lengths[i] = 0;

        for (j = 0; j < MAX_NUM_HASH_LENGTH; j++) {
            hcstore->hash_lengths[i][j]                      = 0;
            hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

            for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++) {
                hcstore->hchain_shelves[i][j].hchain_lengths[g]  = 0;
                hcstore->hchain_shelves[i][j].num_hierarchies[g] = 0;

                for (h = 0; h < MAX_NUM_HIERARCHIES; h++) {
                    if (use_hash_trees) {
                        hip_ll_uninit(&hcstore->hchain_shelves[i][j].hchains[g][h],
                                      hcstore_free_htree);
                    } else {
                        hip_ll_uninit(&hcstore->hchain_shelves[i][j].hchains[g][h],
                                      hcstore_free_hchain);
                    }
                }
            }
        }
    }

    HIP_DEBUG("hash-chain store uninitialized\n");
}

/** registers a new hash function for utilization in the store
 *
 * @param       hcstore the store, where the function should be added
 * @param       hash_func function pointer to the hash function
 * @return      returns the index to the hash function in the store,
 *          -1 if MAX_FUNCTIONS is reached
 */
int hcstore_register_function(struct hchain_store *hcstore,
                              const hash_function hash_func)
{
    int      err = 0;
    unsigned i;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(hash_func != NULL);

    // first check that there's still some space left
    HIP_IFEL(hcstore->num_functions == MAX_FUNCTIONS, -1,
             "space for function-storage is full\n");

    // also check if the function is already stored
    for (i = 0; i < hcstore->num_functions; i++) {
        if (hcstore->hash_functions[i] == hash_func) {
            HIP_DEBUG("hchain store already contains this function\n");

            err = i;
            goto out_err;
        }
    }

    // store the hash-function
    err                                             = hcstore->num_functions;
    hcstore->hash_functions[hcstore->num_functions] = hash_func;
    hcstore->num_functions++;

    HIP_DEBUG("hash function successfully registered\n");

out_err:
    return err;
}

/** registers a new hash length for utilization in the store
 *
 * @param       hcstore the store, where the hash length should be added
 * @param       function_id index to the hash function, where the length should be added
 * @param       hash_length hash length to be added
 * @return      returns the index to the hash length in the store,
 *          -1 if MAX_NUM_HASH_LENGTH is reached
 */
int hcstore_register_hash_length(struct hchain_store *hcstore, const int function_id,
                                 const int hash_length)
{
    int      err = 0;
    unsigned i;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length > 0);

    // first check that there's still some space left
    HIP_IFEL(hcstore->num_hash_lengths[function_id] == MAX_NUM_HASH_LENGTH, -1,
             "space for hash_length-storage is full\n");

    // also check if the hash length is already stored for this function
    for (i = 0; i < hcstore->num_hash_lengths[function_id]; i++) {
        if ((int) hcstore->hash_lengths[function_id][i] == hash_length) {
            HIP_DEBUG("hchain store already contains this hash length\n");

            err = i;
            goto out_err;
        }
    }

    // store the hash length
    err                                                                        = hcstore->num_hash_lengths[function_id];
    hcstore->hash_lengths[function_id][hcstore->num_hash_lengths[function_id]] = hash_length;
    hcstore->num_hash_lengths[function_id]++;

    HIP_DEBUG("hash length successfully registered\n");

out_err:
    return err;
}

/** registers a new hash structure length for utilization in the store
 *
 * @param       hcstore the store, where the hash structure length should be added
 * @param       function_id index to the hash function, where the structure length should be added
 * @param       hash_length_id index to the hash length, where the structure length should be added
 * @param       hitem_length hash length to be added
 * @return      returns the index to the hash structure length in the store,
 *          -1 if MAX_NUM_HCHAIN_LENGTH is reached
 */
int hcstore_register_hash_item_length(struct hchain_store *hcstore,
                                      const int function_id,
                                      const int hash_length_id,
                                      const int hitem_length)
{
    int      err = 0;
    unsigned i;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length_id >= 0
               && hash_length_id < (int) hcstore->num_hash_lengths[function_id]);
    HIP_ASSERT(hitem_length > 0);

    // first check that there's still some space left
    HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths
             == MAX_NUM_HCHAIN_LENGTH, -1, "space for hchain_length-storage is full\n");

    // also check if the hash length is already stored for this function
    for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
         num_hchain_lengths; i++) {
        if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
            == (unsigned) hitem_length) {
            HIP_DEBUG("hchain store already contains this hchain length\n");

            err = i;
            goto out_err;
        }
    }

    // store the hchain length
    err = hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths;
    hcstore->hchain_shelves[function_id][hash_length_id].
    hchain_lengths[hcstore->hchain_shelves[function_id][hash_length_id].
                   num_hchain_lengths] = hitem_length;
    hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths++;

    HIP_DEBUG("hchain length successfully registered\n");

out_err:
    return err;
}

/** registers additional hierarchy levels for utilization in the store
 *
 * @param       hcstore the store, where the hierarchy levels should be added
 * @param       function_id index to the hash function, where the structure length should be added
 * @param       hash_length_id index to the hash length, where the structure length should be added
 * @param       hitem_length hash length to be added
 * @param       addtional_hierarchies
 * @return      returns the hierarchy count, -1 if MAX_NUM_HIERARCHIES is reached
 */
int hcstore_register_hash_item_hierarchy(struct hchain_store *hcstore,
                                         const int function_id,
                                         const int hash_length_id,
                                         const int hitem_length,
                                         const int addtional_hierarchies)
{
    int      item_offset = -1;
    int      err         = 0;
    unsigned i;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length_id >= 0
               && hash_length_id < (int) hcstore->num_hash_lengths[function_id]);
    HIP_ASSERT(hitem_length > 0);
    HIP_ASSERT(addtional_hierarchies > 0);

    // first find the correct hchain item
    for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
         num_hchain_lengths; i++) {
        if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
            == (unsigned) hitem_length) {
            // set item_offset
            item_offset = i;

            break;
        }
    }

    // handle unregistered hchain length
    HIP_IFEL(item_offset < 0, -1, "hchain with unregistered hchain length requested\n");

    // first check that there's still enough space left
    HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].
             num_hierarchies[item_offset] + addtional_hierarchies >
             MAX_NUM_HIERARCHIES, -1,
             "insufficient space in hchain_hierarchies-storage\n");

    // add hierarchies
    hcstore->hchain_shelves[function_id][hash_length_id].
    num_hierarchies[item_offset] += addtional_hierarchies;
    err                           = hcstore->hchain_shelves[function_id][hash_length_id].
                                    num_hierarchies[item_offset];

    HIP_DEBUG("additional hchain hierarchies successfully registered\n");

out_err:
    return err;
}

/** helper function to refill the store
 *
 * @param       hcstore store to be refilled
 * @param       hash_func_id index to the hash function
 * @param       hash_length_id index to the hash length
 * @param       hchain_length_id index to the hash structure length
 * @param       hierarchy_level hierarchy level to be refilled, in case HHL is used
 * @param       update_higher_level needed for the recursion of the refill operation, start with 0
 * @param       use_hash_trees indicates whether hash chains or hash trees are stored
 * @return      number of created hash structures, -1 in case of an error
 */
static int hcstore_fill_item(struct hchain_store *hcstore,
                             const int hash_func_id,
                             const int hash_length_id,
                             const int hchain_length_id,
                             const int hierarchy_level,
                             const int update_higher_level,
                             const int use_hash_trees)
{
    struct hash_chain *hchain         = NULL;
    struct hash_tree  *htree          = NULL;
    struct hash_tree  *link_tree      = NULL;
    hash_function      hash_func      = NULL;
    int                hash_length    = 0;
    int                hchain_length  = 0;
    unsigned           create_hchains = 0;
    struct hash_chain *tmp_hchain     = NULL;
    struct hash_tree  *tmp_htree      = NULL;
    int                err            = 0;
    unsigned           i, j;

    // set necessary parameters
    hash_func     = hcstore->hash_functions[hash_func_id];
    hash_length   = hcstore->hash_lengths[hash_func_id][hash_length_id];
    hchain_length = hcstore->hchain_shelves[hash_func_id][hash_length_id].
                    hchain_lengths[hchain_length_id];

    // how many hchains are missing to fill up the item again
    create_hchains = hcstore->num_hchains_per_item
                     - hip_ll_get_size(&hcstore->hchain_shelves[hash_func_id][hash_length_id].
                                       hchains[hchain_length_id][hierarchy_level]);

    // only update if we reached the threshold or higher level update
    if ((create_hchains >= hcstore->refill_threshold * hcstore->num_hchains_per_item) ||
        update_higher_level) {
        if (hierarchy_level > 0) {
            /* if we refill a higher level, first make sure the lower levels
             * are full */
            HIP_IFEL((err = hcstore_fill_item(hcstore,
                                              hash_func_id,
                                              hash_length_id,
                                              hchain_length_id,
                                              hierarchy_level - 1,
                                              1,
                                              use_hash_trees)) < 0,
                     -1,
                     "failed to fill item\n");
        }

        // create one hchain at a time
        for (i = 0; i < create_hchains; i++) {
            // hierarchy level 0 does not use any link trees
            link_tree = NULL;

            if (hierarchy_level > 0) {
                // right now the trees only support hashes of 20 bytes
                HIP_ASSERT(hash_length == 20);

                // create a link tree for each hchain on level > 0
                link_tree = htree_init(hcstore->num_hchains_per_item, hash_length,
                                       hash_length, hash_length, NULL, 0);
                htree_add_random_secrets(link_tree);

                // lower items should be full by now
                HIP_ASSERT(hip_ll_get_size(&hcstore->hchain_shelves[hash_func_id][hash_length_id].hchains[hchain_length_id][hierarchy_level - 1])
                           == hcstore->num_hchains_per_item);

                // add the anchors of the next lower level as data
                for (j = 0; j < hcstore->num_hchains_per_item; j++) {
                    if (use_hash_trees) {
                        tmp_htree = hip_ll_get(&hcstore->hchain_shelves[hash_func_id][hash_length_id].hchains[hchain_length_id][hierarchy_level - 1],
                                               j);

                        htree_add_data(link_tree, tmp_htree->root, hash_length);
                    } else {
                        tmp_hchain = hip_ll_get(&hcstore->hchain_shelves[hash_func_id][hash_length_id].hchains[hchain_length_id][hierarchy_level - 1],
                                                j);

                        htree_add_data(link_tree, hchain_get_anchor(tmp_hchain),
                                       hash_length);
                    }
                }

                // calculate the tree
                htree_calc_nodes(link_tree, htree_leaf_generator,
                                 htree_node_generator, NULL);
            }

            if (use_hash_trees) {
                // create a new htree
                HIP_IFEL(!(htree = htree_init(hchain_length,
                                              hash_length,
                                              hash_length,
                                              0,
                                              link_tree,
                                              hierarchy_level)),
                         -1,
                         "failed to alloc memory or to init htree\n");
                HIP_IFEL(htree_add_random_data(htree, hchain_length),
                         -1,
                         "failed to add random secrets\n");

                // calculate the tree
                HIP_IFEL(htree_calc_nodes(htree,
                                          htree_leaf_generator,
                                          htree_node_generator,
                                          NULL),
                         -1,
                         "failed to calculate tree nodes\n");

                // add it as last element to have some circulation
                HIP_IFEL(hip_ll_add_last(&hcstore->hchain_shelves[hash_func_id][hash_length_id].hchains[hchain_length_id][hierarchy_level], htree),
                         -1, "failed to store new htree\n");
            } else {
                // create a new hchain
                HIP_IFEL(!(hchain = hchain_create(hash_func, hash_length,
                                                  hchain_length, hierarchy_level, link_tree)), -1,
                         "failed to create new hchain\n");

                // add it as last element to have some circulation
                HIP_IFEL(hip_ll_add_last(&hcstore->hchain_shelves[hash_func_id][hash_length_id].hchains[hchain_length_id][hierarchy_level], hchain),
                         -1, "failed to store new hchain\n");
            }
        }

        err += create_hchains;
    }

    HIP_DEBUG("created %i hchains on hierarchy level %i\n", err, hierarchy_level);

out_err:
    return err;
}

/** refills the store in case it contains less than ITEM_THRESHOLD * MAX_HCHAINS_PER_ITEM
 *  hash structures
 *
 * @param       hcstore store to be refilled
 * @param       use_hash_trees indicates whether hash chains or hash trees are stored
 * @return      number of created hash structures, -1 in case of an error
 */
int hcstore_refill(struct hchain_store *hcstore, const int use_hash_trees)
{
    int      err = 0;
    unsigned i, j, g, h;

    HIP_ASSERT(hcstore != NULL);

    /* go through the store setting up information necessary for creating a new
     * hchain in the respective item */
    for (i = 0; i < hcstore->num_functions; i++) {
        for (j = 0; j < hcstore->num_hash_lengths[i]; j++) {
            for (g = 0; g < hcstore->hchain_shelves[i][j].num_hchain_lengths; g++) {
                for (h = 0; h < hcstore->hchain_shelves[i][j].num_hierarchies[g]; h++) {
                    HIP_IFEL((err = hcstore_fill_item(hcstore, i, j, g, h, 0, use_hash_trees)) < 0,
                             -1, "failed to refill hchain_store\n");
                }
            }
        }
    }

    HIP_DEBUG("total amount of created hash-chains: %i\n", err);

out_err:
    return err;
}

/** gets a stored hash structure with the provided properties
 *
 * @param       hcstore store from which the hash structure should be returned
 * @param       function_id index of the hash function used to create the hash structure
 * @param       hash_length_id index of the hash length of the hash elements
 * @param       hchain_length length of the hash structure
 * @return      pointer to the hash structure, NULL in case of an error or no such structure
 */
void *hcstore_get_hash_item(struct hchain_store *hcstore,
                            const int function_id,
                            const int hash_length_id,
                            const int hchain_length)
{
    // inited to invalid values
    int      item_offset     = -1;
    void    *stored_item     = NULL;
    int      hierarchy_level = 0;
    int      err             = 0;
    unsigned i;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length_id >= 0
               && hash_length_id < (int) hcstore->num_hash_lengths[function_id]);
    HIP_ASSERT(hchain_length > 0);

    // first find the correct hchain item
    for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
         num_hchain_lengths; i++) {
        if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
            == (unsigned) hchain_length) {
            // set item_offset
            item_offset = i;

            break;
        }
    }

    // handle unregistered hchain length or hierarchy
    HIP_IFEL(item_offset < 0, -1,
             "hchain with unregistered hchain length or hierarchy level requested\n");

    // this exclusively returns a hchain from the highest hierarchy level
    hierarchy_level = hcstore->hchain_shelves[function_id][hash_length_id].
                      num_hierarchies[item_offset] - 1;

    HIP_DEBUG("hierarchy_level: %i\n", hierarchy_level);

    HIP_IFEL(!(stored_item = hip_ll_del_first(&hcstore->hchain_shelves[function_id]
                                              [hash_length_id].hchains[item_offset][hierarchy_level], NULL)), -1,
             "no hchain available\n");

out_err:
    if (err) {
        stored_item = NULL;
    }

    return stored_item;
}

/** gets a stored hash structure for the provided anchor element
 *
 * @param       hcstore store from which the hash structure should be returned
 * @param       function_id index of the hash function used to create the hash structure
 * @param       hash_length_id index of the hash length of the hash elements
 * @param       hierarchy_level hierarchy level at which the hash structure is located
 * @param       anchor the anchor element of the hash structure
 * @param       use_hash_trees indicates whether hash chains or hash trees are stored
 * @return      pointer to the hash structure, NULL in case of an error or no such structure
 */
void *hcstore_get_item_by_anchor(struct hchain_store *hcstore,
                                 const int function_id,
                                 const int hash_length_id,
                                 const int hierarchy_level,
                                 const unsigned char *anchor,
                                 const int use_hash_trees)
{
    struct hash_tree *htree       = NULL;
    void             *stored_item = NULL;
    int               hash_length = 0, err = 0;
    unsigned          i, j;

    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length_id >= 0
               && hash_length_id < (int) hcstore->num_hash_lengths[function_id]);
    HIP_ASSERT(hierarchy_level >= 0);
    HIP_ASSERT(anchor != NULL);

    hash_length = hcstore_get_hash_length(hcstore, function_id, hash_length_id);

    HIP_ASSERT(hash_length > 0);

    HIP_HEXDUMP("searching item with anchor: ", anchor, hash_length);

    for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
         num_hchain_lengths; i++) {
        // look for the anchor at each hchain_length with the respective hierarchy level
        HIP_ASSERT((unsigned) hierarchy_level < hcstore->hchain_shelves
                   [function_id][hash_length_id].num_hierarchies[i]);

        for (j = 0; j < hip_ll_get_size(&hcstore->hchain_shelves[function_id]
                                        [hash_length_id].hchains[i][hierarchy_level]); j++) {
            stored_item = hip_ll_get(&hcstore->
                                     hchain_shelves[function_id][hash_length_id].
                                     hchains[i][hierarchy_level], j);

            if (use_hash_trees) {
                htree = stored_item;

                if (!memcmp(anchor, htree->root, hash_length)) {
                    stored_item =
                        hip_ll_del(&hcstore->
                                   hchain_shelves[function_id][hash_length_id].
                                   hchains[i][hierarchy_level],
                                   j,
                                   NULL);

                    HIP_DEBUG("hash-tree matching the anchor found\n");

                    goto out_err;
                }
            } else if (!memcmp(anchor, hchain_get_anchor(stored_item), hash_length)) {
                stored_item = hip_ll_del(&hcstore->
                                         hchain_shelves[function_id][hash_length_id].
                                         hchains[i][hierarchy_level], j, NULL);

                HIP_DEBUG("hash-chain matching the anchor found\n");
                goto out_err;
            }
        }
    }

    HIP_ERROR("hash-chain matching the anchor NOT found\n");
    stored_item = NULL;
    err         = -1;

out_err:
    if (err) {
        stored_item = NULL;
    }

    return stored_item;
}

/** gets a pointer to the hash function for a given index
 *
 * @param       hcstore store from which the hash function should be returned
 * @param       function_id index of the hash function
 * @return      pointer to the hash function, NULL if no such hash function
 */
hash_function hcstore_get_hash_function(struct hchain_store *hcstore,
                                        const int function_id)
{
    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);

    return hcstore->hash_functions[function_id];
}

/** gets the hash length for a given index
 *
 * @param       hcstore store from which the hash length should be returned
 * @param       function_id index of the hash function
 * @param       hash_length_id index of the hash length
 * @return      the hash length, 0 if no such hash length
 */
int hcstore_get_hash_length(struct hchain_store *hcstore,
                            const int function_id,
                            const int hash_length_id)
{
    HIP_ASSERT(hcstore != NULL);
    HIP_ASSERT(function_id >= 0 && function_id < (int) hcstore->num_functions);
    HIP_ASSERT(hash_length_id >= 0
               && hash_length_id < (int) hcstore->num_hash_lengths[function_id]);

    return hcstore->hash_lengths[function_id][hash_length_id];
}

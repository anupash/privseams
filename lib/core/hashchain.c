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
 * API for a hash chain API
 *
 * @brief API for a hash chain API
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "debug.h"
#include "hashtree.h"
#include "ife.h"
#include "hashchain.h"

/** checks if a hash is verifiable by a hash chain
 *
 * @param       current_hash the hash value to be verified
 * @param       last_hash the last known hash value
 * @param       hash_func the hash function to be used
 * @param       hash_length length of the hash values
 * @param       tolerance the maximum number of hash calculations
 * @param       secret the potentially incorporated secret
 * @param       secret_length length og the secret
 * @return      hash distance if the hash authentication was successful, 0 otherwise
 */
int hchain_verify(const unsigned char *current_hash,
                  const unsigned char *last_hash,
                  const hash_function hash_func,
                  const int hash_length,
                  const int tolerance,
                  const unsigned char *secret,
                  const int secret_length)
{
    /* stores intermediate hash results and allow to concat
     * with a secret at each step */
    unsigned char buffer[MAX_HASH_LENGTH + secret_length];
    int           err = 0, i;

    HIP_ASSERT(current_hash != NULL && last_hash != NULL);
    HIP_ASSERT(hash_func != NULL);
    HIP_ASSERT(hash_length > 0 && tolerance >= 0);

    // init buffer with the hash we want to verify
    memcpy(buffer, current_hash, hash_length);

    if (secret && secret_length > 0) {
        HIP_HEXDUMP("secret: ", secret, secret_length);
    }

    for (i = 1; i <= tolerance; i++) {
        // add the secret
        if (secret != NULL && secret_length > 0) {
            memcpy(&buffer[hash_length], secret, secret_length);
        }

        hash_func(buffer, hash_length + secret_length, buffer);

        // compare the elements
        if (!(memcmp(buffer, last_hash, hash_length))) {
            HIP_DEBUG("hash verfied\n");

            err = i;
            goto out_err;
        }
    }

    HIP_DEBUG("no matches found within tolerance: %i!\n", tolerance);

out_err:
    return err;
}

/** creates a new hash chain
 *
 * @param       hash_func hash function to be used to generate the hash values
 * @param       hash_length length of the hash values
 * @param       hchain_length number of hash elements
 * @param       hchain_hierarchy the hierarchy level this hash chain will belong to
 * @param       link_tree the link tree, if HHL is used
 * @return  pointer to the newly created hash chain, NULL on error
 */
struct hash_chain *hchain_create(const hash_function hash_func,
                                 const int hash_length,
                                 const int hchain_length,
                                 const int hchain_hierarchy,
                                 struct hash_tree *link_tree)
{
    struct hash_chain *hchain = NULL;
    /* the hash function output might be longer than needed
     * allocate enough memory for the hash function output
     *
     * @note we also allow a concatenation with the link tree root and the jump chain element here */
    unsigned char hash_value[3 * MAX_HASH_LENGTH];
    int           hash_data_length = 0;
    int           i, err = 0;

    HIP_ASSERT(hash_func != NULL);
    // make sure that the hash we want to use is smaller than the max output
    HIP_ASSERT(hash_length > 0 && hash_length <= MAX_HASH_LENGTH);
    HIP_ASSERT(hchain_length > 0);
    HIP_ASSERT(!(hchain_hierarchy == 0 && link_tree));

    // allocate memory for a new hash chain
    HIP_IFEL(!(hchain = calloc(1, sizeof(struct hash_chain))), -1,
             "failed to allocate memory\n");

    // allocate memory for the hash chain elements
    HIP_IFEL(!(hchain->elements = calloc(1, hash_length * hchain_length)),
             -1, "failed to allocate memory\n");

    // set the link tree if we are using different hierarchies
    if (link_tree) {
        hchain->link_tree = link_tree;
        hash_data_length  = 2 * hash_length;
    } else {
        hchain->link_tree = NULL;
        hash_data_length  = hash_length;
    }

    for (i = 0; i < hchain_length; i++) {
        if (i > 0) {
            // (input, input_length, output) -> output_length == 20
            HIP_IFEL(!(hash_func(hash_value, hash_data_length, hash_value)), -1,
                     "failed to calculate hash\n");
            // only consider highest bytes of digest with length of actual element
            memcpy(&hchain->elements[i * hash_length], hash_value, hash_length);
        } else {
            // random bytes as seed -> need a copy in hash_value for further computations
            HIP_IFEL(RAND_bytes(hash_value, hash_length) <= 0, -1,
                     "failed to get random bytes for source element\n");

            memcpy(&hchain->elements[i * hash_length], hash_value, hash_length);
        }

        /* concatenate used part of the calculated hash with the link tree root */
        if (link_tree) {
            memcpy(&hash_value[hash_length], link_tree->root, link_tree->node_length);
        }
    }

    hchain->hash_function    = hash_func;
    hchain->hash_length      = hash_length;
    hchain->hchain_length    = hchain_length;
    hchain->current_index    = hchain_length;
    hchain->hchain_hierarchy = hchain_hierarchy;

    HIP_DEBUG("Hash-chain with %i elements of length %i created!\n",
              hchain_length,
              hash_length);

out_err:
    if (err) {
        // hchain was fully created
        hchain_free(hchain);
        hchain = NULL;
    }

    return hchain;
}

/* getter function for a specific element of the given hash chain
 *
 * @param       hash_chain hash chain from which the element should be returned
 * @param       idx index to the hash chain element
 * @return      element of the given hash chain
 */
static unsigned char *hchain_element_by_index(const struct hash_chain *hash_chain,
                                              const int idx)
{
    unsigned char *element = NULL;
    int            err     = 0;

    HIP_ASSERT(hash_chain);

    if (idx >= 0 && idx < hash_chain->hchain_length) {
        element = &hash_chain->elements[idx * hash_chain->hash_length];
    } else {
        HIP_ERROR("Element from uninited hash chain or out-of-bound element requested!");

        err = -1;
        goto out_err;
    }

    HIP_HEXDUMP("Hash chain element: ", element, hash_chain->hash_length);

out_err:
    if (err) {
        element = NULL;
    }

    return element;
}

/* getter function for the hash chain anchor element
 *
 * @param       hash_chain hash chain from which the anchor should be returned
 * @return      anchor element of the given hash chain
 */
unsigned char *hchain_get_anchor(const struct hash_chain *hash_chain)
{
    HIP_ASSERT(hash_chain);

    return hchain_element_by_index(hash_chain, hash_chain->hchain_length - 1);
}

/* getter function for the hash chain seed element
 *
 * @param       hash_chain hash chain from which the seed should be returned
 * @return      seed element of the given hash chain
 */
unsigned char *hchain_get_seed(const struct hash_chain *hash_chain)
{
    HIP_ASSERT(hash_chain);

    return hchain_element_by_index(hash_chain, 0);
}

/** returns the next element of the hash chain but does not advance the current element
 * pointer. This function should only be used if the next element is kept secret and has to
 * be used for special purposes like message signatures.
 *
 * @param       hash_chain the hash chain
 * @return      next element of the hash chain or NULL if the hash chain reached boundary
 */
static unsigned char *hchain_next(const struct hash_chain *hash_chain)
{
    unsigned char *element = NULL;

    element = hchain_element_by_index(hash_chain, hash_chain->current_index - 1);

    return element;
}

/** removes and returns the next element from the hash chain advances current element pointer
 *
 * @param       hash_chain hash chain which has to be popped
 * @return      pointer to the next hashchain element or NULL if the hash chain is depleted
 */
unsigned char *hchain_pop(struct hash_chain *hash_chain)
{
    unsigned char *element = NULL;

    HIP_ASSERT(hash_chain);

    element = hchain_next(hash_chain);
    hash_chain->current_index--;

    return element;
}

/** delete hash chain and free memory
 *
 * @param       hash_chain hash chain which should be removed
 * @return      always 0
 */
int hchain_free(struct hash_chain *hash_chain)
{
    int err = 0;

    if (hash_chain) {
        htree_free(hash_chain->link_tree);
        hash_chain->link_tree = NULL;

        free(hash_chain->elements);
        free(hash_chain);
    }

    HIP_DEBUG("all hash-chain elements and dependencies freed\n");

    return err;
}

/** accessor function which returns the number of remaining hash chain elements
 *
 * @param       hash_chain the hash chain
 * @return      number of remaining elements
 */
int hchain_get_num_remaining(const struct hash_chain *hash_chain)
{
    return hash_chain->current_index;
}

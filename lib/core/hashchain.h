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
 *
 * @author Tobias Heer <heer@tobobox.de>
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_LIB_CORE_HASHCHAIN_H
#define HIP_LIB_CORE_HASHCHAIN_H

#include <stdlib.h>
#include <openssl/sha.h>

#include "hashtree.h"

/* longest digest in openssl lib */
#ifdef SHA512_DIGEST_LENGTH
#define MAX_HASH_LENGTH SHA512_DIGEST_LENGTH
#else
#define MAX_HASH_LENGTH 64
#endif

/* hash function used for the creation and verification of the hash chain */
typedef unsigned char * (*hash_function)(const unsigned char *,
                                         unsigned long,
                                         unsigned char *);

struct hash_chain {
    /* pointer to the hash-function used to create and verify the hchain
     *
     * @note params: (in_buffer, in_length, out_buffer)
     * @note out_buffer should be size MAX_HASH_LENGTH */
    hash_function     hash_function;
    int               hash_length; /* length of the hashes, of which the hchain consist */
    int               hchain_length; /* number of initial elements in the hash-chain */
    int               hchain_hierarchy; /* hierarchy this hchain belongs to */
    int               current_index; /* index to currently revealed element for hchain traversal*/
    unsigned char    *elements;    /* array containing the elements of the hash chain*/
    struct hash_tree *link_tree;   /* pointer to a hash tree for linking hchains */
};

int hchain_verify(const unsigned char *current_hash,
                  const unsigned char *last_hash,
                  const hash_function hash_function,
                  const int hash_length,
                  const int tolerance,
                  const unsigned char *secret,
                  const int secret_length);
struct hash_chain *hchain_create(const hash_function hash_function,
                                 const int hash_length,
                                 const int hchain_length,
                                 const int hchain_hierarchy,
                                 struct hash_tree *link_tree);
unsigned char *hchain_get_anchor(const struct hash_chain *hash_chain);
unsigned char *hchain_get_seed(const struct hash_chain *hash_chain);
unsigned char *hchain_pop(struct hash_chain *hash_chain);
int hchain_free(struct hash_chain *hash_chain);
int hchain_get_num_remaining(const struct hash_chain *hash_chain);

#endif /* HIP_LIB_CORE_HASHCHAIN_H */

/**
 * Hash chain functions for packet authentication and
 * packet signatures
 *
 * Description:
 *
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2006
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef HASH_CHAIN_H
#define HASH_CHAIN_H

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "hashtree.h"

/* longest digest in openssl lib */
#ifdef SHA512_DIGEST_LENGTH
# define MAX_HASH_LENGTH SHA512_DIGEST_LENGTH
#else
# define MAX_HASH_LENGTH 64
#endif

/* hash function used for the creation and verification of the hash chain */
typedef unsigned char * (*hash_function_t)(const unsigned char *, size_t,
		unsigned char *);

typedef struct hash_chain
{
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	hash_function_t hash_function;
	int hash_length;	/* length of the hashes, of which the hchain consist */
	int hchain_length;	/* number of initial elements in the hash-chain */
	int hchain_hierarchy; /* hierarchy this hchain belongs to */
	int current_index; /* index to currently revealed element for hchain traversal*/
	unsigned char * elements; /* array containing the elements of the hash chain*/
	hash_tree_t *link_tree; /* pointer to a hash tree for linking hchains */
} hash_chain_t;


void hchain_print(const hash_chain_t * hash_chain);
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		const hash_function_t hash_function, const int hash_length, const int tolerance,
		const unsigned char *secret, const int secret_length);
hash_chain_t * hchain_create(const hash_function_t hash_function, const int hash_length,
		const int hchain_length, const int hchain_hierarchy, hash_tree_t *link_tree);
unsigned char * hchain_get_anchor(const hash_chain_t *hash_chain);
unsigned char * hchain_get_seed(const hash_chain_t *hash_chain);
unsigned char * hchain_element_by_index(const hash_chain_t *hash_chain, const int index);
unsigned char * hchain_next(const hash_chain_t *hash_chain);
unsigned char * hchain_previous(const hash_chain_t * hash_chain);
int hchain_set_current_index(hash_chain_t *hash_chain, const int index);
unsigned char * hchain_current(const hash_chain_t *hash_chain);
unsigned char * hchain_pop(hash_chain_t * hash_chain);
unsigned char * hchain_push(hash_chain_t * hash_chain);
int hchain_reset(hash_chain_t *hash_chain);
int hchain_free(hash_chain_t *hash_chain);
int hchain_get_num_remaining(const hash_chain_t * hash_chain);

#endif /*HASH_CHAIN_H*/

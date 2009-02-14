/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
* In the current version hash-chains created with any hash-function, which
* output is <= 20 bytes are supported.
*
* Authors:
*   - Tobias Heer <heer@tobobox.de> 2006
*  * Licence: GNU/GPL
*
*/
#ifndef HASH_CHAIN_H
#define HASH_CHAIN_H

//#include <sys/types.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "hashtree.h"
//#include "debug.h"

/* biggest digest in openssl lib */
#ifdef SHA512_DIGEST_LENGTH
# define MAX_HASH_LENGTH SHA512_DIGEST_LENGTH
#else
# define MAX_HASH_LENGTH 64
#endif

typedef unsigned char * (*hash_function_t)(const unsigned char *, size_t,
		unsigned char *);

typedef struct hash_chain_element
{
	unsigned char *hash;
	struct hash_chain_element *next;
} hash_chain_element_t;

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
	int remaining;		/* remaining elements int the hash-chain */
	hash_chain_element_t *current_element;
	hash_chain_element_t *source_element;	/* seed - first element */
	hash_chain_element_t *anchor_element;	/* anchor - last element */
	hash_tree_t *link_tree; /* pointer to a hash tree for linking hchains */
} hash_chain_t;


void hchain_print(const hash_chain_t * hash_chain);

/* check if a hash is part of a hash chain */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		hash_function_t hash_function, int hash_length, int tolerance,
		unsigned char *secret, int secret_length);

/* create a new hash chain on the heap */
hash_chain_t * hchain_create(hash_function_t hash_function, int hash_length,
		int hchain_length, int hchain_hierarchy, hash_tree_t *link_tree);

/* remove and return the next element from the hash chain */
unsigned char * hchain_pop(hash_chain_t * hash_chain);

/* return the next element from the hash chain */
unsigned char * hchain_next(const hash_chain_t *hash_chain);

/* return the current element from the hash chain */
unsigned char * hchain_current(const hash_chain_t *hash_chain);

/* delete hash chain and free memory */
int hchain_free(hash_chain_t *hash_chain);

int hchain_get_num_remaining(const hash_chain_t * hash_chain);

#if 0
/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length,
		int num_parts);
#endif

#endif /*HASH_CHAIN_H*/

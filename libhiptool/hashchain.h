/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
*  * Licence: GNU/GPL
*
*/
#ifndef HASH_CHAIN_H
#define HASH_CHAIN_H

#include <inttypes.h>
#include <openssl/sha.h>

/* value used by Tobias Heer */
//#define HCHAIN_ELEMENT_LENGTH 20 // (in bytes)

// modify this when changing the hash function
#define MAX_HASH_LENGTH SHA_DIGEST_LENGTH

typedef struct hash_chain hash_chain_t;
typedef struct hash_chain_element hash_chain_element_t;

struct hash_chain_element
{
	unsigned char *hash;
	hash_chain_element_t *next;
};

struct hash_chain
{
	int hchain_length;	/* number of initial elements in the hash-chain */
	int remaining;	/* remaining elements int the hash-chain */
	hash_chain_element_t *current_element;
	hash_chain_element_t *source_element; /* seed - first element */
	hash_chain_element_t *anchor_element; /* anchor - last element */
};

void hchain_print(const hash_chain_t * hash_chain, int hash_length);
void hexdump(const unsigned char * const buffer, int length);

/* check if a hash is part of a hash chain */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		int hash_length, int tolerance);

/* create a new hash chain on the heap */
int hchain_create(int hchain_length, int hash_length, hash_chain_t *out_hchain);

/* remove and return the next element from the hash chain */
int hchain_pop(hash_chain_t * hash_chain, int hash_length, unsigned char *popped_hash);

/* return the next element from the hash chain */
int hchain_next(const hash_chain_t *hash_chain, int hash_length, unsigned char *next_hash);

/* return the current element from the hash chain */
int hchain_current(const hash_chain_t *hash_chain, int hash_length,
		unsigned char *current_hash);

/* delete hash chain and free memory */
int hchain_destruct(hash_chain_t *hash_chain);

int hchain_get_num_remaining(const hash_chain_t * hash_chain);

/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length,
		int num_parts);
#endif /*HASH_CHAIN_H*/

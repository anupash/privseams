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

// default length of the hash function output used in the chain
#define DEFAULT_HASH_LENGTH 4 // (in bytes)
#define DEFAULT_SALT_LENGTH 0 // (in bytes)
/* value used by Tobias Heer */
//#define HCHAIN_ELEMENT_LENGTH 20 // (in bytes)

// change this, if you are changing the hash function
#define MAX_HASH_LENGTH SHA_DIGEST_LENGTH

#define HCHAIN_VERIFY_WINDOW 10

typedef struct hash_chain hash_chain_t;
typedef struct hash_chain_element hash_chain_element_t;
typedef struct hash_item hash_item_t;

struct hash_chain_element
{
	unsigned char *hash;
	hash_chain_element_t *next;
};

struct hash_chain
{
	int hchain_length;	/* number of initial elements in the hash-chain */
	uint8_t hash_length;	/* length of the hash itself */
	uint8_t salt_length;	/* length of the salt used when calculating the elements */
	int remaining;	/* remaining elements int the hash-chain */
	hash_chain_element_t *current_element;
	hash_chain_element_t *source_element; /* seed - first element */
	hash_chain_element_t *anchor_element; /* anchor - last element */
};

struct hash_item
{
	uint8_t hash_length; /* length of the hash in bytes */
	uint8_t salt_length; /* length of the salt in bytes */
	unsigned char *hash; /* the hash value including the salt */
};

/* create a new hash chain on the heap */
hash_chain_t * hchain_create(int length);

/* remove and return the next element from the hash chain */
hash_item_t * hchain_pop(hash_chain_t * hash_chain);

/* return the next element from the hash chain */
hash_chain_element_t  * hchain_next(hash_chain_t * hash_chain);

/* return the current element from the hash chain */
hash_item_t * hchain_current(hash_chain_t * hash_chain);


/* check if a hash is part of a hash chain */
int hchain_verify(const hash_item_t * hash_item, const hash_item_t * last_item,
		int tolerance);

/* delete hash chain and free memory */
int hchain_destruct(hash_chain_t *hash_chain);

void hchain_print(hash_chain_t *hash_chain);

// for testing
void hexdump(const unsigned char * const buffer, int length);

int hchain_get_num_remaining(hash_chain_t * hash_chain);

/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length, int num_parts);
#endif /*HASH_CHAIN_H*/

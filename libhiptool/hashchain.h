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

// output length of hash function
// TODO make more modular to support both use cases
#define HCHAIN_ELEMENT_LENGTH 4 // (in bytes)
/* value used by Tobias */
//#define HCHAIN_ELEMENT_LENGTH 20 // (in bytes)

typedef struct hash_chain hash_chain_t;
typedef struct hash_chain_element hash_chain_element_t;


struct hash_chain_element{
	unsigned char *hash;
	/* TODO add salt for each element -> should not be revealed only
	 * once during signaling traffic as this would give more time for
	 * pre-calculation in attack scenario */
	hash_chain_element_t *next;
};

struct hash_chain{
	int length;	/* total length */
	int remaining;	/* remaining elements */
	hash_chain_element_t *current_element;
	hash_chain_element_t *source_element; /* seed - first element */
	hash_chain_element_t *anchor_element; /* anchor - last element */
};

/* create a new hash chain on the heap */
hash_chain_t * hchain_create(int length);

/* remove and return the next element from the hash chain */
hash_chain_element_t  * hchain_pop(hash_chain_t * hash_chain);

/* return the next element from the hash chain */
hash_chain_element_t  * hchain_next(hash_chain_t * hash_chain);

/* return the current element from the hash chain */
hash_chain_element_t  * hchain_current(hash_chain_t * hash_chain);


/* check if a hash is part of a hash chain */
int hchain_verify(const unsigned char * hash, const unsigned char * last_hash, int tolerance);

/* delete hash chain and free memory */
int hchain_destruct(hash_chain_t *hash_chain);

void hchain_print(hash_chain_t *hash_chain);

// for testing
void hexdump(const unsigned char * const buffer, int length);

int hchain_get_num_remaining(hash_chain_t * hash_chain);

/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length, int num_parts);
#endif /*HASH_CHAIN_H*/

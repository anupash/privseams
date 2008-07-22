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

#include <sys/types.h>
#include <openssl/sha.h>



/* Hash-functions with longer output than SHA1 are easily supported
 * by increasing this. Right now there is no need to increase the buffer.
 *
 * @note this does not influence the amount of the memory used for a
 *       hash-chain
 * @note hash-lengths of hash-functions used right now when
 *       creating hash-chains:
 *       MD5_DIGEST_LENGTH == 16
 *       SHA_DIGEST_LENGTH == 20
 */
#define MAX_HASH_LENGTH SHA_DIGEST_LENGTH


typedef struct hash_chain_element hash_chain_element_t;
typedef struct hash_chain hash_chain_t;

struct hash_chain_element
{
	unsigned char *hash;
	hash_chain_element_t *next;
};

struct hash_chain
{
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	unsigned char * (*hash_function)(const unsigned char *, unsigned long,
			unsigned char *);
	int hash_length;	/* length of the hashes, of which the hchain consist */
	int hchain_length;	/* number of initial elements in the hash-chain */
	int remaining;		/* remaining elements int the hash-chain */
	hash_chain_element_t *current_element;
	hash_chain_element_t *source_element;	/* seed - first element */
	hash_chain_element_t *anchor_element;	/* anchor - last element */
};

void hchain_print(const hash_chain_t * hash_chain, int hash_length);

/* check if a hash is part of a hash chain */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		unsigned char * (*hash_function)(const unsigned char *, unsigned long, unsigned char *),
		int hash_length, int tolerance);

/* create a new hash chain on the heap */
hash_chain_t *hchain_create(int hchain_length, int hash_length);

/* remove and return the next element from the hash chain */
unsigned char * hchain_pop(hash_chain_t * hash_chain, int hash_length);

/* return the next element from the hash chain */
unsigned char * hchain_next(const hash_chain_t *hash_chain, int hash_length);

/* return the current element from the hash chain */
unsigned char * hchain_current(const hash_chain_t *hash_chain, int hash_length);

/* delete hash chain and free memory */
int hchain_destruct(hash_chain_t *hash_chain);

int hchain_get_num_remaining(const hash_chain_t * hash_chain);

/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length,
		int num_parts);
#endif /*HASH_CHAIN_H*/

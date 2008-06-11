/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobibox.de> 2006
*  * Licence: GNU/GPL
*
*/
#include "hashchain.h"
#include <assert.h>
#include <stdlib.h>			// malloc & co
#include <stdio.h> 			// printf & comalloc & co.
#include <openssl/rand.h>		
#include <openssl/sha.h>
#include <string.h>			// memcpy


#define TRUE  1
#define FALSE 0

/* these are not needed and therefore not implemented
   right now but they should be used where necessary */
#define HCHAIN_LOCK(lock_id)
#define HCHAIN_UNLOCK(lock_id)


void hchain_print(hash_chain_t * hash_chain){
	if(hash_chain){
		
		hash_chain_element_t *current_element;
		printf("Hash chain: %d\n", (int) hash_chain);
		printf("Current element: ");
		
		if(hash_chain->current_element != NULL){
			hexdump(hash_chain->current_element->hash, HCHAIN_ELEMENT_LENGTH);
		}else{
			printf(" -- hash chain not in use -- ");
		}
		printf("\n");
		printf("Remaining elements: %d\n", hchain_get_num_remaining(hash_chain));
		printf(" - Contents:\n");
		int i;
		for(current_element = hash_chain->anchor_element, i=0;
		current_element != NULL;
		current_element = current_element->next, i++){
			if(hash_chain->length - hash_chain->remaining < i+1){
				printf("(+)");
			}else{
				printf("(-)");
			}
			printf("%2d: ", i);
			hexdump(current_element->hash, HCHAIN_ELEMENT_LENGTH);
			printf("\n");
		}
	}else{
		printf("Given hash chain was NULL!");	
	}
	
}

/**
 * hexdump - prints a string as hexadecimal characters.
 * @buffer: buffer to print
 * @length: Length of the buffer (in bytes)
 */
void hexdump(const unsigned char * const buffer, int length){
	if( buffer == NULL ){
		printf("hexdump: NULL BUFFER GIVEN!!!!\n");
		
	}else{ 
		int i;
		for(i = 0; i < length; i++){
			printf("%02X", (unsigned char) buffer[i]);
		}
	}
}

/**
 * hash_chain_verify - verify if the given hash is part of a hash chain
 * @hash: the given hash value
 * @last_hash: the last known hash value
 * @tolerance: The tolerance limit determines how many steps may be missing in the hash chain
 *             0 means that only sequential hash values are considered as valid.
 * @return: returns 1 if the hash authentication was successfull, 0 otherwise
 */
int hchain_verify(const unsigned char * hash, const unsigned char * last_hash, int tolerance){
	
	assert(tolerance >= 0);
	assert(hash != NULL && last_hash != NULL);
	
	int i;
	unsigned char *buffer = NULL;
	unsigned char *hash_value = NULL;
	
	buffer = (unsigned char*) malloc(HCHAIN_ELEMENT_LENGTH);
	hash_value = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
	
	// init buffer with the hash we want to verify
	memcpy(buffer, hash, HCHAIN_ELEMENT_LENGTH);
	
	printf("Compare old: ");
	hexdump(last_hash, HCHAIN_ELEMENT_LENGTH);
	printf("\nto new: ");
	hexdump(buffer, HCHAIN_ELEMENT_LENGTH);
	printf("\n");
	
	// TODO free hashes
	
	for(i = 0; i < tolerance - 1; i++){
		//printf("Calculating round %2d: ", i + 1);
		SHA1(buffer, HCHAIN_ELEMENT_LENGTH, hash_value);
		memcpy(buffer, hash_value, HCHAIN_ELEMENT_LENGTH);
		//hexdump(buffer, HCHAIN_ELEMENT_LENGTH);
		//printf(" <-> ");
		//hexdump(last_hash, HCHAIN_ELEMENT_LENGTH);
		//printf("\n");
		
		// compare the elements
		if(memcmp(buffer, last_hash, HCHAIN_ELEMENT_LENGTH) == 0){
			return TRUE;
		}
	}
	return FALSE;
}



/**
 * hchain_create - create a new hash chain of a certain length 
 * @length: number of hash entries
 * @return: returns a pointer to the newly created hash_chain
 */
hash_chain_t * hchain_create(int length)
{
	
	hash_chain_element_t *last_element = NULL, *current_element = NULL;
	int i;
	
	// the hash function output might be longer than needed
	// allocate enough memory for the hash function output
	unsigned char *hash_value = NULL;
	hash_value = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	
	// allocate memory for a new hash chain
	hash_chain_t* hash_chain;
	hash_chain = (hash_chain_t*)malloc(sizeof(hash_chain_t));
	
	for(i = 0; i < length; i++){
		
		// allocate memory for a new element 
		current_element = (hash_chain_element_t*)malloc(sizeof(hash_chain_element_t));
		current_element->hash = (unsigned char*)malloc(HCHAIN_ELEMENT_LENGTH);
		
		if(last_element != NULL){
			// (input, input-length, output -> length == 20)
			SHA1(last_element->hash, HCHAIN_ELEMENT_LENGTH, hash_value);
			// only consider HCHAIN_ELEMENT_LENGTH highest bytes
			memcpy(current_element->hash, hash_value, HCHAIN_ELEMENT_LENGTH);
		}else{
			/* TODO delete this after taking the measurements */
			// we need some deterministic seed as we don't exchange the anchors
			memset(current_element->hash, 0, HCHAIN_ELEMENT_LENGTH);
			// random bytes as seed
			//RAND_bytes(current_element->hash, HCHAIN_ELEMENT_LENGTH);
			hash_chain->source_element = current_element;
		}
		
		// list with backwards links
		current_element->next = last_element;
		last_element = current_element;
	}
	
	hash_chain->length    = length;
	hash_chain->remaining = length;
	// hash_chain->source_element set above
	hash_chain->anchor_element  = current_element;
	hash_chain->current_element = NULL;
	
	free(hash_value);
	hash_value = NULL;
	last_element = NULL;
	current_element = NULL;
	
	printf("hchain_create: Hash-chain with %i elements created!\n", length);
	
	return hash_chain;
}

/**
 * hchain_pop - return the next element in a hash chain
 * 		and move the current_element pointer forward
 * @hash_chain: the hash chain which has to be popped
 * @return: pointer to the current hash_chain element
 */
hash_chain_element_t  * hchain_pop(hash_chain_t * hash_chain){
	
	if(hash_chain == NULL){
		printf("hchain_pop: Given pointer is NULL.\n");
		exit(1);
	}
	hash_chain_element_t * return_element;
	HCHAIN_LOCK(&hash_chain);  
	if( hash_chain->current_element != NULL){
		// hash chain already in use
		if( hash_chain->current_element->next == NULL ){
			return_element = NULL;
			printf("hchain_next: Hash chain depleted!\n");
			exit(1);
		}else{
			return_element = hash_chain->current_element->next;
		}
	}else{
		// hash_chain unused yet
		return_element = hash_chain->anchor_element;
	}
	
	hash_chain->current_element = return_element;
	hash_chain->remaining--;
	HCHAIN_UNLOCK(&hash_chain);
	printf("Popping Hash chain element: ");
	hexdump(return_element->hash, HCHAIN_ELEMENT_LENGTH);
	printf("\n");
	return return_element;
	
	
}

/**
 * hchain_next - returns the next element of the hash chain but does not advance the current_element
 * pointer. This function should only be used if the next element is kept secret and has to 
 * be used for special puroses like message signatures.
 * @hash_chain: the hash chain 
 * @return: next element of the hash chain or NULL if the hash chain is depleted.
 */
hash_chain_element_t  * hchain_next(hash_chain_t * hash_chain){
	
	if(hash_chain == NULL){
		printf("hchain_next: Given pointer is NULL.\n");
		exit(1);
	}
	
	hash_chain_element_t * return_element;
	if( hash_chain->current_element != NULL){
		// hash chain already in use
		if( hash_chain->current_element->next == NULL ){
			// hash chain depleted. return NULL
			printf("hchain_next: Hash chain depleted!\n");
			exit(1);
			return_element = NULL;
		}else{
			// hash chain in use: return next.
			return hash_chain->current_element->next;
		}
	}else{
		// hash_chain is unused. return the anchor element
		return hash_chain->anchor_element;
	}
	// every execution path must have a return value. This will never happen.
	return NULL;
}

/**
 * hchain_current - returns the current element of the hash chain 
 * @hash_chain: the hash chain 
 * @return: current element of the hash chain or NULL if the hash chain is depleted.
 */
hash_chain_element_t  * hchain_current(hash_chain_t * hash_chain){
	
	if(hash_chain == NULL){
		printf("hchain_next: Given pointer is NULL.\n");
		exit(1);
	}
	if(hash_chain->current_element == NULL){
		printf("hchain_next: Current element is NULL.\n");
		exit(1);
	}
	return hash_chain->current_element;
}



/**
 * hchain_destruct - delete hash chain and free memory
 * @hash_chain: the hash chain which has to be removed
 * @return: 0 in case of success
 */
int hchain_destruct(hash_chain_t *hash_chain)
{
	if( hash_chain != NULL ){
		hash_chain_element_t *current_element;
		for(current_element = hash_chain->anchor_element;
		    current_element != NULL;
		    current_element = current_element->next){
			free(current_element->hash);
			free(current_element);
		}
		free(hash_chain);
	}
	return 0;
}

/** 
 * hchain_get_num_remaining - accessor function which returns the number of remaining hash chain 
 * elements
 * @hash_chain: the hash chain
 * @return: number of remaining elements
 **/
int hchain_get_num_remaining(hash_chain_t * hash_chain){
	return hash_chain->remaining;
}

/*************** Helper functions ********************/
/** 
 * concat_n_hash_SHA - concatenate various strings and hash them
 * @hash: return value. Needs to be an empty buffer with HIP_HASH_SHA_LEN bytes memory
 * @parts: array with byte strings
 * @part_length: length of each byte string
 * @num_parts: number of parts
 * @return: zero on success, non-zero otherwise
 **/
int concat_n_hash_SHA(unsigned char* hash, unsigned char** parts, int* part_length, int num_parts){
	
	int total_len = 0, position = 0, i;
	unsigned char* buffer = NULL;
	
	/* add up the part lengths */
	for(i = 0; i < num_parts; i++){
		total_len += part_length[i];
		printf("Part %d [%d]:\n",i, part_length[i]);
		hexdump(parts[i], part_length[i]);
		printf("\n");
	}
	printf("%d parts, %d bytes\n", num_parts, total_len);
	/* allocate buffer space */
	buffer = malloc(total_len);
	if(buffer == NULL ) return -1; 
	/* copy the parts to the buffer */
	for(i = 0; i < num_parts; i++){
		memcpy(buffer + position, parts[i], part_length[i]); 
		position += part_length[i];
	}
	printf("Buffer:");
	hexdump( buffer, total_len);
	printf("\n");
	/* hash the buffer */
	// TODO get this right
	SHA(buffer, total_len, hash);
	printf("Buffer:");
	printf("\n");

	/* free buffer memory*/ 
	if(buffer) free(buffer);
	return 0;
}

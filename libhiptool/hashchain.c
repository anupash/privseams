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
#include <string.h>			// memcpy
#include "debug.h"
#include "ife.h"

/* these are not needed and therefore not implemented
   right now but they should be used where necessary */
#define HCHAIN_LOCK(lock_id)
#define HCHAIN_UNLOCK(lock_id)

void hchain_print(const hash_chain_t * hash_chain, int hash_length)
{
	hash_chain_element_t *current_element = NULL;
	int i;
	
	if(hash_chain)
	{	
		printf("Hash chain: %d\n", (int) hash_chain);
		printf("Current element: ");
		
		if(hash_chain->current_element != NULL)
		{
			hexdump(hash_chain->current_element->hash, hash_length);
		} else
		{
			printf(" -- hash chain not in use -- ");
		}
		
		printf("\n");
		printf("Remaining elements: %d\n", hchain_get_num_remaining(hash_chain));
		printf(" - Contents:\n");
		
		for(current_element = hash_chain->anchor_element, i=0;
				current_element != NULL;
				current_element = current_element->next, i++)
		{
			if(hash_chain->hchain_length - hash_chain->remaining < i+1)
			{
				printf("(+)");
			} else
			{
				printf("(-)");
			}
			
			printf("%2d: ", i);
			hexdump(current_element->hash, hash_length);
			printf("\n");
		}
	} else
	{
		printf("Given hash chain was NULL!");	
	}
}

/**
 * hexdump - prints a string as hexadecimal characters.
 * @buffer: buffer to print
 * @length: Length of the buffer (in bytes)
 */
void hexdump(const unsigned char * const buffer, int length)
{
	if( buffer == NULL )
	{
		printf("hexdump: NULL BUFFER GIVEN!!!!\n");
		
	} else
	{ 
		int i;
		for(i = 0; i < length; i++)
		{
			printf("%02X", (unsigned char) buffer[i]);
		}
	}
}

/**
 * hash_chain_verify - verify if the given hash is part of a hash chain
 * @hash_item: the given hash value
 * @last_item: the last known hash value
 * @tolerance: The tolerance limit determines how many steps may be missing in the hash chain
 *             0 means that only sequential hash values are considered as valid.
 * @return: returns 1 if the hash authentication was successfull, 0 otherwise
 */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		int hash_length, int tolerance)
{
	// this will store the intermediate hash calculation results
	unsigned char *buffer = NULL;
	/* the hash function output might be longer than needed
	 * allocate enough memory for the hash function output */
	unsigned char *hash_value = NULL;
	int err = 0, i;
	
	HIP_ASSERT(hash_length >= 0 && tolerance >= 0);
	HIP_ASSERT(current_hash != NULL && last_hash != NULL);
	
	HIP_IFEL(!(buffer = (unsigned char*)malloc(hash_length)), -1,
			"failed to allocate memory\n");
	
	HIP_IFEL(!(hash_value = (unsigned char*)malloc(MAX_HASH_LENGTH)), -1,
			"failed to allocate memory\n");
	
	// init buffer with the hash we want to verify
	memcpy(buffer, current_hash, hash_length);
	
	printf("Compare old: ");
	hexdump(last_hash, hash_length);
	printf("\nto new: ");
	hexdump(buffer, hash_length);
	printf("\n");
	
	for(i = 0; i < tolerance - 1; i++)
	{
		//HIP_DEBUG("Calculating round %2d: ", i + 1);
		
		// (input, input_length, output) -> output_length == 20
		SHA1(buffer, hash_length, hash_value);
		memcpy(buffer, hash_value, hash_length);
		
		//hexdump(buffer, hash_length);
		//HIP_DEBUG(" <-> ");
		//hexdump(last_hash, hash_length);
		//HIP_DEBUG("\n");
		
		// compare the elements
		if(!(memcmp(buffer, last_hash, hash_length)))
		{
			err = 1;
			break;
		}
	}
	
  out_err:
  	if (buffer)
  		free(buffer);
  	if (hash_value)
  		free(hash_value);
  
  	return err;
}

/**
 * hchain_create - create a new hash chain of a certain length 
 * @length: number of hash entries
 * @return: returns a pointer to the newly created hash_chain
 */
int hchain_create(int hchain_length, int hash_length, hash_chain_t *out_hchain)
{
	hash_chain_element_t *last_element = NULL, *current_element = NULL;
	unsigned char *hash_value = NULL;
	int i, err = 0;
	out_hchain = NULL;
	
	// make sure that the hash we want to use is smaller than the max output
	HIP_ASSERT(hash_length <= MAX_HASH_LENGTH);
	
	/* the hash function output might be longer than needed
	 * allocate enough memory for the hash function output */
	HIP_IFEL(!(hash_value = (unsigned char *)malloc(MAX_HASH_LENGTH)), -1,
			"failed to allocate memory\n");
	
	// allocate memory for a new hash chain
	HIP_IFEL(!(out_hchain = (hash_chain_t *)malloc(sizeof(hash_chain_t))), -1,
			"failed to allocate memory\n");
	
	for(i = 0; i < hchain_length; i++)
	{
		// allocate memory for a new element 
		HIP_IFEL(!(current_element = (hash_chain_element_t *)
				malloc(sizeof(hash_chain_element_t))), -1, "failed to allocate memory\n");
		HIP_IFEL(!(current_element->hash = (unsigned char *)malloc(hash_length)), -1,
				"failed to allocate memory\n");
		
		if(last_element != NULL){
			// (input, input_length, output) -> output_length == 20
			SHA1(last_element->hash, hash_length, hash_value);
			// only consider DEFAULT_HASH_LENGTH highest bytes
			memcpy(current_element->hash, hash_value, hash_length);
		}else{
			// random bytes as seed
			RAND_bytes(current_element->hash, hash_length);
			out_hchain->source_element = current_element;
		}
		
		// list with backwards links
		current_element->next = last_element;
		last_element = current_element;
	}
	
	out_hchain->hchain_length = hchain_length;
	out_hchain->remaining = hchain_length;
	// hash_chain->source_element set above
	out_hchain->anchor_element  = current_element;
	out_hchain->current_element = NULL;
	
	HIP_DEBUG("Hash-chain with %i elements created!\n", hchain_length);

  out_err:
    if (hash_value)	
    	free(hash_value);
  	hash_value = NULL;
  	last_element = NULL;
  	current_element = NULL;
  	
	return err;
}

/**
 * hchain_pop - return the next element in a hash chain
 * 		and move the current_element pointer forward
 * @hash_chain: the hash chain which has to be popped
 * @return: pointer to the current hash_chain element
 */
int hchain_pop(hash_chain_t * hash_chain, int hash_length, unsigned char *popped_hash)
{
	int err = 0;
	hash_chain_element_t *tmp_element = NULL;
	popped_hash = NULL;
	
	HIP_ASSERT(hash_chain != NULL);
	
	HCHAIN_LOCK(&hash_chain);  
	if(hash_chain->current_element != NULL){
		// hash chain already in use
		if(hash_chain->current_element->next == NULL){
			HIP_ERROR("hchain_next: Hash chain depleted!\n");
			exit(1);
		} else
		{
			tmp_element = hash_chain->current_element->next;
		}
	} else
	{
		// hash_chain unused yet
		tmp_element = hash_chain->anchor_element;
	}
	
	popped_hash = tmp_element->hash;
	
	HIP_DEBUG("Popping hash chain element: ");
	hexdump(popped_hash, hash_length);
	HIP_DEBUG("\n");
	
	// hchain update
	hash_chain->current_element = tmp_element;
	hash_chain->remaining--;
	
  out_err:
  	HCHAIN_UNLOCK(&hash_chain);
	
	return err;
}

/**
 * hchain_next - returns the next element of the hash chain but does not advance the current_element
 * pointer. This function should only be used if the next element is kept secret and has to 
 * be used for special puroses like message signatures.
 * @hash_chain: the hash chain 
 * @return: next element of the hash chain or NULL if the hash chain is depleted.
 */
int hchain_next(const hash_chain_t *hash_chain, int hash_length, unsigned char *next_hash)
{
	int err = 0;
	next_hash = NULL;
	
	HIP_ASSERT(hash_chain != NULL);
	
	if(hash_chain->current_element != NULL)
	{
		// hash chain already in use
		if( hash_chain->current_element->next == NULL ){
			// hash chain depleted. return NULL
			HIP_ERROR("hchain_next: Hash chain depleted!\n");
			exit(1);
		} else
		{
			// hash chain in use: return next.
			next_hash = hash_chain->current_element->next->hash;
		}
	} else
	{
		// hash_chain is unused. return the anchor element
		next_hash = hash_chain->anchor_element->hash;
	}
	
  out_err:
  	return err;
}

/**
 * hchain_current - returns the current element of the hash chain 
 * @hash_chain: the hash chain 
 * @return: current element of the hash chain or NULL if the hash chain is depleted.
 */
int hchain_current(const hash_chain_t *hash_chain, int hash_length,
		unsigned char *current_hash)
{
	int err = 0;
	current_hash = NULL;
	
	HIP_ASSERT(hash_chain != NULL);
	HIP_ASSERT(hash_chain->current_element != NULL);

	current_hash = hash_chain->current_element->hash;
	
  out_err:
	return err;
}

/**
 * hchain_destruct - delete hash chain and free memory
 * @hash_chain: the hash chain which has to be removed
 * @return: 0 in case of success
 */
int hchain_destruct(hash_chain_t *hash_chain)
{
	hash_chain_element_t *current_element = NULL;
	int err = 0;
	
	if( hash_chain != NULL )
	{
		for (current_element = hash_chain->anchor_element;
		    current_element != NULL;
		    current_element = current_element->next)
		{
			free(current_element->hash);
			free(current_element);
		}
		
		free(hash_chain);
		hash_chain = NULL;
	}
	
  out_err:
	return err;
}

/** 
 * hchain_get_num_remaining - accessor function which returns the number of remaining hash chain 
 * elements
 * @hash_chain: the hash chain
 * @return: number of remaining elements
 **/
int hchain_get_num_remaining(const hash_chain_t * hash_chain)
{
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
int concat_n_hash_SHA(unsigned char* hash, unsigned char** parts, int* part_length,
		int num_parts)
{	
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

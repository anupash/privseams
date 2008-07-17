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
#include <openssl/rand.h>
#include "crypto.h"
#include "misc.h"

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
		HIP_DEBUG("Hash chain: %d\n", (int) hash_chain);
		
		if(hash_chain->current_element != NULL)
		{
			HIP_HEXDUMP("currrent element: ", hash_chain->current_element->hash,
					hash_length);
		} else
		{
			HIP_DEBUG(" -- hash chain not in use -- \n");
		}
		
		HIP_DEBUG("Remaining elements: %d\n", hchain_get_num_remaining(hash_chain));
		HIP_DEBUG(" - Contents:\n");
		
		for(current_element = hash_chain->anchor_element, i=0;
				current_element != NULL;
				current_element = current_element->next, i++)
		{
			if(hash_chain->hchain_length - hash_chain->remaining < i+1)
			{
				HIP_DEBUG("(+) element %i:\n", i + 1);
			} else
			{
				HIP_DEBUG("(-) element %i:\n", i + 1);
			}

			HIP_HEXDUMP("\t", current_element->hash, hash_length);
		}
	} else
	{
		HIP_DEBUG("Given hash chain was NULL!\n");	
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
int hchain_verify(const unsigned char *current_hash, const unsigned char *last_hash,
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
	
	HIP_HEXDUMP("comparing given hash: ", buffer, hash_length);
	HIP_DEBUG("\t<->\n");
	HIP_HEXDUMP("last known hash: ", last_hash, hash_length);
	
	for(i = 0; i < tolerance - 1; i++)
	{
		HIP_DEBUG("Calculating round %i:\n", i + 1);
		
		// (input, input_length, output) -> output_length == 20
		SHA1(buffer, hash_length, hash_value);
		memcpy(buffer, hash_value, hash_length);
		
		HIP_HEXDUMP("comparing buffer: ", buffer, hash_length);
		HIP_DEBUG("\t<->\n");
		HIP_HEXDUMP("last known hash: ", last_hash, hash_length);
		
		// compare the elements
		if(!(memcmp(buffer, last_hash, hash_length)))
		{
			HIP_DEBUG("hash verfied\n");
			
			err = 1;
			goto out_err;
		}
	}
	
	HIP_DEBUG("no matches found within tolerance: %i!\n", tolerance);
	
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
hash_chain_t *hchain_create(int hchain_length, int hash_length)
{
	hash_chain_t *return_hchain = NULL;
	hash_chain_element_t *last_element = NULL, *current_element = NULL;
	unsigned char *hash_value = NULL;
	int i, err = 0;
	
	// make sure that the hash we want to use is smaller than the max output
	HIP_ASSERT(hash_length > 0 && hash_length <= MAX_HASH_LENGTH);
	
	/* the hash function output might be longer than needed
	 * allocate enough memory for the hash function output */
	HIP_IFEL(!(hash_value = (unsigned char *)malloc(MAX_HASH_LENGTH)), -1,
			"failed to allocate memory\n");
	// allocate memory for a new hash chain and set members to 0/NULL
	HIP_IFEL(!(return_hchain = (hash_chain_t *)malloc(sizeof(hash_chain_t))), -1,
			"failed to allocate memory\n");
	memset(return_hchain, 0, sizeof(hash_chain_t));
	
	for(i = 0; i < hchain_length; i++)
	{
		// allocate memory for a new element 
		HIP_IFEL(!(current_element = (hash_chain_element_t *)
				malloc(sizeof(hash_chain_element_t))), -1, "failed to allocate memory\n");
		HIP_IFEL(!(current_element->hash = (unsigned char *)malloc(hash_length)), -1,
				"failed to allocate memory\n");
		
		if (last_element != NULL)
		{
			// (input, input_length, output) -> output_length == 20
			HIP_IFEL(!(SHA1(last_element->hash, hash_length, hash_value)), -1,
					"failed to calculate hash\n");
			// only consider DEFAULT_HASH_LENGTH highest bytes
			memcpy(current_element->hash, hash_value, hash_length);
		} else
		{
			// random bytes as seed
			HIP_IFEL(RAND_bytes(current_element->hash, hash_length) <= 0, -1,
					"failed to get random bytes for source element\n");
			return_hchain->source_element = current_element;
		}
		
		HIP_HEXDUMP("element created: ", current_element->hash, hash_length);
		
		// list with backwards links
		current_element->next = last_element;
		last_element = current_element;
	}
	
	return_hchain->hchain_length = hchain_length;
	return_hchain->remaining = hchain_length;
	// hash_chain->source_element set above
	return_hchain->anchor_element  = current_element;
	return_hchain->current_element = NULL;
	
	HIP_DEBUG("Hash-chain with %i elements of length %i created!\n", hchain_length,
			hash_length);
	//hchain_print(return_hchain, hash_length);
	HIP_IFEL(!(hchain_verify(return_hchain->source_element->hash, return_hchain->anchor_element->hash,
			hash_length, hchain_length)), -1, "failed to verify the hchain\n");
	HIP_DEBUG("hchain successfully verfied\n");

  out_err:
    if (err)
    {
    	// try to free all that's there
    	if (return_hchain->anchor_element)
    	{
    		// hchain was created
    		hchain_destruct(return_hchain);
    	} else
    	{
    		while (current_element)
    		{
    			last_element = current_element;
    			current_element = current_element->next;
    			free(last_element);
    		}
    		if (return_hchain->source_element)
    			free(return_hchain->source_element);
    	}
    	
    	if (return_hchain);
    		free(return_hchain);
    	return_hchain = NULL;
    }
    
    // normal clean-up
    if (hash_value)	
    	free(hash_value);
  	hash_value = NULL;
  	last_element = NULL;
  	current_element = NULL;
  	
	return return_hchain;
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
	
	HIP_HEXDUMP("Popping hash chain element: ", popped_hash, hash_length);
	
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
		HIP_DEBUG("Part %d [%d]:\n",i, part_length[i]);
		HIP_HEXDUMP("", parts[i], part_length[i]);
	}
	HIP_DEBUG("%d parts, %d bytes\n", num_parts, total_len);
	/* allocate buffer space */
	buffer = malloc(total_len);
	if(buffer == NULL)
		return -1; 
	/* copy the parts to the buffer */
	for(i = 0; i < num_parts; i++){
		memcpy(buffer + position, parts[i], part_length[i]); 
		position += part_length[i];
	}
	HIP_HEXDUMP("Buffer: ", buffer, total_len);
	/* hash the buffer */
	HIP_SHA(buffer, total_len, hash);
	HIP_HEXDUMP("Buffer: ", buffer, total_len);

	/* free buffer memory*/ 
	if(buffer)
		free(buffer);
	return 0;
}

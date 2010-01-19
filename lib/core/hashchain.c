/**
 * @file firewall/hashchain.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * API for a hash chain API
 *
 * @brief API for a hash chain API
 *
 * @author Tobias Heer <heer@tobobox.de>
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "hashchain.h"
#include "debug.h"
#include "ife.h"

/* these are not needed and therefore not implemented
   right now but they should be used where necessary */
#define HCHAIN_LOCK(lock_id)
#define HCHAIN_UNLOCK(lock_id)

/** prints the hash chain
 *
 * @param	hash_chain the hash chain to be printed
 */
void hchain_print(const hash_chain_t * hash_chain)
{
	int i;

	if (hash_chain)
	{
		HIP_DEBUG("Hash chain: %p\n", hash_chain);

		if(hash_chain->current_index < hash_chain->hchain_length)
		{
			HIP_HEXDUMP("currrent element: ", hchain_element_by_index(hash_chain, hash_chain->current_index),
					hash_chain->hash_length);
		} else
		{
			HIP_DEBUG(" -- hash chain not in use -- \n");
		}

		HIP_DEBUG("Remaining elements: %d\n", hchain_get_num_remaining(hash_chain));
		HIP_DEBUG(" - Contents:\n");

		for (i = 0;	i < hash_chain->hchain_length; i++)
		{
			if (i < hash_chain->current_index)
			{
				HIP_DEBUG("(+) element %i:\n", i + 1);

			} else
			{
				HIP_DEBUG("(-) element %i:\n", i + 1);
			}

			HIP_HEXDUMP("\t", hchain_element_by_index(hash_chain, i),
					hash_chain->hash_length);
		}

	} else
	{
		HIP_DEBUG("Given hash chain was NULL!\n");
	}
}

/** checks if a hash is verifiable by a hash chain
 *
 * @param	current_hash the hash value to be verified
 * @param	lasl_hash the last known hash value
 * @param	hash_function the hash function to be used
 * @param	hash_length length of the hash values
 * @param	tolerance the maximum number of hash calculations
 * @param	secret the potentially incorporated secret
 * @param	secret_length length og the secret
 * @return	hash distance if the hash authentication was successful, 0 otherwise
 */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		const hash_function_t hash_function, const int hash_length, const int tolerance,
		const unsigned char *secret, const int secret_length)
{
	/* stores intermediate hash results and allow to concat
	 * with a secret at each step */
	unsigned char buffer[MAX_HASH_LENGTH + secret_length];
	int err = 0, i;

	HIP_ASSERT(current_hash != NULL && last_hash != NULL);
	HIP_ASSERT(hash_function != NULL);
	HIP_ASSERT(hash_length > 0 && tolerance >= 0);

	// init buffer with the hash we want to verify
	memcpy(buffer, current_hash, hash_length);

	if (secret && secret_length > 0)
	{
		HIP_HEXDUMP("secret: ", secret, secret_length);
	}

	_HIP_HEXDUMP("comparing given hash: ", buffer, hash_length);
	_HIP_DEBUG("\t<->\n");
	_HIP_HEXDUMP("last known hash: ", last_hash, hash_length);

	for(i = 1; i <= tolerance; i++)
	{
		_HIP_DEBUG("Calculating round %i:\n", i);

		// add the secret
		if (secret != NULL && secret_length > 0)
			memcpy(&buffer[hash_length], secret, secret_length);

		hash_function(buffer, hash_length + secret_length, buffer);

		_HIP_HEXDUMP("comparing buffer: ", buffer, hash_length);
		_HIP_DEBUG("\t<->\n");
		_HIP_HEXDUMP("last known hash: ", last_hash, hash_length);

		// compare the elements
		if(!(memcmp(buffer, last_hash, hash_length)))
		{
			HIP_DEBUG("hash verfied\n");

			err = i;
			goto out_err;
		}
	}

	HIP_DEBUG("no matches found within tolerance: %i!\n", tolerance);

  out_err:
  	return err;
}

/** creates a new hash chain
 *
 * @param	hash_function hash function to be used to generate the hash values
 * @param	hash_length length of the hash values
 * @param	hchain_length number of hash elements
 * @param	hchain_hierarchy the hierarchy level this hash chain will belong to
 * @param	link_tree the link tree, if HHL is used
 * @return  pointer to the newly created hash chain, NULL on error
 */
hash_chain_t * hchain_create(const hash_function_t hash_function, const int hash_length,
		const int hchain_length, const int hchain_hierarchy, hash_tree_t *link_tree)
{
	hash_chain_t *hchain = NULL;
	/* the hash function output might be longer than needed
	 * allocate enough memory for the hash function output
	 *
	 * @note we also allow a concatenation with the link tree root and the jump chain element here */
	unsigned char hash_value[3 * MAX_HASH_LENGTH];
	int hash_data_length = 0;
	int i, err = 0;

	HIP_ASSERT(hash_function != NULL);
	// make sure that the hash we want to use is smaller than the max output
	HIP_ASSERT(hash_length > 0 && hash_length <= MAX_HASH_LENGTH);
	HIP_ASSERT(hchain_length > 0);
	HIP_ASSERT(!(hchain_hierarchy == 0 && link_tree));

	// allocate memory for a new hash chain
	HIP_IFEL(!(hchain = (hash_chain_t *) malloc(sizeof(hash_chain_t))), -1,
			"failed to allocate memory\n");
	memset(hchain, 0, sizeof(hash_chain_t));

	// allocate memory for the hash chain elements
	HIP_IFEL(!(hchain->elements = (unsigned char *) malloc(hash_length * hchain_length)), -1,
				"failed to allocate memory\n");
	memset(hchain->elements, 0, hash_length * hchain_length);

	// set the link tree if we are using different hierarchies
	if (link_tree)
	{
		hchain->link_tree = link_tree;
		hash_data_length = 2 * hash_length;

	} else
	{
		hchain->link_tree = NULL;
		hash_data_length = hash_length;
	}

	for (i = 0; i < hchain_length; i++)
	{
		if (i > 0)
		{
			// (input, input_length, output) -> output_length == 20
			HIP_IFEL(!(hash_function(hash_value, hash_data_length, hash_value)), -1,
					"failed to calculate hash\n");
			// only consider highest bytes of digest with length of actual element
			memcpy( &hchain->elements[i * hash_length], hash_value, hash_length);
		} else
		{
			// random bytes as seed -> need a copy in hash_value for further computations
			HIP_IFEL(RAND_bytes(hash_value, hash_length) <= 0, -1,
					"failed to get random bytes for source element\n");

			memcpy(&hchain->elements[i * hash_length], hash_value, hash_length);
		}

		/* concatenate used part of the calculated hash with the link tree root */
		if (link_tree)
		{
			memcpy(&hash_value[hash_length], link_tree->root, link_tree->node_length);
		}

		_HIP_HEXDUMP("element created: ", &hchain->elements[i], hash_length);
	}

	hchain->hash_function = hash_function;
	hchain->hash_length = hash_length;
	hchain->hchain_length = hchain_length;
	hchain->current_index = hchain_length;
	hchain->hchain_hierarchy = hchain_hierarchy;

	HIP_DEBUG("Hash-chain with %i elements of length %i created!\n", hchain_length,
			hash_length);

  out_err:
    if (err)
    {
		// hchain was fully created
		hchain_free(hchain);
    	hchain = NULL;
    }

	return hchain;
}

/* getter function for the hash chain anchor element
 *
 * @param	hash_chain hash chain from which the anchor should be returned
 * @return	anchor element of the given hash chain
 */
unsigned char * hchain_get_anchor(const hash_chain_t *hash_chain)
{
	HIP_ASSERT(hash_chain);

	return hchain_element_by_index(hash_chain, hash_chain->hchain_length - 1);
}

/* getter function for the hash chain seed element
 *
 * @param	hash_chain hash chain from which the seed should be returned
 * @return	seed element of the given hash chain
 */
unsigned char * hchain_get_seed(const hash_chain_t *hash_chain)
{
	HIP_ASSERT(hash_chain);

	return hchain_element_by_index(hash_chain, 0);
}

/* getter function for a specific element of the given hash chain
 *
 * @param	hash_chain hash chain from which the element should be returned
 * @param	index index to the hash chain element
 * @return	element of the given hash chain
 */
unsigned char * hchain_element_by_index(const hash_chain_t *hash_chain, const int index)
{
	unsigned char *element = NULL;
	int err = 0;

	HIP_ASSERT(hash_chain);

	if (index >= 0 && index < hash_chain->hchain_length)
	{
		element = &hash_chain->elements[index * hash_chain->hash_length];

	} else
	{
		HIP_ERROR("Element from uninited hash chain or out-of-bound element requested!");

		err = -1;
		goto out_err;
	}

	HIP_HEXDUMP("Hash chain element: ", element, hash_chain->hash_length);

  out_err:
	if (err)
		element = NULL;

	return element;
}

/* setter function for a specific index of the given hash chain
 *
 * @param	hash_chain hash chain from which the element should be returned
 * @param	index index to the hash chain element
 * @return	always 0
 */
int hchain_set_current_index(hash_chain_t *hash_chain, const int index)
{
	int err = 0;

	HIP_ASSERT(hash_chain);
	HIP_ASSERT(index >= 0 && index <= hash_chain->hchain_length);

	hash_chain->current_index = index;

	return err;
}

/** returns the next element of the hash chain but does not advance the current element
 * pointer. This function should only be used if the next element is kept secret and has to
 * be used for special purposes like message signatures.
 *
 * @param	hash_chain the hash chain
 * @return	next element of the hash chain or NULL if the hash chain reached boundary
 */
unsigned char * hchain_next(const hash_chain_t *hash_chain)
{
	unsigned char *element = NULL;

	element = hchain_element_by_index(hash_chain, hash_chain->current_index - 1);

  	return element;
}

/** returns the previous element of the hash chain but does not advance the current element
 * pointer.
 *
 * @param	hash_chain given hash chain
 * @return	previous element of the hash chain or NULL if the hash chain reached boundary
 */
unsigned char * hchain_previous(const hash_chain_t * hash_chain)
{
	unsigned char *element = NULL;

	element = hchain_element_by_index(hash_chain, hash_chain->current_index + 1);

  	return element;
}

/** returns the current element of the hash chain but does not advance the current element
 * pointer.
 *
 * @param	hash_chain given hash chain
 * @return	current element of the hash chain or NULL if the hash chain reached boundary
 */
unsigned char * hchain_current(const hash_chain_t *hash_chain)
{
	unsigned char *element = NULL;

	element = hchain_element_by_index(hash_chain, hash_chain->current_index);

	return element;
}

/** removes and returns the next element from the hash chain advances current element pointer
 *
 * @param	hash_chain hash chain which has to be popped
 * @return	pointer to the next hashchain element or NULL if the hash chain is depleted
 */
unsigned char * hchain_pop(hash_chain_t * hash_chain)
{
	unsigned char *element = NULL;

	HIP_ASSERT(hash_chain);

	HCHAIN_LOCK(&hash_chain);
	element = hchain_next(hash_chain);
	hash_chain->current_index--;
	HCHAIN_UNLOCK(&hash_chain);

	return element;
}

/** returns the previous element from the hash chain and decreases current element pointer
 *
 * @param	hash_chain hash chain which has to be popped
 * @return	pointer to the previous hashchain element or NULL if the hash chain is depleted
 */
unsigned char * hchain_push(hash_chain_t * hash_chain)
{
	unsigned char *element = NULL;

	HIP_ASSERT(hash_chain);

	HCHAIN_LOCK(&hash_chain);
	element = hchain_previous(hash_chain);
	hash_chain->current_index++;
	HCHAIN_UNLOCK(&hash_chain);

	return element;
}

/** resets the pointer to the current element
 *
 * @param	hash_chain hash chain that should be reset
 * @return	always 0
 */
int hchain_reset(hash_chain_t *hash_chain)
{
	int err = 0;

	hash_chain->current_index = hash_chain->hchain_length;

	return err;
}

/** delete hash chain and free memory
 *
 * @param	hash_chain hash chain which should be removed
 * @return	always 0
 */
int hchain_free(hash_chain_t *hash_chain)
{
	int err = 0;

	if(hash_chain)
	{
		htree_free(hash_chain->link_tree);
		hash_chain->link_tree = NULL;

		if (hash_chain->elements)
			free(hash_chain->elements);

		free(hash_chain);
	}

	HIP_DEBUG("all hash-chain elements and dependencies freed\n");

	return err;
}

/** accessor function which returns the number of remaining hash chain elements
 *
 * @param	hash_chain the hash chain
 * @return	number of remaining elements
 */
int hchain_get_num_remaining(const hash_chain_t * hash_chain)
{
	return hash_chain->current_index;
}

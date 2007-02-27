#ifndef HIP_LHASHTABLE_H
#define HIP_LHASHTABLE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include "list.h"
#include "debug.h"

#undef MIN_NODES
#define MIN_NODES	16
#define UP_LOAD		(2*LH_LOAD_MULT) /* load times 256  (default 2) */
#define DOWN_LOAD	(LH_LOAD_MULT)   /* load times 256  (default 1) */

// XX FIXME: HAS TO BE CONVERTED

static LHASH *amih;
static LHASH *tblhash=NULL;
static uint reclength=37;


struct hip_ht_common {
	LHASH_NODE **hipb;
	/** a pointer to memory area to be used as hashtable. */
	LHASH *ami;
	hip_list_t *head;
	int hashsize;
	/** offset of the hip_list_t that links the elements. */
	int offset;
	/** a pointer to a function that hashes the key. */
	int (*hash)(const void *key, int range);
	/** a pointer to a function that compares two keys. */
	int (*compare)(const void *key_to_match,
		       const void *key_to_be_matched);
	/** a pointer to a function that increases the element's reference
	    count. */
	void (*hold)(void *entry);
	/** a pointer to a function that decreases the element's reference
	    count. */
	void (*put)(void *entry);
	/** a pointer to a function that returns the element's key from
	    the element structure. */
	void *(*get_key)(void *entry);
	/** name of the hashtable. */

	unsigned int num_nodes;
     	unsigned int num_alloc_nodes;
     	unsigned int p;
     	unsigned int pmax;
	unsigned int error;
     	unsigned long up_load; /* load times 256 */
     	unsigned long down_load; /* load times 256 */
    	unsigned long num_items;
     	unsigned long num_expands;
     	unsigned long num_expand_reallocs;
     	unsigned long num_contracts;
     	unsigned long num_contract_reallocs;
     	unsigned long num_hash_calls;
     	unsigned long num_comp_calls;
     	unsigned long num_insert;
     	unsigned long num_replace;
     	unsigned long num_delete;
     	unsigned long num_no_delete;
     	unsigned long num_retrieve;
     	unsigned long num_retrieve_miss;
     	unsigned long num_hash_comps;
	int comp;
	
	
	char name[16];
};

typedef struct hip_ht_common HIP_HASHTABLE;
/*typedef struct lhash_st HIP_LHASH;*/


int hip_ht_init( HIP_HASHTABLE  *ht);
void hip_ht_uninit( HIP_HASHTABLE *ht);

void *hip_ht_find(HIP_HASHTABLE *ht, const void *key);
int hip_ht_add(HIP_HASHTABLE *ht, void *data);
void hip_ht_delete(HIP_HASHTABLE *ht, void *entry);
#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

#endif /* LHASHTABLE_H */


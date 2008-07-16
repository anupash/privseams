/*
 * Host Identity Protocol
 * Copyright (C) 2004-06 the Boeing Company
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  hip_sadb.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * the HIP Security Association database
 *
 */
#include "user_ipsec_sadb.h"
#include "esp_prot.h"
#include <openssl/sha.h>

#define INDEX_HASH_LENGTH SHA_DIGEST_LENGTH

// database storing the sa entries, indexed by src _and_ dst hits
HIP_HASHTABLE *sadb = NULL;
// database storing shortcut to sa entries for incoming packets
HIP_HASHTABLE *linkdb = NULL;

//callback wrappers providing per-variable casts before calling the type-specific callbacks
static IMPLEMENT_LHASH_HASH_FN(hip_sa_entry_hash, const hip_sa_entry_t *)
static IMPLEMENT_LHASH_COMP_FN(hip_sa_entries_compare, const hip_sa_entry_t *)
static IMPLEMENT_LHASH_HASH_FN(hip_link_entry_hash, const hip_link_entry_t *)
static IMPLEMENT_LHASH_COMP_FN(hip_link_entries_compare, const hip_link_entry_t *)

int hip_sadb_init()
{
	int err = 0;
	
	HIP_IFEL(!(sadb = hip_ht_init(LHASH_HASH_FN(hip_sa_entry_hash),
			LHASH_COMP_FN(hip_sa_entries_compare))), -1,
			"failed to initialize sadb\n");
	HIP_IFEL(!(linkdb = hip_ht_init(LHASH_HASH_FN(hip_link_entry_hash),
			LHASH_COMP_FN(hip_link_entries_compare))), -1,
			"failed to initialize linkdb\n");
	
	HIP_DEBUG("sadb initialized\n");

  out_err:
  	return err;
}

unsigned long hip_sa_entry_hash(const hip_sa_entry_t *sa_entry)
{
	struct in6_addr addr_pair[2];		/* in BEET-mode these are HITs */
	unsigned char hash[INDEX_HASH_LENGTH];
	int err = 0;
	
	// values have to be present
	HIP_ASSERT(sa_entry != NULL && sa_entry->inner_src_addr != NULL
			&& sa_entry->inner_dst_addr != NULL);
	
	memset(hash, 0, INDEX_HASH_LENGTH);
	
	if (sa_entry->mode == 3)
	{
		/* use hits to index in beet mode
		 * 
		 * NOTE: the index won't change during ongoing connection
		 * NOTE: the HIT fields of an host association struct cannot be assumed to
		 * be alligned consecutively. Therefore, we must copy them to a temporary
		 * array. */
		memcpy(&addr_pair[0], sa_entry->inner_src_addr, sizeof(struct in6_addr));
		memcpy(&addr_pair[1], sa_entry->inner_dst_addr, sizeof(struct in6_addr));
		
	} else
	{
		HIP_ERROR("indexing for non-BEET-mode not implemented!\n");
		
		err = -1;
		goto out_err;
	}
	 
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, (void *)addr_pair, sizeof(addr_pair), hash),
			-1, "failed to hash addresses\n");
	
  out_err:
  	if (err)
  	{
  		*hash = 0;
  	}
  	
	return *((unsigned long *)hash);
}

int hip_sa_entries_compare(const hip_sa_entry_t *sa_entry1,
		const hip_sa_entry_t *sa_entry2)
{
	int err = 0;
	unsigned long hash1 = 0;
	unsigned long hash2 = 0;
	
	// values have to be present
	HIP_ASSERT(sa_entry1 != NULL && sa_entry1->inner_src_addr != NULL
			&& sa_entry1->inner_dst_addr != NULL);
	HIP_ASSERT(sa_entry2 != NULL && sa_entry2->inner_src_addr != NULL
				&& sa_entry2->inner_dst_addr != NULL);

	HIP_IFEL(!(hash1 = hip_sa_entry_hash(sa_entry1)), -1, "failed to hash sa entry\n");
	HIP_IFEL(!(hash2 = hip_sa_entry_hash(sa_entry2)), -1, "failed to hash sa entry\n");
	
	if (hash1 != hash2 || sa_entry1->spi != sa_entry2->spi)
	{
		err = 1;
	}
	
  out_err:
    return err;
}

unsigned long hip_link_entry_hash(const hip_link_entry_t *link_entry)
{
	unsigned char hash_input[sizeof(struct in6_addr) + sizeof(uint32_t)];
	unsigned char hash[INDEX_HASH_LENGTH];
	int err = 0;
	
	// values have to be present
	HIP_ASSERT(link_entry != NULL && link_entry->dst_addr != NULL && link_entry->spi != 0);
	
	memset(hash, 0, INDEX_HASH_LENGTH);
	
	/* concatenate dst_addr and spi */
	memcpy(&hash_input[0], link_entry->dst_addr, sizeof(struct in6_addr));
	memcpy(&hash_input[sizeof(struct in6_addr) - 1], &link_entry->spi, sizeof(uint32_t));
	 
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, (void *)hash_input, sizeof(hash_input), hash),
			-1, "failed to hash addresses\n");
	
  out_err:
  	if (err)
  	{
  		*hash = 0;
  	}
  	
	return *((unsigned long *)hash);
}

int hip_link_entries_compare(const hip_link_entry_t *link_entry1,
		const hip_link_entry_t *link_entry2)
{
	int err = 0;
	unsigned long hash1 = 0;
	unsigned long hash2 = 0;
	
	// values have to be present
	HIP_ASSERT(link_entry1 != NULL && link_entry1->dst_addr != NULL
			&& link_entry1->spi != 0);
	HIP_ASSERT(link_entry2 != NULL && link_entry2->dst_addr != NULL
				&& link_entry2->spi != 0);

	HIP_IFEL(!(hash1 = hip_link_entry_hash(link_entry1)), -1,
			"failed to hash link entry\n");
	HIP_IFEL(!(hash2 = hip_link_entry_hash(link_entry2)), -1,
			"failed to hash link entry\n");
	
	if (hash1 != hash2)
	{
		err = 1;
	}
	
  out_err:
    return err;
}

int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor,
		int retransmission, int update)
{
	int err = 0;
	
	// TODO handle retransmission and update correctly
	
	if (update)
	{
		HIP_IFEL(hip_sa_entry_update(direction, spi, mode, src_addr, dst_addr, inner_src_addr,
				inner_dst_addr, encap_mode, src_port, dst_port, ealg, a_keylen,
				e_keylen, a_key, e_key, lifetime, esp_prot_transform, esp_prot_anchor), -1,
				"failed to update sa entry\n");
	} else
	{
		HIP_IFEL(hip_sa_entry_add(direction, spi, mode, src_addr, dst_addr, inner_src_addr,
				inner_dst_addr, encap_mode, src_port, dst_port, ealg, a_keylen,
				e_keylen, a_key, e_key, lifetime, esp_prot_transform, esp_prot_anchor), -1,
				"failed to add sa entry\n");
	}
	
  out_err:
  	return err;
}

int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor)
{
	hip_sa_entry_t *entry = NULL;
	int err = 0;
	
	/* initialize members to 0/NULL */
	HIP_IFEL(!(entry = (hip_sa_entry_t *) malloc(sizeof(hip_sa_entry_t))), -1,
			"failed to allocate memory\n");
	memset(entry, 0, sizeof(hip_sa_entry_t));
	
	HIP_IFEL(!(entry->src_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))), -1,
			"failed to allocate memory\n");
	memset(entry->src_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->dst_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))), -1,
			"failed to allocate memory\n");
	memset(entry->dst_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->inner_src_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))),
			-1, "failed to allocate memory\n");
	memset(entry->inner_src_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->inner_dst_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))),
			-1, "failed to allocate memory\n");
	memset(entry->inner_dst_addr, 0, sizeof(struct in6_addr));
	
	HIP_IFEL(!(entry->a_key = (unsigned char *) malloc(a_keylen)), -1,
			"failed to allocate memory\n");
	memset(entry->a_key, 0, a_keylen);
	if (e_keylen > 0)
	{
		HIP_IFEL(!(entry->e_key = (unsigned char *) malloc(e_keylen)), -1,
				"failed to allocate memory\n");
		memset(entry->e_key, 0, e_keylen);
	}
	
	HIP_IFEL(hip_sa_entry_set(entry, direction, spi, mode, src_addr, dst_addr,
			inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
			a_keylen, e_keylen, a_key, e_key, lifetime, esp_prot_transform, esp_prot_anchor),
			-1, "failed to set the entry members\n");
	
	HIP_DEBUG("adding sa entry with following index attributes:\n");
	HIP_DEBUG_HIT("inner_src_addr", entry->inner_src_addr);
	HIP_DEBUG_HIT("inner_dst_addr", entry->inner_dst_addr);
	HIP_DEBUG("mode: %i\n", entry->mode);
	
	/* returns the replaced item or NULL on normal operation and error.
	 * A new entry should not replace another one! */
	HIP_IFEL(hip_ht_add(sadb, entry), -1, "hash collision detected!\n");
	
	// add links to this entry for incoming packets
	HIP_IFEL(hip_link_entries_add(entry), -1, "failed to add link entries\n");
	
	HIP_DEBUG("sa entry added successfully\n");
	
	hip_sadb_print();
	
  out_err:
  	if (err)
  	{	
  		if (entry)
  		{
  			hip_link_entries_delete_all(entry);
  			hip_sa_entry_free(entry);
  			free(entry);
  		}
  		entry = NULL;
  	}
  
  	return err;
}

int hip_sa_entry_update(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor)
{
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;
	
	// we need the sadb entry to go through entries in the linkdb
	HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(inner_src_addr, inner_dst_addr)),
			-1, "failed to retrieve sa entry\n");
	
	pthread_mutex_lock(stored_entry->rw_lock);
	/* delete all links
	 * 
	 * TODO more efficient to delete entries in inbound db for all (addr, oldspi)
	 * or just those with (oldaddr, spi) */
	HIP_IFEL(hip_link_entries_delete_all(stored_entry), -1, "failed to remove links\n");
	
	/* change members of entry in sadb and add new links */
	HIP_IFEL(hip_sa_entry_set(stored_entry, direction, spi, mode, src_addr, dst_addr,
			inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg, a_keylen,
			e_keylen, a_key, e_key, lifetime, esp_prot_transform, esp_prot_anchor),
			-1, "failed to update the entry members\n");
	
	HIP_IFEL(hip_link_entries_add(stored_entry), -1, "failed to add links\n");
	pthread_mutex_unlock(stored_entry->rw_lock);
	
	HIP_DEBUG("sa entry updated\n");
	
  out_err:
  	return err;
}

int hip_sa_entry_set(hip_sa_entry_t *entry, int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor)
{
	int key_len = 0; 							/* for 3-DES */
	unsigned char key1[8], key2[8], key3[8]; 	/* for 3-DES */
	int err = 0;
	
	/* copy values for non-zero members */
	entry->direction = direction;
	entry->spi = spi;
	entry->mode = mode;
	memcpy(entry->src_addr, src_addr, sizeof(struct in6_addr));
	memcpy(entry->dst_addr, dst_addr, sizeof(struct in6_addr));
	if (entry->mode == 3)
	{ 
		memcpy(entry->inner_src_addr, inner_src_addr, sizeof(struct in6_addr));
		memcpy(entry->inner_dst_addr, inner_dst_addr, sizeof(struct in6_addr));
	}	
	entry->encap_mode = encap_mode;
	entry->src_port = src_port;
	entry->dst_port = dst_port;
	
	entry->ealg = ealg;
	entry->a_keylen = a_keylen;
	entry->e_keylen = e_keylen;
	
	HIP_DEBUG("ealg value is: %d\n", ealg);
	
	// copy raw keys
	memcpy(entry->a_key, a_key, a_keylen);
	if (e_keylen > 0)
		memcpy(entry->e_key, e_key, e_keylen);
	
	// set up keys for the transform in use
	switch (ealg)
	{
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_3DES_MD5:
			key_len = e_keylen/3;
			
			memset(key1, 0, key_len);
			memset(key2, 0, key_len);
			memset(key3, 0, key_len);
			
			memcpy(key1, &e_key[0], key_len);
			memcpy(key2, &e_key[8], key_len);
			memcpy(key3, &e_key[16], key_len);
			
			des_set_odd_parity((des_cblock*)key1);
			des_set_odd_parity((des_cblock*)key2);
			des_set_odd_parity((des_cblock*)key3);
			
			err = des_set_key_checked((des_cblock*)key1, entry->ks[0]);
			err += des_set_key_checked((des_cblock*)key2, entry->ks[1]);
			err += des_set_key_checked((des_cblock*)key3, entry->ks[2]);
			
			HIP_IFEL(err, -1, "3DES key problem\n");
			
			break;
		case HIP_ESP_AES_SHA1:
			/* AES key differs for encryption/decryption, so we set
			 * it upon first use in the SA */
			entry->aes_key = NULL;
			
			break;
		case HIP_ESP_BLOWFISH_SHA1:
			entry->bf_key = (BF_KEY *) malloc(sizeof(BF_KEY));
			BF_set_key(entry->bf_key, e_keylen, e_key);
			
			break;
		case HIP_ESP_NULL_SHA1:
			// same encryption chiper as next transform
		case HIP_ESP_NULL_MD5:
			// nothing needs to be set up
			break;
		default:
			HIP_ERROR("Unsupported encryption transform: %i.\n", ealg);
			
			err = -1;
			goto out_err;
	}
	
	entry->sequence = 1;
	entry->lifetime = lifetime;
	
	HIP_IFEL(esp_prot_set_sadb(entry, esp_prot_transform, esp_prot_anchor, direction), -1,
			"failed to set esp protection members\n");
	
  out_err:
  	return err;
}

hip_sa_entry_t * hip_sa_entry_find_inbound(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_link_entry_t *stored_link = NULL;
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;
	
	HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, spi)), -1,
			"failed to find link entry");
	
	stored_entry = stored_link->linked_sa_entry;
	
  out_err:
  	if (err)
  		stored_entry = NULL;
  	
  	return stored_entry;
}

hip_sa_entry_t * hip_sa_entry_find_outbound(struct in6_addr *src_hit,
		struct in6_addr *dst_hit)
{
	hip_sa_entry_t *search_entry = NULL, *stored_entry = NULL;
	int err = 0;
	
	HIP_IFEL(!(search_entry = (hip_sa_entry_t *) malloc(sizeof(hip_sa_entry_t))), -1,
			"failed to allocate memory\n");
	memset(search_entry, 0, sizeof(hip_sa_entry_t));
	
	// fill search entry with information needed by the hash function
	search_entry->inner_src_addr = src_hit;
	search_entry->inner_dst_addr = dst_hit;
	search_entry->mode = BEET_MODE;
	
	HIP_DEBUG("looking up sa entry with following index attributes:\n");
	HIP_DEBUG_HIT("inner_src_addr", search_entry->inner_src_addr);
	HIP_DEBUG_HIT("inner_dst_addr", search_entry->inner_dst_addr);
	HIP_DEBUG("mode: %i\n", search_entry->mode);
	
	hip_sadb_print();
	
	// find entry in sadb db
	HIP_IFEL(!(stored_entry = hip_ht_find(sadb, search_entry)), -1,
			"failed to retrieve sa entry\n");
	
  out_err:
  	if (err)
  		stored_entry = NULL;
  
  	if (search_entry)
  		free(search_entry);
  	
  	return stored_entry;
}

int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;
	
	/* find entry in sadb and delete entries in linkdb for all (addr, spi)-matches */
	HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(src_addr, dst_addr)), -1,
			"failed to retrieve sa entry\n");
	
	/* NOTE: no need to unlock mutex as the entry is already freed and can't be
	 * accessed any more */
	pthread_mutex_lock(stored_entry->rw_lock);
	
	HIP_IFEL(hip_link_entries_delete_all(stored_entry), -1, "failed to delete links\n");
	
	// free all entry members
	hip_sa_entry_free(stored_entry);
	
	hip_ht_delete(sadb, stored_entry);
	if (stored_entry)
	{
		HIP_DEBUG("this does not yet delete the entry\n");
		free(stored_entry);
	}
	
  out_err:
  	return err;
}

int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry)
{
	hip_link_entry_t *link = NULL;
	int err = 0;
	
	HIP_IFEL(!(link = (hip_link_entry_t *) malloc(sizeof(hip_link_entry_t))), -1,
					"failed to allocate memory\n");
			
	link->dst_addr = dst_addr;
	link->spi = entry->spi;
	link->linked_sa_entry = entry;
	
	hip_ht_add(linkdb, link);
	
  out_err:
  	return err;
}

int hip_link_entries_add(hip_sa_entry_t *entry)
{
	int err = 0;
	
	HIP_DEBUG("adding links to this sadb entry...\n");
	
	// TODO add multihoming support here
	//while (entry has more dst_addr)
	HIP_IFEL(hip_link_entry_add(entry->dst_addr, entry), -1,
				"failed to add link entry\n");
	
  out_err:
  	return err;
}

hip_link_entry_t *hip_link_entry_find(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_link_entry_t *search_link = NULL, *stored_link = NULL;
	int err = 0;
		
	HIP_IFEL(!(search_link = (hip_link_entry_t *) malloc(sizeof(hip_link_entry_t))), -1,
				"failed to allocate memory\n");
	memset(search_link, 0, sizeof(hip_link_entry_t));
	
	// search the linkdb for the link to the corresponding entry
	search_link->dst_addr = dst_addr;
	search_link->spi = spi;
	
	HIP_IFEL(!(stored_link = hip_ht_find(linkdb, search_link)), -1,
				"failed to retrieve link entry\n");
  out_err:
  	if (err)
  		stored_link = NULL;
  
	if (search_link)
	  	free(search_link);
	
	return stored_link;
}

int hip_link_entry_delete(struct in6_addr *dst_addr, hip_sa_entry_t *entry)
{
	hip_link_entry_t *stored_link = NULL;
	int err = 0;
	
	HIP_IFEL(!(stored_link = (hip_link_entry_t *) malloc(sizeof(hip_link_entry_t))), -1,
					"failed to allocate memory\n");
			
	stored_link->dst_addr = dst_addr;
	stored_link->spi = entry->spi;
	stored_link->linked_sa_entry = entry;
	
	// find link entry and free members
	HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, entry->spi)), -1,
				"failed to retrieve sa entry\n");
	
	if (stored_link->dst_addr)
		free(stored_link->dst_addr);
	
	// delete the link
	hip_ht_delete(linkdb, stored_link);
	if (stored_link)
	{
		HIP_DEBUG("this does not yet delete the entry\n");
		free(stored_link);
	}
	
  out_err:
  	return err;
}

int hip_link_entries_delete_all(hip_sa_entry_t *entry)
{
	int err = -1;
	
	HIP_DEBUG("adding links to this sadb entry...\n");
	
	// TODO lock link hashtable and add multihoming support here
	//while (entry has more dst_addr)
	HIP_IFEL(hip_link_entry_delete(entry->dst_addr, entry), -1,
			"failed to add link entry\n");
	
  out_err:
  	return err;
}

void hip_sa_entry_free(hip_sa_entry_t * entry)
{
	if (entry)
	{
		if (entry->src_addr)
			free(entry->src_addr);
		if (entry->dst_addr)
			free(entry->dst_addr);
		if (entry->inner_src_addr)
			free(entry->inner_src_addr);
		if (entry->inner_dst_addr)
			free(entry->inner_dst_addr);
		if (entry->a_key)
			free(entry->a_key);
		if (entry->e_key)
			free(entry->e_key);
		if (entry->ks)
			free(entry->ks);
		if (entry->aes_key)
			free(entry->aes_key);
		if (entry->bf_key)
			free(entry->bf_key);
		if (entry->active_hchain)
			free(entry->active_hchain);
		if (entry->next_hchain)
			free(entry->next_hchain);
		if (entry->active_anchor)
			free(entry->active_anchor);
		if (entry->next_anchor)
			free(entry->next_anchor);
	}
}

int hip_sadb_flush()
{
	int err = 0, i = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_sa_entry_t *entry = NULL;
	
	// TODO use DO_ALL makro here
	// iterating over all elements
	list_for_each_safe(item, tmp, sadb, i)
	{
		HIP_IFEL(!(entry = list_entry(item)), -1, "failed to get list entry\n");
		HIP_IFEL(hip_sa_entry_delete(entry->inner_src_addr, entry->inner_dst_addr), -1,
				"failed to delete sa entry\n");
	}
	
	HIP_DEBUG("sadb flushed\n");
	
  out_err:
  	return err;
}

void hip_sa_entry_print(hip_sa_entry_t *entry)
{
	if (entry)
	{
		HIP_DEBUG("direction: %i\n", entry->direction);
		HIP_DEBUG("spi: %u\n", entry->spi);
		HIP_DEBUG("mode: %u\n", entry->mode);
		HIP_DEBUG_HIT("src_addr", entry->src_addr);
		HIP_DEBUG_HIT("dst_addr", entry->dst_addr);
		HIP_DEBUG_HIT("inner_src_addr", entry->inner_src_addr);
		HIP_DEBUG_HIT("inner_dst_addr", entry->inner_dst_addr);
		HIP_DEBUG("encap_mode: %u\n", entry->encap_mode);
		HIP_DEBUG("src_port: %u\n", entry->src_port);
		HIP_DEBUG("dst_port: %u\n", entry->dst_port);
		HIP_DEBUG("... (more members)\n");
// TODO print the rest
#if 0
		/****************** crypto parameters *******************/
		int ealg;								/* crypto transform in use */
		uint32_t a_keylen;						/* length of raw keys */
		uint32_t e_keylen;
		unsigned char *a_key;					/* raw crypto keys */
		unsigned char *e_key;
		des_key_schedule ks[3];					/* 3-DES keys */
		AES_KEY *aes_key;						/* AES key */
		BF_KEY *bf_key;							/* BLOWFISH key */
		/*********************************************************/
		uint64_t lifetime;			/* seconds until expiration */
		uint64_t bytes;				/* bytes transmitted */
		struct timeval usetime;		/* last used timestamp */
		struct timeval usetime_ka;	/* last used timestamp, incl keep-alives */
		uint32_t sequence;			/* sequence number counter */
		uint32_t replay_win;		/* anti-replay window */
		uint32_t replay_map;		/* anti-replay bitmap */
		/*********** esp protection extension params *************/
		/* hash chain parameters for this SA used in secure ESP extension */
		/* for outgoing SA */
		hash_chain_t *active_hchain;
		hash_chain_t *next_hchain;
		/* for incoming SA */
		int tolerance;
		unsigned char *active_anchor;
		unsigned char *next_anchor;
		/* for both */
		uint8_t active_transform;
		uint8_t next_transform;
#endif
	} else
	{
		HIP_DEBUG("entry is NULL\n");
	}
}

void hip_sadb_print()
{
	int i = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_sa_entry_t *entry = NULL;
	
	HIP_DEBUG("printing sadb...\n");
	
	// TODO use DO_ALL makro here
	// iterating over all elements
	list_for_each_safe(item, tmp, sadb, i)
	{
		if (!(entry = list_entry(item)))
		{
			HIP_ERROR("failed to get list entry\n");
			break;
		}
		hip_sa_entry_print(entry);
	}
	
	if (i == 0)
	{
		HIP_DEBUG("sadb contains no items\n");
	}
}


#if 0
/*
 * init_sadb()
 *
 * Initialize hash tables.
 */
void hip_sadb_init() {
	memset(hip_sadb, 0, sizeof(hip_sadb));
	memset(hip_sadb_dst, 0, sizeof(hip_sadb_dst));
	lsi_temp = NULL;
    memset(hip_proto_sel, 0, sizeof(hip_proto_sel));
}

int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
    struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst, __u16 sport,
    __u16 dport, int direction, __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen,
    __u8 *a_key, __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic,
    uint8_t nat_mode, uint8_t esp_prot_transform, unsigned char *esp_prot_anchor)
{
	
	hip_sadb_entry *entry = NULL;
	hip_lsi_entry *lsi_entry = NULL;
	int key_len = 0;
	__u8 key1[8], key2[8], key3[8]; /* for 3-DES */
	struct sockaddr *use_dst, *use_src;
	int err = 0;

	/* type is currently ignored */	
	if (!src || !dst || !a_key)
	{
		HIP_DEBUG("some parameters missing\n");
		return(-1);
	}
	
	entry = &hip_sadb[sadb_hashfn(spi)];
	if (entry->spi && entry->spi==spi)
	{ 
		/* entry already exists */
		HIP_ERROR("the entry already exists\n");
		return(-1);
	} else if (entry->spi) { /* another entry matches hash value */
		/* advance to end of linked list */
		for ( ; entry->next; entry=entry->next);
		/* create a new entry at end of list */
		entry->next = malloc(sizeof(hip_sadb_entry));
		if (!entry->next)
		{
			HIP_ERROR("failed to allocate memory\n");
			return(-1);
		}
		entry = entry->next;
	}
	
	/* add the new entry */
	HIP_DEBUG("adding new sadb entry...\n");
	memset(entry, 0, sizeof(hip_sadb_entry));
	pthread_mutex_lock(&entry->rw_lock);
	entry->mode = mode;
	entry->direction = direction;
	entry->next = NULL;
	entry->spi = spi;
	entry->hit_magic = hitmagic;
	entry->src_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->dst_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->inner_src_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->inner_dst_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	/* hash chains and anchors for esp extension */
	entry->active_hchain = NULL;
	entry->next_hchain = NULL;
	entry->active_anchor = NULL;
	entry->next_anchor = NULL;
	entry->active_transform = 0;
	entry->next_transform = 0;
	entry->tolerance = 0;
	entry->src_port = sport ;
	entry->dst_port = dport ;
	entry->nat_mode = nat_mode;
	entry->usetime_ka.tv_sec = 0;
	entry->usetime_ka.tv_usec = 0;
	memset(&entry->lsi, 0, sizeof(struct sockaddr_storage));
	memset(&entry->lsi6, 0, sizeof(struct sockaddr_storage));
	entry->a_type = a_type;
	entry->e_type = e_type;
	entry->a_keylen = a_keylen;
	entry->e_keylen = e_keylen;
	entry->a_key = (__u8*)malloc(a_keylen);
	if (e_keylen > 0)
		entry->e_key = (__u8*)malloc(e_keylen);
	entry->lifetime = lifetime;
	entry->bytes = 0;
	entry->usetime.tv_sec = 0;
	entry->usetime.tv_usec = 0;
	entry->sequence = 1;
	entry->replay_win = 0;
	entry->replay_map = 0;
	pthread_mutex_unlock(&entry->rw_lock);

	/* malloc error */
	if (!entry->src_addrs || !entry->dst_addrs || !entry->a_key)
	{
		HIP_ERROR("failed to allocate memory\n");
		goto hip_sadb_add_error;
	}
	if ((e_keylen > 0) && !entry->e_key)
	{
		HIP_ERROR("failed to allocate memory\n");
		goto hip_sadb_add_error;
	}

	/* copy addresses */
	pthread_mutex_lock(&entry->rw_lock);
	memset(entry->src_addrs, 0, sizeof(sockaddr_list));
	memset(entry->dst_addrs, 0, sizeof(sockaddr_list));
	memcpy(&entry->src_addrs->addr, src, SALEN(src));
	memcpy(&entry->dst_addrs->addr, dst, SALEN(dst));
	memset(entry->inner_src_addrs, 0, sizeof(sockaddr_list));
	memset(entry->inner_dst_addrs, 0, sizeof(sockaddr_list));

	if (entry->mode == 0 || entry->mode == 3) { 
		memcpy(&entry->inner_src_addrs->addr, inner_src, SALEN(inner_src));
		memcpy(&entry->inner_dst_addrs->addr, inner_dst, SALEN(inner_dst));
	}
	
	// set the esp protection extension transform
	entry->active_transform = esp_prot_transform;
	HIP_DEBUG("entry->active_transform: %u\n", entry->active_transform);
	
	// only set up the anchor or hchain, if esp extension is used
	if (esp_prot_transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		HIP_DEBUG("setting up ESP extension parameters...\n");
		
		/* set up hash chains or anchors depending on the direction */
		if (direction == HIP_SPI_DIRECTION_IN)
		{
			// set anchor for inbound SA
			entry->active_anchor = esp_prot_anchor;
			entry->tolerance = DEFAULT_VERIFY_WINDOW;
		} else
		{
			// set hchain for outbound SA
			err = esp_prot_get_corresponding_hchain(esp_prot_anchor, esp_prot_transform,
					entry->active_hchain);
			
			if (err)
			{
				HIP_ERROR("corresponding hchain not found");
				goto hip_sadb_add_error;
			}
		}
	}
	
	/* copy keys */

	HIP_DEBUG("e_type value is: %d\n", e_type);
	HIP_DEBUG("a_type value is: %d \n", a_type);
	
	HIP_DEBUG("SADB_EALG_3DESCBC value is: %d \n ", SADB_EALG_3DESCBC);
	HIP_DEBUG("SADB_X_EALG_AESCBC value is:%d \n", SADB_X_EALG_AESCBC);
	HIP_DEBUG("SADB_X_EALG_BLOWFISHCBC value is: %d \n", SADB_X_EALG_BLOWFISHCBC);
	
	memcpy(entry->a_key, a_key, a_keylen);
	if (e_keylen > 0)
		memcpy(entry->e_key, e_key, e_keylen);
	if ((e_keylen > 0) && (e_type == SADB_EALG_3DESCBC)) {
		key_len = e_keylen/3;
		memcpy(key1, &e_key[0], key_len);
		memcpy(key2, &e_key[8], key_len);
		memcpy(key3, &e_key[16], key_len);
		des_set_odd_parity((des_cblock*)key1);
		des_set_odd_parity((des_cblock*)key2);
		des_set_odd_parity((des_cblock*)key3);
		err = des_set_key_checked((des_cblock*)key1, entry->ks[0]);
		err += des_set_key_checked((des_cblock*)key2, entry->ks[1]);
		err += des_set_key_checked((des_cblock*)key3, entry->ks[2]);
		if (err)
			HIP_DEBUG("hip_sadb_add: Warning - 3DES key problem.\n");
	} else if ((e_keylen > 0) && (e_type == SADB_X_EALG_AESCBC)) {
		/* AES key differs for encryption/decryption, so we set
		 * it upon first use in the SA */
		entry->aes_key = NULL;
	} else if ((e_keylen > 0) && (e_type == SADB_X_EALG_BLOWFISHCBC)) {
		entry->bf_key = malloc(sizeof(BF_KEY));
		BF_set_key(entry->bf_key, e_keylen, e_key);
	}
	pthread_mutex_unlock(&entry->rw_lock);

	/* add to destination cache for easy lookup via address
	 * for HIP over UDP, HITs are used and not outer dst addr 
	 * 	which can be the same for multiple hosts 
	 */
	
	HIP_DEBUG("IPsec mode is %d \n", entry->mode);

	use_src = (entry->mode == 3 || entry->mode == 0 ) ? inner_src : src;
	use_dst = (entry->mode == 3 || entry->mode == 0 ) ? inner_dst : dst;
	if (!use_src || !use_dst)
		goto hip_sadb_add_error;
	
	
	hip_sadb_add_dst_entry(use_dst, entry);



	/*FIXME, if LSI supported */

	
	/* HIPL does not support LSI right now, FIXME*/

	/* fill in LSI, add entry to destination cache for outbound;
	 * the LSI is needed for both outbound and inbound SAs */
	if ((lsi_entry = hip_lookup_lsi_by_addr(use_dst))) {
		if (lsi_entry->lsi4.ss_family == AF_INET) { /* lsi exists? */
			memcpy(&entry->lsi,  &lsi_entry->lsi4, 
				SALEN(&lsi_entry->lsi4));
			hip_sadb_add_dst_entry(SA(&lsi_entry->lsi4), entry);
		
			HIP_DEBUG("lsi_entry belongs to AF_INET\n");

		}
		if (lsi_entry->lsi6.ss_family == AF_INET6) { /* lsi6 exists? */
			memcpy(&entry->lsi6, &lsi_entry->lsi6,
				SALEN(&lsi_entry->lsi6));
			hip_sadb_add_dst_entry(SA(&lsi_entry->lsi6), entry);
			
			HIP_DEBUG("lsi_entry belongs to AF_INET6\n");

		}
	} else if ((lsi_entry = hip_lookup_lsi_by_addr(use_src))) {

		HIP_DEBUG("lsi_entry from use_src\n");

		memcpy(&entry->lsi,  &lsi_entry->lsi4, SALEN(&lsi_entry->lsi4));
		memcpy(&entry->lsi6, &lsi_entry->lsi6, SALEN(&lsi_entry->lsi6));
		lsi_entry->send_packets = 1;
		/* Once an incoming SA is added (outgoing is always added 
		 * first in hipd) then we need to send unbuffered packets.
		 * While that could be done here, instead we decrease the
		 * timeout of hip_esp_input so it is done later. Otherwise,
		 * experience shows a race condition where the first
		 * unbuffered packet arrives at the peer before its SAs
		 * are built. */
		g_read_usec = 200000;
	}
	return(0);

hip_sadb_add_error:
	if (entry) /* take care of deallocation and unlinking from list */
		hip_sadb_delete_entry(entry);
		
	return(-1);
}

/*
 * hip_sadb_delete()
 *
 * Remove an SADB entry from the SADB hash table.
 * type, src, dst are provided for compatibility but are currently ignored.
 * First free dynamically-allocated elements, then unlink the entry and
 * either replace it or zero it.
 */ 
int hip_sadb_delete(__u32 type, struct sockaddr *src, struct sockaddr *dst,
    __u32 spi) {
	hip_sadb_entry *entry;
	hip_lsi_entry *lsi_entry;

	if (!(entry = hip_sadb_lookup_spi(spi)))
		return(-1);

	pthread_mutex_lock(&entry->rw_lock);
	if (entry->direction == 2) {
		hip_sadb_delete_dst_entry(SA(&entry->lsi));
		hip_sadb_delete_dst_entry(SA(&entry->lsi6));
	}
	if (entry->mode==3) { /*(HIP_ESP_OVER_UDP) */
		hip_sadb_delete_dst_entry(SA(&entry->inner_dst_addrs->addr));
	} else {
		hip_sadb_delete_dst_entry(dst);
	}

	/* set LSI entry to expire */
	if ((lsi_entry = hip_lookup_lsi(SA(&entry->lsi))))
		lsi_entry->creation_time.tv_sec = 0;

	pthread_mutex_unlock(&entry->rw_lock);
	hip_sadb_delete_entry(entry);

	return(0);
}

int hip_sadb_delete_entry(hip_sadb_entry *entry)
{
	hip_sadb_entry *prev, *tmp;
	int hash;
	if (!entry)
		return(-1);

	pthread_mutex_lock(&entry->rw_lock);
	/* free address lists */
	if (entry->src_addrs)
		free_addr_list(entry->src_addrs); 
	if (entry->dst_addrs)
		free_addr_list(entry->dst_addrs);
	if (entry->inner_src_addrs)
		free_addr_list(entry->inner_src_addrs);
	if (entry->inner_dst_addrs)
		free_addr_list(entry->inner_dst_addrs);
	
	/* securely erase keys */
	if (entry->a_key) {
		memset(entry->a_key, 0, entry->a_keylen);
		free(entry->a_key);
	}
	if (entry->e_key) {
		memset(entry->e_key, 0, entry->e_keylen);
		free(entry->e_key);
	}
	
	/* adjust linked-list pointers */
	hash = sadb_hashfn(entry->spi);
	prev = NULL;
	for (tmp = &hip_sadb[hash]; tmp; tmp=tmp->next) {
		if (tmp == entry)
			break;
		prev = tmp;
	}
	pthread_mutex_unlock(&entry->rw_lock);
	if (prev) { /* unlink the entry from the list */
		prev->next = entry->next;
		memset(entry, 0, sizeof(hip_sadb_entry));
		free(entry);
	} else if (entry->next) { /* replace entry in table w/next in list */
		tmp = entry->next;
		memcpy(&hip_sadb[hash], tmp, sizeof(hip_sadb_entry));
		memset(tmp, 0, sizeof(hip_sadb_entry));
		free(tmp);
	} else { /* no prev or next, just erase single entry */
		memset(entry, 0, sizeof(hip_sadb_entry));
	}
	return(0);
}

/*
 * sadb_hashfn()
 *
 * SADB entries are index by hash of their SPI.
 * Since SPIs are assumedly randomly allocated, distribution of this should
 * be uniform and the hash function given here is very simple (and fast!).
 */
int sadb_hashfn(uint32_t spi) 
{
	return(spi % SADB_SIZE);
}

/*
 * sadb_dst_hashfn()
 *
 * A destination cache mainains IP to SADB entry mappings, for efficient
 * lookup for outgoing packets.
 */
int sadb_dst_hashfn(struct sockaddr *dst)
{
	uint32_t addr;
	struct sockaddr_in6 *addr6;
	
	if (dst->sa_family == AF_INET) {
		addr = htonl(((struct sockaddr_in*)dst)->sin_addr.s_addr);
	} else {
		addr6 = (struct sockaddr_in6*)dst;
		addr = addr6->sin6_addr.s6_addr32[0];
		addr ^= addr6->sin6_addr.s6_addr32[1];
		addr ^= addr6->sin6_addr.s6_addr32[2];
		addr ^= addr6->sin6_addr.s6_addr32[3];
	}
	
	return(addr % SADB_SIZE);
}

/*
 * hip_sadb_add()
 *
 * Add an SADB entry to the SADB hash table.
 */ 

void free_addr_list(sockaddr_list *a)
{
	sockaddr_list *a_next;
	while(a) {
		a_next = a->next;
		free(a);
		a = a_next;
	}
}


/*
 * create_lsi_entry()
 *
 * Allocate a new LSI entry and link it in the global list lsi_temp.
 */
hip_lsi_entry *create_lsi_entry(struct sockaddr *lsi)
{
	hip_lsi_entry *entry, *tmp;

	entry = (hip_lsi_entry*) malloc(sizeof(hip_lsi_entry));
	if (!entry) {
		printf("create_lsi_entry: malloc error!\n");
		return NULL;
	}
	memset(entry, 0, sizeof(hip_lsi_entry));
	entry->next = NULL;
	if (lsi->sa_family == AF_INET) {
		memcpy(&entry->lsi4, lsi, SALEN(lsi));
		memset(&entry->lsi6, 0, sizeof(entry->lsi6));
	} else {
		memset(&entry->lsi4, 0, sizeof(entry->lsi4));
		memcpy(&entry->lsi6, lsi, SALEN(lsi));
	}
	entry->num_packets = 0;
	entry->next_packet = 0;
	entry->send_packets = 0;
	gettimeofday(&entry->creation_time, NULL);
	
	/* add it to the list */
	if (!lsi_temp) {
		lsi_temp = entry;
	} else {
		for (tmp = lsi_temp; tmp->next; tmp = tmp->next);
		tmp->next = entry;
	}
	return(entry);
}

/*
 * hip_remove_expired_lsi_entries()
 *
 * LSI entries are only used temporarily, so sadb_add() can know the LSI
 * mapping and for embargoed packets that are buffered. This checks the
 * creation time and removes those entries older than LSI_ENTRY_LIFETIME.
 */
void hip_remove_expired_lsi_entries()
{
	struct timeval now;
	hip_lsi_entry *entry, *tmp, *prev = NULL;

	gettimeofday(&now, NULL);
	entry = lsi_temp;
	while (entry) {
		if (entry->send_packets)
			unbuffer_packets(entry);
		if ((now.tv_sec - entry->creation_time.tv_sec) > 
			LSI_ENTRY_LIFETIME) {
			/* unlink the entry */
			if (prev)
				prev->next = entry->next;
			else 
				lsi_temp = entry->next;
			/* delete the entry */
			tmp = entry;
			entry = entry->next;
			free(tmp);
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}

/*
 * hip_add_lsi()
 *
 * Adds an <IP,LSI> mapping to the temporary LSI list.
 * This list is used only on SA creation, to provide the <IP,LSI> mapping
 * before an SADB entry exists.
 */
void hip_add_lsi(struct sockaddr *addr, struct sockaddr *lsi4, 
		struct sockaddr *lsi6)
{
	hip_lsi_entry *entry;

	if ( !(entry = hip_lookup_lsi(lsi4)) &&
	     !(entry = hip_lookup_lsi(lsi6)) ) {
		entry = create_lsi_entry(lsi4);
	} else { /* refresh timer for existing LSI entry */
		gettimeofday(&entry->creation_time, NULL);
	}
	if (lsi6)
		memcpy(&entry->lsi6, lsi6, SALEN(lsi6));
	memcpy(&entry->addr, addr, SALEN(addr));
}

/*
 * hip_lookup_lsi_by_addr()
 *
 * LSI entry lookup based on corresponding destination (peer) address.
 */
hip_lsi_entry *hip_lookup_lsi_by_addr(struct sockaddr *addr)
{
	hip_lsi_entry *entry;
	// we will only get hits here
	hip_hit_t *hit = (hip_hit_t *) hip_cast_sa_addr(addr);
	
	for (entry = lsi_temp; entry; entry = entry->next) {
		if (IN6_ARE_ADDR_EQUAL((hip_hit_t *)(hip_cast_sa_addr(&entry->addr)), hit)) {
			return(entry);
		}
	}
	return(NULL);
}

/*
 * hip_lookup_lsi()
 *
 * LSI entry lookup based on the LSI.
 */
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi)
{
	hip_lsi_entry *entry;
	struct sockaddr_storage *entry_lsi;
	hip_hit_t *hit = (hip_hit_t *) hip_cast_sa_addr(lsi);

	for (entry = lsi_temp; entry; entry = entry->next) {
		entry_lsi = (lsi->sa_family == AF_INET) ? &entry->lsi4 : 
							  &entry->lsi6;
		if (IN6_ARE_ADDR_EQUAL((hip_hit_t *)(hip_cast_sa_addr(entry_lsi)), hit))
			return(entry);
	}
	return(NULL);
}

/*
 * hip_sadb_lookup_spi()
 *
 * Lookup an SADB entry based on SPI, for incoming ESP packets.
 */ 
hip_sadb_entry *hip_sadb_lookup_spi(__u32 spi) {
	hip_sadb_entry *entry;
	for (entry = &hip_sadb[sadb_hashfn(spi)]; entry; entry = entry->next) {
		if (entry->spi == spi)
			return entry;
	}
	return(NULL);
}

/*
 * hip_sadb_add_dst_entry()
 *
 * Add an address to the destination cache, pointing to corresponding
 * SADB entry. This allows quick lookups based on address (LSI), since
 * the SADB hashes on SPI.
 */
int hip_sadb_add_dst_entry(struct sockaddr *addr, hip_sadb_entry *entry)
{
	hip_sadb_dst_entry *dst_entry, *last;
	hip_hit_t *hit = (hip_hit_t *) hip_cast_sa_addr(addr);
	
	if (!addr || !entry)
		return(-1);

	/* check for existing entry (address is same) and
	 * just update the entry ptr */
	for (dst_entry = &hip_sadb_dst[sadb_dst_hashfn(addr)];
		dst_entry; dst_entry = dst_entry->next) {
		last = dst_entry;
		if (dst_entry->sadb_entry &&
			IN6_ARE_ADDR_EQUAL((hip_hit_t *)(hip_cast_sa_addr(&dst_entry->addr)), hit))
		{
			dst_entry->sadb_entry = entry;
			return(0);
		}
	}

	/* when hash slot is occupied, add to the end of the list */
	if (last->sadb_entry) {
		dst_entry = (hip_sadb_dst_entry*) 
			    malloc(sizeof(hip_sadb_dst_entry));
		last->next = dst_entry;
	} else {
		dst_entry = last;
	}

	memset(dst_entry, 0, sizeof(hip_sadb_dst_entry));
	dst_entry->next = NULL;
	memcpy(&dst_entry->addr, addr, SALEN(addr));
	dst_entry->sadb_entry = entry;
	return(0);
}

/*
 * hip_sadb_delete_dst_entry()
 *
 * Delete an SADB entry based on destination address (LSI).
 */ 
int hip_sadb_delete_dst_entry(struct sockaddr *addr) {
	hip_sadb_dst_entry *entry, *prev, *next;
	hip_hit_t *hit = (hip_hit_t *) hip_cast_sa_addr(addr);
	
	prev = NULL;
	for (entry = &hip_sadb_dst[sadb_dst_hashfn(addr)]; 
	     entry; entry = entry->next) {
		if (!IN6_ARE_ADDR_EQUAL((hip_hit_t *)(hip_cast_sa_addr(&entry->addr)), hit))
		{
			prev = entry;
			continue;
		}
		/* entry was found */
		if (prev) {
			prev->next = entry->next;
			memset(entry, 0, sizeof(hip_sadb_dst_entry));
			free(entry);
		} else if (entry->next) { /* no prev, next replaces it */
			next = entry->next;
			memcpy(entry, next, sizeof(hip_sadb_dst_entry));
			memset(next, 0, sizeof(hip_sadb_dst_entry));
			free(next);
		} else { /* no prev, next - just erase it */
			memset(entry, 0, sizeof(hip_sadb_dst_entry));
		}
		return(0);
	}
	return(-1);
}


/*
 * hip_sadb_lookup_addr()
 *
 * Lookup an SADB entry based on destination address (LSI), for outgoing
 * ESP packets. Uses the destination cache.
 */ 
hip_sadb_entry *hip_sadb_lookup_addr(struct sockaddr *addr) {
	hip_sadb_dst_entry *entry;
	hip_hit_t *hit = (hip_hit_t *) hip_cast_sa_addr(addr);
	
	for (entry = &hip_sadb_dst[sadb_dst_hashfn(addr)]; 
	     entry; entry = entry->next) {
		if ((addr->sa_family == entry->addr.ss_family) &&
				IN6_ARE_ADDR_EQUAL((hip_hit_t *)(hip_cast_sa_addr(&entry->addr)), hit))
		{
			return(entry->sadb_entry);
		}
	}
	return(NULL);
}

/*
 * hip_sadb_get_next()
 *
 * Return the next valid outgoing SADB entry from the table, starting from
 * placemark if supplied.
 */
hip_sadb_entry *hip_sadb_get_next(hip_sadb_entry *placemark)
{
	int i;
	hip_sadb_entry *entry, *prev_entry=NULL;

	/* step through entire hash table */
	for (i=0; i < SADB_SIZE; i++) {
		/* no entry in this slot */
		if (!hip_sadb[i].spi) 
			continue;
		/* no placemark, return first valid outgoing entry */
		if (!placemark && hip_sadb[i].direction==2)
			return(&hip_sadb[i]);
		/* search for placemark, set prev_entry to flag that the
		 * next should be returned 
		 */
		for (entry = &hip_sadb[i]; entry; entry = entry->next) {
			/* prev_entry is placemark, return next outgoing entry*/
			if (prev_entry && entry->direction==2) 
				return(entry);
			/* look for placemark */
			else if (entry==placemark)
				prev_entry = entry;
		}
	}
	/* no more entries */
	return(NULL);
}
#endif

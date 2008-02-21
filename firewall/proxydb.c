#include "proxydb.h"


/**
 * Maps function @c func to every HA in HIT hash table. The hash table is
 * LOCKED while we process all the entries. This means that the mapper function
 * MUST be very short and _NOT_ do any operations that might sleep!
 *
 * @param func a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       negative if an error occurs. If an error occurs during
 *               traversal of a the HIT hash table, then the traversal is
 *               stopped and function returns. Returns the last return value of
 *               applying the mapper function to the last element in the hash
 *               table.
 */
int hip_for_each_proxy_db(int (*func)(hip_ha_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_proxy_t *this;
	hip_list_t *item, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hadb_hit);
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("list_for_each_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (fail)
			goto out_err;
	}

 out_err:	
	HIP_UNLOCK_HT(&hadb_hit);
	return fail;
}

unsigned long hip_hash_proxy_db(const hip_proxy_t *p)
{
     hip_hit_t hitpair[2];
     uint8_t hash[HIP_AH_SHA_LEN];

     if(p == NULL || &(p->addr_our) == NULL || &(p->addr_peer) == NULL)
     {
	  return 0;
     }
     
     /* The HIT fields of an host association struct cannot be assumed to be
	alligned consecutively. Therefore, we must copy them to a temporary
	array. */
     memcpy(&hitpair[0], &(p->addr_our), sizeof(p->addr_our));
     memcpy(&hitpair[1], &(p->addr_peer), sizeof(p->addr_peer));
     
     hip_build_digest(HIP_DIGEST_SHA1, (void *)hitpair, sizeof(hitpair), hash);
     
     return *((unsigned long *)hash);
}

int hip_compare_proxy_db(const hip_proxy_t *ha1, const hip_proxy_t *ha2)
{
     if(ha1 == NULL || &(ha1->addr_our) == NULL || &(ha1->addr_peer) == NULL ||
	ha2 == NULL || &(ha2->addr_our) == NULL || &(ha2->addr_peer) == NULL)
     {
	  return 1;
     }

     return (hip_hash_proxy_db(ha1) != hip_hash_proxy_db(ha2));
}

void hip_init_hadb(void)
{
     /** @todo Check for errors. */
     
     /* The next line initializes the hash table for host associations. Note
	that we are using callback wrappers IMPLEMENT_LHASH_HASH_FN and
	IMPLEMENT_LHASH_COMP_FN defined in the beginning of this file. These
	provide automagic variable casts, so that all elements stored in the
	hash table are cast to hip_ha_t. Lauri 09.10.2007 16:58. */
	hip_proxy_db = hip_ht_init(LHASH_HASH_FN(hip_hash_proxy_db),
				   LHASH_COMP_FN(hip_compare_proxy_db));
}



void hip_uninit_proxy_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_proxy_t *entry;
	
	list_for_each_safe(item, tmp, hip_proxy_db, i)
	{
		entry = list_entry(item);
		hip_ht_delete(hip_proxy_db, entry);
	}  

}

int hip_proxy_add_entry(struct in6_addr *addr_our, struct in6_addr *addr_peer)
{
	hip_proxy_t *tmp = NULL, *new_item = NULL;
	int err = 0;
	
	new_item = (hip_proxy_t *)malloc(sizeof(hip_proxy_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}
	
	memset(new_item, 0, sizeof(hip_proxy_t));
	ipv6_addr_copy(&new_item->addr_our, addr_our);
	ipv6_addr_copy(&new_item->addr_peer, addr_peer);
	
	err = hip_ht_add(hip_proxy_db, new_item);

	return err;
}


hip_proxy_t *hip_proxy_find_by_addr(struct in6_addr *addr, struct in6_addr *addr2)
{
	hip_proxy_t p, *ret;
	memcpy(&p.addr_our, addr, sizeof(struct in6_addr));
	memcpy(&p.addr_peer, addr2, sizeof(struct in6_addr));

	return hip_ht_find(hip_proxy_db, &p);
}

hip_proxy_t *hip_proxy_find_by_hit(hip_hit_t *hit_our, hit_hit_t *hit_peer)
{
	int i = 0, fail = 0;
	hip_proxy_t *this;
	hip_list_t *item, *tmp;

	list_for_each_safe(item, tmp, hip_proxy_db, i)
	{
		this = list_entry(item);
		if (!ipv6_addr_cmp(&this->hit_our, hit_our) &&
		    !ipv6_addr_cmp(&this->hit_peer, hit_peer))
			return this;
	}
	return NULL;
}

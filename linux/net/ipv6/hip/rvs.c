/* Rendezvous Server functionality for HIP.
 *
 * Kristian Slavov, 2004
 *
 */

#include "rvs.h"

HIP_RVA *hip_rva_allocate(int gfpmask)
{
	int i;
	HIP_RVA *res;

	res = kmalloc(sizeof(*res), gfpmask);
	if (!res)
		return NULL;

	atomic_set(&res->refcnt, 0);
	SPIN_LOCK_INIT(&res->rva_lock);
	res->lifetime = 0;
	res->type = HIP_TYPE_RVA;
	memset(res->ip_addrs, 0, HIP_RVA_MAX_IPS*sizeof(struct in6_addr));

	return res;
}

/*
 * Must be called from a kernel/user context.
 * Memory is allocated using GFP_KERNEL
 */
HIP_RVA *hip_ha_to_rva(hip_ha_t *ha, int gfpmask)
{
	HIP_RVA *rva;
	struct hip_peer_addr_list_item *item;
	int ipcnt = 0;
	struct in6_addr *tmpbuf;

	rva = hip_rva_allocate(gfpmask);
	if (!rva)
		return NULL;

	HIP_LOCK_HA(ha);
	memcpy(&rva->hit, &ha->hit_peer, sizeof(rva->hit));
	memcpy(&rva->hmac_our, &ha->hmac_our, sizeof(rva->hmac_our));
	memcpy(&rva->hmac_peer, &ha->hmac_peer, sizeof(rva->hmac_peer));

	list_for_each_entry(item, &ha->per_addr_list, list) {
		if (item->address_state != PEER_ADDR_STATE_REACHABLE)
			continue;

		ipv6_addr_copy(&rva->ip_addrs[ipcnt], &item->address);
		ipcnt++;
		if (ipcnt >= HIP_RVA_MAX_IPS)
			break;
	}
	HIP_UNLOCK_HA(ha);

	return rva;

}

static HIP_RVA *hip_rva_find_nolock(struct in6_addr *hit, int hash)
{
	HIP_RVA *rva;

	list_for_each_entry(rva, &hadb_byhit[hash], next_hit) {
		if (state->type != HIP_TYPE_RVA)
			continue;

		hip_hold_rva(rva);

		if (!ipv6_addr_cmp(&rva->hit, hit)) {
			HIP_UNLOCK_HADB;
			return rva;
		} 

		hip_put_rva(rva);
	}
	HIP_UNLOCK_HADB;
	return NULL;
}

HIP_RVA *hip_rva_find(struct in6_addr *hit)
{
	int h;
	HIP_RVA *rva;

	h = hip_hadb_hash_hit(hit);

	HIP_LOCK_HADB;
	rva = hip_rva_find_nolock(hit, h);
	HIP_UNLOCK_HADB;

	return rva;
}


/**
 * hip_rva_insert_ip - Insert/update/overwrite one IP in the RVA.
 * @rva: RVA
 * @ip: IP address to be written to the RVA's IP-list.
 *
 * The IP that is overwritten is the first in the list. This can, and probably
 * will change as we create better algorithms to decide which address to
 * replace (LRU/MRU/etc).
 *
 * Should return 0 always.
 */
void hip_rva_insert_ip(HIP_RVA *rva, struct in6_addr *ip)
{
	HIP_LOCK_RVA(rva);
	ipv6_addr_copy(&rva->ip_addrs[0], ip);
	HIP_UNLOCK_RVA(rva);
}

/**
 * hip_rva_insert_ip_n - Insert/update/overwrite one IP in the RVA.
 * @rva: RVA
 * @ip: IP address to be written to the RVA's IP-list.
 * @n: Repalce n:th element in the IP-list. 0 <= n < HIP_RVA_MAX_IPS
 *
 * The IP that is overwritten is the n:th in the list.
 *
 * Returns 0 if ok, -EINVAL if n >= %HIP_RVA_MAX_IPS
 */
int hip_rva_insert_ip_n(HIP_RVA *rva, struct in6_addr *ip, unsigned int n)
{
	if (n >= HIP_RVA_MAX_IPS)
		return -EINVAL;

	HIP_LOCK_RVA(rva);
	ipv6_addr_copy(&rva->ip_addrs[n], ip);
	HIP_UNLOCK_RVA(rva);
	return 0;
}

/**
 * hip_rva_get_ip - Allocate memory and copy one IP from RVA's list.
 * @rva: RVA
 * @gfpmask: gfpmask
 *
 * Memory is allocated and the IP to copy is selected to be the first one
 * in to RVA's list. Later we might have a better algorithm selecting
 * a better IP. 
 *
 * Returns pointer to an IPv6 address that MUST be freed after use.
 */
struct in6_addr *hip_rva_get_ip(HIP_RVA *rva,int gfpmask)
{
	struct in6_addr *hit;

	hit = kmalloc(sizeof(struct in6_addr), gfpmask);
	if (!hit)
		return NULL;

	HIP_HOLD_RVA(rva);
	ipv6_addr_copy(hit, &rva->ip_addrs[0]);
	HIP_PUT_RVA(rva);
	return hit;
}



/**
 * hip_rva_get_ip - Allocate memory and copy one IP from RVA's list.
 * @rva: RVA
 * @gfpmask: gfpmask
 * @n: Element ot get from the RVA's IP-list.
 *
 * Memory is allocated and the IP to copy is selected to be the first one
 * in to RVA's list. Later we might have a better algorithm selecting
 * a better IP. 
 *
 * Returns pointer to an IPv6 address that MUST be freed after use.
 * Or %NULL if failed.
 */
struct in6_addr *hip_rva_get_ip_n(HIP_RVA *rva, int gfpmask, unsigned int n)
{
	struct in6_addr *hit;

	if (n >= HIP_RVA_MAX_IPS)
		return NULL;

	hit = kmalloc(sizeof(struct in6_addr), gfpmask);
	if (!hit)
		return NULL;

	HIP_HOLD_RVA(rva);
	ipv6_addr_copy(hit, &rva->ip_addrs[n]);
	HIP_PUT_RVA(rva);
	return hit;
}

int hip_rva_insert(HIP_RVA *rva)
{
	HIP_RVA *tmp;
	int h;

	HIP_ASSERT(atomic_read(&rva->refcnt) <= 1); 
	rva->type = HIP_TYPE_RVA; /* just to make sure */

	h = hip_hadb_hash_hit(&rva->hit);
	HIP_LOCK_HADB;
	tmp = hip_rva_find_nolock(&rva->hit, h);
	if (tmp) {
		HIP_UNLOCK_HADB;
		hip_put_rva(tmp);
		return -EEXIST;
	}

	list_add(&rva->next_hit, &hadb_byhit[h]);
	HIP_UNLOCK_HADB;
	hip_hold_rva(rva);

	return 0;
}

/*
 * HIP proxy connection tracking
 */
#include <sys/types.h>
#include "conndb.h"
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "hidb.h"
#include "hashtable.h"

#ifndef ANDROID_CHANGES$
 #include <linux/icmpv6.h>
#else
 #include <linux/icmp.h>
 #include <linux/coda.h>
 #include "icmp6.h"
#endif

static HIP_HASHTABLE *hip_conn_db = NULL;

/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_HASH_FN(hip_hash_proxy_db, const hip_proxy_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_COMP_FN(hip_compare_conn_db, const hip_conn_t *)

unsigned long hip_conn_db_hash(const hip_conn_t *p)
{
	uint8_t hash[HIP_AH_SHA_LEN];

	if(p == NULL)
	{
		return 0;
	}
	
	hip_build_digest(HIP_DIGEST_SHA1, (void *)p, sizeof(struct hip_conn_key), hash);
	return *((unsigned long *)hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_conn_db, const hip_conn_t)

int hip_conn_db_cmp(const hip_conn_t *ha1, const hip_conn_t *ha2)
{
	if(ha1 == NULL || &(ha1->key) == NULL || &(ha1->addr_client) == NULL || &(ha1->addr_peer) == NULL ||
			ha2 == NULL ||  &(ha2->key) == NULL || &(ha2->addr_client) == NULL ||&(ha2->addr_peer) == NULL )
	{
		return 1;
	}

	return (hip_conn_db_hash(ha1) != hip_conn_db_hash(ha2));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_conn_db, const hip_conn_t)

void hip_init_conn_db(void)
{
	/** @todo Check for errors. */

	hip_conn_db = hip_ht_init(LHASH_HASH_FN(hip_conn_db),
				  LHASH_COMP_FN(hip_conn_db));
}

/* still not-static bec. function-call in firewall.c , commented right now
 * but will be completed
 * Hanno 9/12/2009
 */
void hip_uninit_conn_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_conn_t *entry;

	list_for_each_safe(item, tmp, hip_conn_db, i)
	{
		entry = list_entry(item);
		hip_ht_delete(hip_conn_db, entry);
	}  

}

int hip_conn_add_entry(const struct in6_addr *addr_client, 
		       const struct in6_addr *addr_peer,
		       const struct in6_addr *hit_proxy, 
		       const struct in6_addr *hit_peer, 
		       const int protocol, 
		       const int port_client, 
		       const int port_peer,  
		       const int state)
{
	hip_conn_t *new_item = NULL;
	int err = 0;

	new_item = (hip_conn_t *)malloc(sizeof(hip_conn_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

	memset(new_item, 0, sizeof(hip_conn_t));
	ipv6_addr_copy(&new_item->addr_client, addr_client);
	ipv6_addr_copy(&new_item->addr_peer, addr_peer);
	ipv6_addr_copy(&new_item->key.hit_proxy, hit_proxy);
	ipv6_addr_copy(&new_item->key.hit_peer, hit_peer);
	new_item->key.protocol = protocol;
	new_item->key.port_client = port_client;
	new_item->key.port_peer = port_peer;
	//new_item->key.hit_proxy = *hit_proxy;
	//new_item->key.hit_peer = *hit_peer;
	new_item->state = state;
	err = hip_ht_add(hip_conn_db, new_item);
	HIP_DEBUG("conn adds connection state successfully!\n");
	HIP_DEBUG_IN6ADDR("source ip addr",&new_item->addr_client);
	HIP_DEBUG_IN6ADDR("destination ip addr",&new_item->addr_peer);
	HIP_DEBUG("port_client=%d port_peer=%d protocol=%d\n", port_client, port_peer, protocol);

	return err;
}


hip_conn_t *hip_conn_find_by_portinfo(const struct in6_addr *hit_proxy,
				      const struct in6_addr *hit_peer,
				      const int protocol,
				      const int port_client,
				      const int port_peer)
{
	hip_conn_t p, *ret;
	memcpy( (char *)&p.key.hit_proxy, (char *)hit_proxy, sizeof(struct in6_addr));
	memcpy( (char *)&p.key.hit_peer, (char *)hit_peer, sizeof(struct in6_addr));
	p.key.protocol = protocol;
	p.key.port_client = port_client;
	p.key.port_peer = port_peer;
	return hip_ht_find(hip_conn_db, &p);
}

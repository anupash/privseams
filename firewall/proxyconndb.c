/**
 * @file firewall/proxyconndb.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * Connection database for clien-side HIP proxy. Operates only when
 * the proxy mode is enabled.  Documented in more detail in <a
 * href="http://hipl.hiit.fi/index.php?index=publications">Weiwei
 * Hu, HIP Proxy, to be completed during 2010</a>
 *
 * @brief Connection database for client-side HIP proxy
 *
 * @author Weiwei Hu
 */
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "hipd/hidb.h"
#include "lib/core/hashtable.h"
#include "proxyconndb.h"

#ifndef ANDROID_CHANGES
 #include <linux/icmpv6.h>
#else
 #include <linux/icmp.h>
 #include <linux/coda.h>
 #include "libhipandroid/icmp6.h"
#endif

static HIP_HASHTABLE *hip_proxy_conn_db = NULL;


/**
 * Create a hash of the given entry for the hash table
 *
 * @param p the connection entry
 * @return a hash calculated based on the given entry
 **/
unsigned long hip_proxy_conn_db_hash(const hip_proxy_conn_t *p)
{
	uint8_t hash[HIP_AH_SHA_LEN];

	if(p == NULL)
	{
		return 0;
	}
	
	hip_build_digest(HIP_DIGEST_SHA1, (void *)p, sizeof(struct hip_proxy_conn_key), hash);
	return *((unsigned long *)hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_proxy_conn_db, const hip_proxy_conn_t)

/**
 * Compare two hash keys
 *
 * @param ha1 first hash key
 * @param ha2 second hash key
 * @return zero if keys match or one otherwise
 **/
int hip_proxy_conn_db_cmp(const hip_proxy_conn_t *ha1, const hip_proxy_conn_t *ha2)
{
	if(ha1 == NULL || &(ha1->key) == NULL || &(ha1->addr_client) == NULL || &(ha1->addr_peer) == NULL ||
			ha2 == NULL ||  &(ha2->key) == NULL || &(ha2->addr_client) == NULL ||&(ha2->addr_peer) == NULL )
	{
		return 1;
	}

	return (hip_proxy_conn_db_hash(ha1) != hip_proxy_conn_db_hash(ha2));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_proxy_conn_db, const hip_proxy_conn_t)

/**
 * Initialize the proxy database
 **/
void hip_proxy_init_conn_db(void)
{
	/** @todo Check for errors. */

	hip_proxy_conn_db = hip_ht_init(LHASH_HASH_FN(hip_proxy_conn_db),
				  LHASH_COMP_FN(hip_proxy_conn_db));
}

/**
 * Unitialize the proxy database
 **/
void hip_proxy_uninit_conn_db(void)
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_proxy_conn_t *entry;

	list_for_each_safe(item, tmp, hip_proxy_conn_db, i)
	{
		entry = (hip_proxy_conn_t *)list_entry(item);
		hip_ht_delete(hip_proxy_conn_db, entry);
		free(entry);
	}  
	hip_ht_uninit(&hip_proxy_conn_db);

}

/**
 * Add an entry to the connection database of the HIP proxy
 *
 * @param addr_client Addess of the legacy client
 * @param addr_peer Address of the HIP server (responder)
 * @param hit_proxy HIT of the local HIP proxy (initiator)
 * @param hit_peer HIT of the HIP server (responder)
 * @param protocol protocol of the current packet being translated (IPPROTO_TCP, etc)
 * @param port_client TCP or UDP port of the legacy client
 * @param port_peer TCP or UDP port of the server (responder)
 * @param state HIP association state
 * @return zero on success or non-zero on failure
 **/
int hip_proxy_conn_add_entry(const struct in6_addr *addr_client, 
			     const struct in6_addr *addr_peer,
			     const struct in6_addr *hit_proxy, 
			     const struct in6_addr *hit_peer, 
			     const int protocol, 
			     const int port_client, 
			     const int port_peer,  
			     const int state)
{
	hip_proxy_conn_t *new_item = NULL;
	int err = 0;

	new_item = (hip_proxy_conn_t *)malloc(sizeof(hip_proxy_conn_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

	memset(new_item, 0, sizeof(hip_proxy_conn_t));
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
	err = hip_ht_add(hip_proxy_conn_db, new_item);
	HIP_DEBUG("conn adds connection state successfully!\n");
	HIP_DEBUG_IN6ADDR("source ip addr",&new_item->addr_client);
	HIP_DEBUG_IN6ADDR("destination ip addr",&new_item->addr_peer);
	HIP_DEBUG("port_client=%d port_peer=%d protocol=%d\n", port_client, port_peer, protocol);

	return err;
}


/**
 * Find the proxy database entry corresponding to packet's port numbers
 *
 * @param hit_proxy HIT of the local proxy (initiator) 
 * @param hit_peer HIT of the server (responder)
 * @param protocol protocol (IPPROTO_TCP etc) of the packet
 * @param port_client transport protocol port of the legacy client
 * @param port_peer transport protocol port of the server (responder)
 * @return the database entry if found or otherwise NULL
 **/
hip_proxy_conn_t *hip_proxy_conn_find_by_portinfo(const struct in6_addr *hit_proxy,
					    const struct in6_addr *hit_peer,
					    const int protocol,
					    const int port_client,
					    const int port_peer)
{
	hip_proxy_conn_t p;
	memcpy(&p.key.hit_proxy, hit_proxy, sizeof(struct in6_addr));
	memcpy(&p.key.hit_peer, hit_peer, sizeof(struct in6_addr));
	p.key.protocol = protocol;
	p.key.port_client = port_client;
	p.key.port_peer = port_peer;
	return hip_ht_find(hip_proxy_conn_db, &p);
}


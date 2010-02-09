/**
 * @file firewall/cache_port.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * Cache TCP and UDP port information for incoming HIP-related connections for LSIs.
 * When hipfw sees an incoming HIT-based connection, it needs to figure out if
 * it needs to be translated to LSI or not. LSI translation is done only when there is
 * no IPv6 application bound the corresponding TCP or UDP port. The port information
 * can be read from /proc but consumes time. To avoid this overhead, hipfw caches
 * the port information after the first read. Notice that cache is static and hipfw
 * must be restarted if there are changes in the port numbers. This is described in
 * more detail in <a
 * href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>.
 *
 * @brief Cache TCP and UDP port numbers for inbound HIP-related connections to optimize LSI translation
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include "cache_port.h"
#include "cache.h"
#include "lib/core/misc.h"

static HIP_HASHTABLE *firewall_port_cache_db = NULL;

/**
 * add a default entry in the firewall port cache.
 * 
 * @param key the hash key (a string consisting of concatenation of the port, an underscore and the protocol)
 * @param value	the value for the hash key (LSI mode value)
 *
 * @return zero on success or non-zero on failure
 */
static int hip_port_cache_add_new_entry(const char *key, int value){
	firewall_port_cache_hl_t *new_entry = NULL;
	int err = 0;

	HIP_DEBUG("\n");
/*
	HIP_ASSERT(ha_entry != NULL);
*/
	new_entry = (firewall_port_cache_hl_t *)(hip_cache_create_hl_entry());
	memcpy(new_entry->port_and_protocol, key, strlen(key));
	new_entry->traffic_type = value;
	hip_ht_add(firewall_port_cache_db, new_entry);

	return err;
}


/**
 * Search in the port cache database. The key composed of port and protocol
 *
 * @param port the TCP or UDP port to search for
 * @param proto the protocol (IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMPV6)
 *
 * @return the cache entry if found or NULL otherwise
 */
firewall_port_cache_hl_t *hip_firewall_port_cache_db_match(
							   in_port_t port,
							   int proto){
  firewall_port_cache_hl_t *found_entry = NULL;
	char key[FIREWALL_PORT_CACHE_KEY_LENGTH];
	char protocol[10], proto_for_bind[10];
	int bind = FIREWALL_PORT_CACHE_IPV4_TRAFFIC;	//3 - default to ipv4, non-LSI traffic

	memset(protocol, 0, sizeof(protocol));
	memset(proto_for_bind, 0, sizeof(proto_for_bind));
	memset(key, 0, sizeof(key));

	switch(proto){
	case IPPROTO_UDP:
		strcpy(protocol, "udp");
		strcpy(proto_for_bind, "udp6");
		break;
	case IPPROTO_TCP:
		strcpy(protocol, "tcp");
		strcpy(proto_for_bind, "tcp6");
		break;
	case IPPROTO_ICMPV6:
		strcpy(protocol, "icmp");
		break;
	default:
		goto out_err;
		break;
	}

	//assemble the key
	sprintf(key, "%i", (int)port);
	memcpy(key + strlen(key), "_", 1);
	memcpy(key + strlen(key), protocol, strlen(protocol));

	found_entry = (firewall_port_cache_hl_t *)hip_ht_find(
						firewall_port_cache_db,
						(void *)key);

	if(proto == IPPROTO_ICMPV6){
		goto out_err;
	}

	if(!found_entry){
		bind = hip_get_proto_info(ntohs(port), proto_for_bind);
		hip_port_cache_add_new_entry(key, bind);
		found_entry = (firewall_port_cache_hl_t *)hip_ht_find(
						firewall_port_cache_db,
						(void *)key);
	}
	else{
		HIP_DEBUG("Matched port using hash\n");
	}

out_err:
	return found_entry;
}



/**
 * Generate the hash information that is used to index the table
 *
 * @param ptr pointer to the hit used to assemble the hash
 *
 * @return hash value
 */
static unsigned long hip_firewall_port_hash_key(const void *ptr){
        char *key = (char *)(&((firewall_port_cache_hl_t *)ptr)->port_and_protocol);
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, key, sizeof(*key), hash);     
	return *((unsigned long *)hash);

}


/**
 * Compare two keys for the hashtable
 *
 * @param ptr1 pointer to the first key
 * @param ptr2 pointer to the second key
 *
 * @return 0 if hashes identical, otherwise 1
 */
static int hip_firewall_match_port_cache_key(const void *ptr1, const void *ptr2){
	return (hip_firewall_port_hash_key(ptr1) != hip_firewall_port_hash_key(ptr2));
}

/**
 * Initialize port cache database
 * 
 */
void hip_firewall_port_cache_init_hldb(void){
	firewall_port_cache_db = hip_ht_init(hip_firewall_port_hash_key,
					hip_firewall_match_port_cache_key);
}

/**
 * Initialize port cache database
 * 
 */
void hip_firewall_port_cache_uninit_hldb(void){
	int i;
	firewall_port_cache_hl_t *this = NULL;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_port_cache_db);

	list_for_each_safe(item, tmp, firewall_port_cache_db, i)
	{
		this = (firewall_port_cache_hl_t *)list_entry(item);
		hip_ht_delete(firewall_port_cache_db, this);
		free(this);
	}
	HIP_UNLOCK_HT(&firewall_port_cache_db);
        hip_ht_uninit(&firewall_port_cache_db);
	HIP_DEBUG("End hldbdb delete\n");
}



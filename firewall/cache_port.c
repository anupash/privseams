#include "firewall/cache_port.h"
#include "firewall/cache.h"
#include "libhipcore/misc.h"

static HIP_HASHTABLE *firewall_port_cache_db;

/**
 * port_cache_add_new_entry:
 * Adds a default entry in the firewall port cache.
 * 
 * @param key	self-evident
 * @param value	self-evident
 *
 * @return	error if any
 */
static int port_cache_add_new_entry(const char *key, int value){
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
 * firewall_port_cache_db_match:
 * Search in the port cache database the key composed of this port and protocol
 */
firewall_port_cache_hl_t *firewall_port_cache_db_match(
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
		port_cache_add_new_entry(key, bind);
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
 * hip_firewall_port_hash_key:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the hit used to make the hash
 *
 * @return hash information
 */
static unsigned long hip_firewall_port_hash_key(const void *ptr){
        char *key = (char *)(&((firewall_port_cache_hl_t *)ptr)->port_and_protocol);
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, key, sizeof(*key), hash);     
	return *((unsigned long *)hash);

}


/**
 * hip_firewall_match_port_cache_key:
 * Compares two port_and_protocol keys
 *
 * @param ptr1: pointer to key
 * @param ptr2: pointer to key
 *
 * @return 0 if hashes identical, otherwise 1
 */
static int hip_firewall_match_port_cache_key(const void *ptr1, const void *ptr2){
	return (hip_firewall_port_hash_key(ptr1) != hip_firewall_port_hash_key(ptr2));
}


void firewall_port_cache_init_hldb(void){
	firewall_port_cache_db = hip_ht_init(hip_firewall_port_hash_key,
					hip_firewall_match_port_cache_key);
}


/*
 * libinet6 wrap_db.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */
#ifdef CONFIG_HIP_OPPORTUNISTIC
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#ifdef CONFIG_HIP_CORPORATE
#  include "lhashtable.h"
#else
#  include "hashtable.h"
#endif
#include "hadb.h"
#include "wrap_db.h"

HIP_HASHTABLE socketdb;
static struct list_head socketdb_by_pid_socket_list[HIP_SOCKETDB_SIZE]= { 0 };

int hip_exists_translation(int pid, int socket)
{
	hip_opp_socket_t *entry = NULL;

	entry = hip_socketdb_find_entry(pid, socket);
	if(entry) {
		if(entry->pid == pid && entry->orig_socket == socket)
			return 1;
		else
			return 0;
	} else
		return 0;
}

inline int hip_hash_pid_socket(const void *hashed_pid_socket, int range)
{
	int hash = 0;
	
	_HIP_DEBUG("range %d\n", range);
	
	hash = *(int*)hashed_pid_socket;
	_HIP_DEBUG("hash %d\n", hash);
	
	//int hashed = 0;
	//hashed = hash % range;
	_HIP_DEBUG("hashed %d\n", hashed);
	return hash % range;
}

inline int hip_socketdb_match(const void *key_1, const void *key_2)
{
	_HIP_DEBUG("key_1=%d key_2=%d \n", *(int *)key_1, *(int *)key_2);
	return *(int *)key_1 == *(int *)key_2;
}

inline void hip_socketdb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, struct hip_opp_socket_entry);
}
inline void hip_socketdb_put_entry(void *entry)
{  	
	HIP_DB_PUT_ENTRY(entry, struct hip_opp_socket_entry,
			 hip_socketdb_del_entry_by_entry);
}

inline void *hip_socketdb_get_key(void *entry)
{
	return &(((hip_opp_socket_t *)entry)->hash_key);
}

inline void hip_xor_pid_socket(int *key, int pid, int socket)
{
	*key = pid ^ socket;
}

void hip_init_socket_db()
{
	memset(&socketdb,0,sizeof(socketdb));
	
	socketdb.head =      socketdb_by_pid_socket_list;
	socketdb.hashsize =  HIP_SOCKETDB_SIZE;
	socketdb.offset =    offsetof(hip_opp_socket_t, next_entry);
	socketdb.hash =      hip_hash_pid_socket;
	socketdb.compare =   hip_socketdb_match;
	socketdb.hold =      hip_socketdb_hold_entry;
	socketdb.put =       hip_socketdb_put_entry;
	socketdb.get_key =   hip_socketdb_get_key;
	
	strncpy(socketdb.name,"SOCKETDB_BYPSOC", 15);
	socketdb.name[15] = 0;
	
	hip_ht_init(&socketdb);
}

void hip_uninit_socket_db()
{
	int i = 0;
	hip_opp_socket_t *item = NULL;
	hip_opp_socket_t *tmp = NULL;
	
	_HIP_DEBUG("DEBUG: DUMP SOCKETDB LISTS\n");
	//hip_socketdb_dump();
	
	_HIP_DEBUG("DELETING\n");
	//  hip_ht_uninit();
	for(i = 0; i < HIP_SOCKETDB_SIZE; i++)
	{
		list_for_each_entry_safe(item, tmp,
		                         &socketdb_by_pid_socket_list[i],
		                         next_entry)
		{
			if (atomic_read(&item->refcnt) > 2)
				HIP_ERROR("socketdb: %p, in use while removing it from socketdb\n", item);
			hip_socketdb_put_entry(item);
		}
	}  
}

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	_HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
		  entry->pid, entry->orig_socket);
	HIP_LOCK_SOCKET(entry);
	hip_ht_delete(&socketdb, entry);
	HIP_UNLOCK_SOCKET(entry);
	HIP_FREE(entry);
}
/**
 * This function searches for a hip_opp_socket_t entry from the socketdb
 * by pid and orig_socket.
 */
//hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket)
{
        int key = 0;
		
	hip_xor_pid_socket(&key, pid, socket);
	_HIP_DEBUG("pid %d socket %d computed key\n", pid, socket, key);

	return (hip_opp_socket_t *)hip_ht_find(&socketdb, (void *)&key);
}

void hip_socketdb_dump()
{
	int i;
	char src_ip[INET6_ADDRSTRLEN] = "\0";
	char dst_ip[INET6_ADDRSTRLEN] = "\0";
	char src_hit[INET6_ADDRSTRLEN] = "\0";
	char dst_hit[INET6_ADDRSTRLEN] = "\0";
	hip_opp_socket_t *item = NULL;
	hip_opp_socket_t *tmp = NULL;

	HIP_DEBUG("start socketdb dump\n");

	HIP_LOCK_HT(&socketdb);
	
	for(i = 0; i < HIP_SOCKETDB_SIZE; i++) {
		if (!list_empty(&socketdb_by_pid_socket_list[i])) {
			HIP_DEBUG("HT[%d]\n", i);
			list_for_each_entry_safe(item, tmp,
					     &(socketdb_by_pid_socket_list[i]),
					     next_entry) {
				hip_in6_ntop(SA2IP(&item->orig_local_id),
					     src_ip);
				hip_in6_ntop(SA2IP(&item->orig_peer_id),
					     dst_ip);
				hip_in6_ntop(SA2IP(&item->translated_local_id),
					     src_hit);
				hip_in6_ntop(SA2IP(&item->translated_peer_id),
					     dst_hit);

				HIP_DEBUG("pid=%d orig_socket=%d new_socket=%d hash_key=%d domain=%d type=%d protocol=%d \
src_ip=%s dst_ip=%s src_hit=%s dst_hit=%s lock=%d refcnt=%d\n",
					  item->pid, item->orig_socket,
					  item->translated_socket,
					  item->hash_key, item->domain,
					  item->type, item->protocol,
					  src_ip, dst_ip, src_hit, dst_hit,
					  item->lock, item->refcnt);
			}
		}
	}
	HIP_UNLOCK_HT(&socketdb);
	HIP_DEBUG("end socketdb dump\n");
}

hip_opp_socket_t *hip_create_opp_entry() 
{
	hip_opp_socket_t * entry = NULL;
	
	entry = (hip_opp_socket_t *)malloc(sizeof(hip_opp_socket_t));
	if (!entry){
		HIP_ERROR("hip_opp_socket_t memory allocation failed.\n");
		return NULL;
	}
	
	memset(entry, 0, sizeof(*entry));
	
	INIT_LIST_HEAD(&entry->next_entry);
	
	HIP_LOCK_SOCKET_INIT(entry);
	atomic_set(&entry->refcnt, 0);
	HIP_UNLOCK_SOCKET_INIT(entry);
 out_err:
	return entry;
}


//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_socketdb_add_entry(int pid, int socket)
{
	int err = 0;
	hip_opp_socket_t *tmp = NULL;
	hip_opp_socket_t *new_item = NULL;
	
	new_item = (hip_opp_socket_t *)malloc(sizeof(hip_opp_socket_t));
	if (!new_item) {                                                     
		HIP_ERROR("new_item malloc failed\n");                   
		err = -ENOMEM;                                               
		return err;
	}
	
	memset(new_item, 0, sizeof(hip_opp_socket_t));
	
	hip_xor_pid_socket(&new_item->hash_key, pid, socket);
	new_item->pid = pid;
	new_item->orig_socket = socket;
	err = hip_ht_add(&socketdb, new_item);
	HIP_DEBUG("pid %d, orig_sock %d are added to HT socketdb, entry=%p\n",
		  new_item->pid, new_item->orig_socket,  new_item); 
	//hip_socketdb_dump();
	
	return err;
}

int hip_socketdb_del_entry(int pid, int socket)
{
	hip_opp_socket_t *entry = NULL;
	
	entry = hip_socketdb_find_entry(pid, socket);
	if (!entry) {
		return -ENOENT;
	}
	hip_socketdb_del_entry_by_entry(entry);
	return 0;
}

#endif // CONFIG_HIP_OPPORTUNISTIC


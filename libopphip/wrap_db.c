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

HIP_HASHTABLE *socketdb;
static hip_list_t socketdb_by_pid_socket_list[HIP_SOCKETDB_SIZE]= { 0 };

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

unsigned long hip_hash_pid_socket(const void *ptr)
{
	unsigned long key = ((hip_opp_socket_t *)ptr)->hash_key;
	_HIP_DEBUG("hip_hash_pid_socket(%p): 0x%x\n", ptr, key);
	return key;
}

int hip_socketdb_match(const void *ptr1, const void *ptr2)
{
	unsigned long key1, key2;
	key1 = ((hip_opp_socket_t *)ptr1)->hash_key;
	key2 = ((hip_opp_socket_t *)ptr2)->hash_key;
	_HIP_DEBUG("key1=0x%x key2=0x%x\n", key1, key2);
	return !(key1 == key2);
}

inline void hip_xor_pid_socket(int *key, int pid, int socket)
{
	*key = pid ^ socket;
}

void hip_init_socket_db()
{
/*	memset(&socketdb, 0, sizeof(socketdb));
	
	socketdb.head =      socketdb_by_pid_socket_list;
	socketdb.hashsize =  HIP_SOCKETDB_SIZE;
	socketdb.offset =    offsetof(hip_opp_socket_t, next_entry);
	socketdb.hash =      hip_hash_pid_socket;
	socketdb.compare =   hip_socketdb_match;
	socketdb.hold =      hip_socketdb_hold_entry;
	socketdb.put =       hip_socketdb_put_entry;
	socketdb.get_key =   hip_socketdb_get_key;
	
	strncpy(socketdb.name, "SOCKETDB_BYPSOC", 15);
	socketdb.name[15] = 0;*/
	
	socketdb = hip_ht_init(hip_hash_pid_socket, hip_socketdb_match);
	if (!socketdb) HIP_ERROR("hip_init_socket_db() error!\n");
}

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	_HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
		  entry->pid, entry->orig_socket);
	HIP_LOCK_SOCKET(entry);
	HIP_FREE(entry);
	hip_ht_delete(socketdb, entry);
	HIP_UNLOCK_SOCKET(entry);
}
void hip_uninit_socket_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_opp_socket_t *entry;
	
	_HIP_DEBUG("DEBUG: DUMP SOCKETDB LISTS\n");
	//hip_socketdb_dump();
	
	_HIP_DEBUG("DELETING\n");
	//  hip_ht_uninit();
	list_for_each_safe(item, tmp, socketdb, i)
	{
//		if (atomic_read(&item->refcnt) > 2)
//			HIP_ERROR("socketdb: %p, in use while removing it from socketdb\n", item);
		entry = list_entry(item);
		hip_socketdb_del_entry_by_entry(entry);
	}  

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

	return (hip_opp_socket_t *)hip_ht_find(socketdb, (void *)&key);
}

void hip_socketdb_dump()
{
	int i;
	char src_ip[INET6_ADDRSTRLEN] = "\0";
	char dst_ip[INET6_ADDRSTRLEN] = "\0";
	char src_hit[INET6_ADDRSTRLEN] = "\0";
	char dst_hit[INET6_ADDRSTRLEN] = "\0";
	hip_list_t *item, *tmp;
	hip_opp_socket_t *entry;

	HIP_DEBUG("start socketdb dump\n");

	HIP_LOCK_HT(&socketdb);
	
	list_for_each_safe(item, tmp, socketdb, i)
	{
		entry = list_entry(item);
		hip_in6_ntop(SA2IP(&entry->orig_local_id), src_ip);
		hip_in6_ntop(SA2IP(&entry->orig_peer_id), dst_ip);
		hip_in6_ntop(SA2IP(&entry->translated_local_id), src_hit);
		hip_in6_ntop(SA2IP(&entry->translated_peer_id), dst_hit);

		HIP_DEBUG("pid=%d orig_socket=%d new_socket=%d hash_key=%d"
		          " domain=%d type=%d protocol=%d"
		          " src_ip=%s dst_ip=%s src_hit=%s"
		          " dst_hit=%s lock=%d refcnt=%d\n",
		          entry->pid, entry->orig_socket,
		          entry->translated_socket,
		          entry->hash_key, entry->domain,
		          entry->type, entry->protocol,
		          src_ip, dst_ip, src_hit, dst_hit,
		          entry->lock, entry->refcnt);
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


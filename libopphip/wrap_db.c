/*
 * libinet6 wrap_db.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef CONFIG_HIP_OPPORTUNISTIC
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <pthread.h>

#include "hashtable.h"
#include "hadb.h"
#include "wrap_db.h"

HIP_HASHTABLE *socketdb;

int hip_exists_translation(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *entry = NULL;

	entry = hip_socketdb_find_entry(pid, socket, tid);

	if(entry) {
		if(entry->pid == pid && entry->orig_socket == socket &&
		   entry->tid == tid)
			return 1;
		else
			return 0;
	} else
		return 0;
}

unsigned long hip_pid_socket_hash(const void *ptr)
{
	hip_opp_socket_t *entry = (hip_opp_socket_t *)ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	/* 
	   The hash table is indexed with three fields: 
	   pid, original socket, tid (thread id)
	 */
	hip_build_digest(HIP_DIGEST_SHA1, entry, sizeof(pid_t)+sizeof(int)+sizeof(pthread_t), hash);

	return *((unsigned long *)hash);

}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_pid_socket, const void)

int hip_socketdb_cmp(const void *ptr1, const void *ptr2)
{
	unsigned long key1, key2;
	
	key1 = hip_pid_socket_hash(ptr1);
	key2 = hip_pid_socket_hash(ptr2);
	_HIP_DEBUG("key1=0x%x key2=0x%x\n", key1, key2);
	return (key1 != key2);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_socketdb, const void)

void hip_init_socket_db()
{
	socketdb = hip_ht_init(LHASH_HASH_FN(hip_pid_socket),
			    LHASH_COMP_FN(hip_socketdb));

	if (!socketdb) HIP_ERROR("hip_init_socket_db() error!\n");
}

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	_HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
		  entry->pid, entry->orig_socket);
	if (!hip_ht_delete(socketdb, entry))
	  HIP_DEBUG("No entry was found to delete.\n");
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
		entry = (hip_opp_socket_t *)list_entry(item);
		hip_socketdb_del_entry_by_entry(entry);
	}  

}

/**
 * This function searches for a hip_opp_socket_t entry from the socketdb
 * by pid and orig_socket.
 */
//hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t opp, *ret;

	opp.pid = pid;
	opp.orig_socket = socket;
	opp.tid = tid;
	_HIP_DEBUG("pid %d socket %d computed key\n", pid, socket);
	
	ret = (hip_opp_socket_t *)hip_ht_find(socketdb, (void *)&opp);

	return ret;
}

void hip_socketdb_dump()
{
	int i;
	hip_list_t *item, *tmp;
	hip_opp_socket_t *entry;

	HIP_DEBUG("start socketdb dump\n");

	//HIP_LOCK_HT(&socketdb);
	
	list_for_each_safe(item, tmp, socketdb, i)
	{
		entry = (hip_opp_socket_t *)list_entry(item);

		HIP_DEBUG("pid=%d orig_socket=%d tid=%d new_socket=%d domain=%d\n",
			  entry->pid, entry->orig_socket, entry->tid,
		          entry->translated_socket,
		          entry->domain);

	}
	
	//HIP_UNLOCK_HT(&socketdb);
	HIP_DEBUG("end socketdb dump\n");
}


//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_socketdb_add_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *new_item = NULL;
	int err = 0;
	
	new_item = (hip_opp_socket_t *)malloc(sizeof(hip_opp_socket_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}
	
	memset(new_item, 0, sizeof(hip_opp_socket_t));
	
	new_item->pid = pid;
	new_item->orig_socket = socket;
	new_item->tid = tid;
	err = hip_ht_add(socketdb, new_item);
	_HIP_DEBUG("pid %d, orig_sock %d, tid %d are added to HT socketdb, entry=%p\n",
		  new_item->pid, new_item->orig_socket, new_item->tid, new_item); 
	//hip_socketdb_dump();

	return err;
}

int hip_socketdb_del_entry(int pid, int socket, pthread_t tid)
{
	hip_opp_socket_t *entry = NULL;

	entry = hip_socketdb_find_entry(pid, socket, tid);
	if (!entry) {
		return -ENOENT;
	}
	hip_socketdb_del_entry_by_entry(entry);

	return 0;
}

#endif // CONFIG_HIP_OPPORTUNISTIC


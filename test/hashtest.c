#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include "debug.h"
#ifdef CONFIG_HIP_CORPORATE
#  include "lhashtable.h"
#else
#  include "hashtable.h"
#endif
#include "hadb.h"
#include "wrap_db.h"

HIP_HASHTABLE socketdb;
//static hip_list_t socketdb_by_pid_socket_list[HIP_SOCKETDB_SIZE]= { 0 };

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
	
	socketdb.head =      socketdb;
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
	for(i = 0; i < HIP_SOCKETDB_SIZE; i++) {
		list_for_each_entry_safe(item, tmp,
					 &socketdb[i],
					 next_entry) {
			if (atomic_read(&item->refcnt) > 2)
				HIP_ERROR("socketdb: %p, in use while removing it from socketdb\n", item);
			hip_socketdb_put_entry(item);
		}
	}  
}

hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket)
{
        int key = 0;
		
	hip_xor_pid_socket(&key, pid, socket);
	_HIP_DEBUG("pid %d socket %d computed key\n", pid, socket, key);

	return (hip_opp_socket_t *)hip_ht_find(&socketdb, (void *)&key);
}

int hip_socketdb_add_entry(pid_t pid, int socket)
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
	HIP_DEBUG("pid %d, orig_sock %d are added to HT socketdb, entry=%p, err = %d\n",
		  new_item->pid, new_item->orig_socket,  new_item, err); 
	err = hip_ht_add(&socketdb, new_item);
	//hip_socketdb_dump();
	
	return err;
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
		if (!list_empty(&socketdb[i])) {
			HIP_DEBUG("HT[%d]\n", i);
			list_for_each_entry_safe(item, tmp,
					     &(socketdb[i]),
					     next_entry) {
				HIP_DEBUG("pid=%d orig_socket=%d new_socket=%d hash_key=%d domain=%d type=%d protocol=%d \
src_ip=%s dst_ip=%s src_hit=%s dst_hit=%s lock=%d refcnt=%d\n",
					  item->pid, item->orig_socket);
			}
		}
	}
	HIP_UNLOCK_HT(&socketdb);
	HIP_DEBUG("end socketdb dump\n");
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

void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	_HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
		  entry->pid, entry->orig_socket);
	HIP_LOCK_SOCKET(entry);
	hip_ht_delete(&socketdb, entry);
	HIP_UNLOCK_SOCKET(entry);
	HIP_FREE(entry);
}

// used to test socketdb
void test_db(){
	pid_t pid = getpid();
	int socket = 1;
	int err = 0;
	hip_opp_socket_t *entry = NULL;
	//  struct hip_opp_socket_entry *entry = NULL;
	
	HIP_DEBUG("testing db\n");

	HIP_DEBUG("1111 pid=%d, socket=%d\n", pid, socket);
	entry =   hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket);
	HIP_ASSERT(!err);
	entry =  hip_socketdb_find_entry(pid, socket);
	hip_socketdb_dump();
	HIP_ASSERT(entry);
	
	//  pid++; 
	socket++;
	HIP_DEBUG("2222 pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket);
	HIP_ASSERT(!err);
	entry = hip_socketdb_find_entry(pid, socket);
	entry->translated_socket = socket+100;
	HIP_ASSERT(entry);
	hip_socketdb_dump();
	
	
	//pid++; 
	socket++;
	HIP_DEBUG("3333 pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	err = hip_socketdb_add_entry(pid, socket);
	HIP_ASSERT(!err);
	entry = NULL;
	entry =  hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(entry);
	hip_socketdb_dump();
	
	HIP_DEBUG("3333  testing del entry\n\n");
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(entry);
	entry = NULL;
	err = hip_socketdb_del_entry(pid, socket);
	HIP_ASSERT(!err);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	
	
	HIP_DEBUG("2222 testing del entry by entry\n\n");
	socket--;
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(entry);
	hip_socketdb_del_entry_by_entry(entry);
	entry = NULL;
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	
	HIP_DEBUG("1111 testing del entry by entry\n\n");
	socket--;
	HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
	entry = NULL;
	entry = hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(entry);
	hip_socketdb_del_entry_by_entry(entry);
	entry = NULL;
	entry =  hip_socketdb_find_entry(pid, socket);
	HIP_ASSERT(!entry);
	hip_socketdb_dump();
	HIP_DEBUG("end of testing db\n");

	HIP_DEBUG("*** success ***\n");
}

int main(int argc, char **argv) {
	hip_init_socket_db();
	test_db();
	hip_uninit_socket_db();
}

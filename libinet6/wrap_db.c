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
#include "hashtable.h"
#include "hadb.h"
//#include "hip.h"
//#include "list.h"
//#include "debug.h"

//struct hip_opp_pid_socket_entry {
//pid_t pid;
//int old_socket;
//int new_socket;
//}
struct hip_opp_socket_entry {
  struct list_head     	next_entry;
  spinlock_t           	lock;
  atomic_t             	refcnt;
  pid_t 		pid;
  int 			old_socket;
  int  			new_socket;
  int 			hash_key;// pid XOR old_socket
  int 	       		domain;
  int 			type;
  int 			protocol;
  struct in6_addr      	src_ip;
  struct in6_addr      	dst_ip;
  struct in6_addr      	src_hit;
  struct in6_addr      	dst_hit;
};

typedef struct hip_opp_socket_entry hip_opp_socket_t;

// not implemented for hs either
#define HIP_LOCK_SOCKET_INIT(entry)
#define HIP_UNLOCK_SOCKET_INIT(entry)
#define HIP_LOCK_SOCKET(entry)  
#define HIP_UNLOCK_SOCKET(entry)
#define HIP_SOCKETDB_SIZE 533

HIP_HASHTABLE socketdb;
static struct list_head socketdb_by_pid_socket_list[HIP_SOCKETDB_SIZE]= { 0 };

void hip_init_socket_db();
void hip_uninit_socket_db();
hip_opp_socket_t *hip_create_opp_entry();
void hip_socketdb_dump();
//void hip_socketdb_get_entry(hip_opp_socket_t *entry, int pid, int socket);
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket);
int hip_socketdb_add_entry(int pid, int socket);
int hip_socketdb_del_entry(int pid, int socket);
int hip_socketdb_add_entry_by_entry(const hip_opp_socket_t *entry); //TODO::implement this func
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry);

int exists_mapping(int pid, int socket)
{
  hip_opp_socket_t *entry = NULL;

  entry = hip_socketdb_find_entry(pid, socket);
  if(entry) {
    if(entry->pid == pid && entry->old_socket == socket)
      return 1;
    else // this should not happen
      assert(0);
  } else
    return 0;
}

inline int hip_socketdb_has_new_socket(const hip_opp_socket_t *entry)
{
  HIP_DEBUG("new socket %d\n", entry->new_socket);
  if(entry)
    return (entry->new_socket > 0);
  else 
    return 0;

}
inline int hip_socketdb_get_old_socket(const hip_opp_socket_t *entry)
{
    return entry->old_socket;
}
inline int hip_socketdb_get_domain(const hip_opp_socket_t *entry)
{
    return entry->domain;
}
inline int hip_socketdb_get_type(const hip_opp_socket_t *entry)
{
    return entry->type;
}
inline int hip_socketdb_get_protocol(const hip_opp_socket_t *entry)
{
    return entry->protocol;
}
inline int hip_socketdb_get_new_socket(const hip_opp_socket_t *entry)
{
    return entry->new_socket;
}
inline void hip_socketdb_modify_old_socket(hip_opp_socket_t *entry, int socket)
{
  entry->old_socket = socket;
}
inline void hip_socketdb_add_new_socket(hip_opp_socket_t *entry, int socket)
{
  entry->new_socket = socket;
}
inline void hip_socketdb_add_domain(hip_opp_socket_t *entry, int domain)
{
  entry->domain = domain;
}
inline void hip_socketdb_add_type(hip_opp_socket_t *entry, int type)
{
  entry->type = type;

}
inline void hip_socketdb_add_protocol(hip_opp_socket_t *entry, int protocol)
{
  entry->protocol = protocol;
}
inline void hip_socketdb_add_src_ip(hip_opp_socket_t *entry, const struct in6_addr *ip)
{
  memcpy(&entry->src_ip, ip, sizeof(entry->src_ip));
}
inline void hip_socketdb_add_dst_ip(hip_opp_socket_t *entry, const struct in6_addr *ip)
{
  memcpy(&entry->dst_ip, ip, sizeof(entry->dst_ip));
}
inline void hip_socketdb_add_src_hit(hip_opp_socket_t *entry, const struct in6_addr *hit)
{
  memcpy(&entry->src_hit, hit, sizeof(entry->src_hit));
}
inline void hip_socketdb_add_dst_hit(hip_opp_socket_t *entry, const struct in6_addr *hit)
{
  memcpy(&entry->dst_hit, hit, sizeof(entry->dst_hit));
} 

inline int hip_hash_pid_socket(const void *hashed_pit_socket, int range)
{
  int hash = 0;

  HIP_DEBUG("range %d\n", range);

  hash = *(int*)hashed_pit_socket;
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
  HIP_DB_PUT_ENTRY(entry, struct hip_opp_socket_entry, hip_socketdb_del_entry_by_entry);
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
  
  HIP_DEBUG("DEBUG: DUMP SOCKETDB LISTS\n");
  hip_socketdb_dump();

  HIP_DEBUG("DELETING\n");
  //  hip_ht_uninit();
  for(i = 0; i < HIP_SOCKETDB_SIZE; i++) {
    list_for_each_entry_safe(item, tmp, &socketdb_by_pid_socket_list[i], next_entry) {
      if (atomic_read(&item->refcnt) > 2)
	HIP_ERROR("socketdb: %p, in use while removing it from socketdb\n", item);
      hip_socketdb_put_entry(item);
    }
  }  
}

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
	HIP_DEBUG("entry=0x%p pid=%d, old_socket=%d\n", entry,
		  entry->pid, entry->old_socket);
	HIP_LOCK_SOCKET(entry);
	hip_ht_delete(&socketdb, entry);
	HIP_UNLOCK_SOCKET(entry);
	HIP_FREE(entry);
}
/**
 * This function searches for a hip_opp_socket_t entry from the socketdb
 * by pid and old_socket.
 */
//hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket)
{
        int key = 0;
		
	hip_xor_pid_socket(&key, pid, socket);
	HIP_DEBUG("pid %d socket %d computed key\n", pid, socket, key);

	return (hip_opp_socket_t *)hip_ht_find(&socketdb, (void *)&key);
}

void hip_socketdb_get_entry(hip_opp_socket_t *entry, int pid, int socket)
{
  // deprecated, do not use

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
      list_for_each_entry_safe(item, tmp, &(socketdb_by_pid_socket_list[i]), next_entry) {
	hip_in6_ntop(&item->src_ip, src_ip);
	hip_in6_ntop(&item->dst_ip, dst_ip);
	hip_in6_ntop(&item->src_hit, src_hit);
	hip_in6_ntop(&item->dst_hit, dst_hit);

	HIP_DEBUG("pid=%d old_socket=%d new_socket=%d hash_key=%d domain=%d type=%d protocol=%d \
src_ip=%s dst_ip=%s src_hit=%s dst_hit=%s lock=%d refcnt=%d\n",
		  item->pid, item->old_socket, item->new_socket,
		  item->hash_key, item->domain, item->type, item->protocol,
		  src_ip, dst_ip, src_hit, dst_hit, item->lock, item->refcnt);
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
  atomic_set(&entry->refcnt,0);
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

  hip_xor_pid_socket(&new_item->hash_key, pid, socket);
  new_item->pid = pid;
  new_item->old_socket = socket;
  new_item->new_socket = 0;

  ipv6_addr_copy(&new_item->src_ip, &in6addr_any);
  ipv6_addr_copy(&new_item->dst_ip, &in6addr_any);
  ipv6_addr_copy(&new_item->src_hit, &in6addr_any);
  ipv6_addr_copy(&new_item->dst_hit, &in6addr_any);
  err = hip_ht_add(&socketdb, new_item);                                     
  HIP_DEBUG("pid %d, old_socket %d are added to HT socketdb, entry=%p\n",
	    new_item->pid, new_item->old_socket,  new_item); 
  hip_socketdb_dump();

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

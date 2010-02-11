/** @file
 * HIP opportunistic database implementation.
 *
 * @author Bing Zhou <bingzhou@cc.hut.fi>
 * @author Miika Komu <miika@iki.fi>
 * @note Distributed under
 * <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <pthread.h>

#include "lib/core/hashtable.h"
#include "hipd/hadb.h"
#include "wrap_db.h"

/** Hash table to store information on translated sockets */
HIP_HASHTABLE *socketdb;

/**
 * check if a given socket has been recorded to the database
 *
 * @param pid process id
 * @param socket socket file descriptor
 * @param tid thread id
 * @return one if socket existists in the database or zero otherwise
 */
int hip_exists_translation(int pid, int socket, pthread_t tid)
{
    hip_opp_socket_t *entry = NULL;

    entry = hip_socketdb_find_entry(pid, socket, tid);

    if (entry) {
        if (entry->pid == pid && entry->orig_socket == socket &&
            entry->tid == tid) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

/**
 * create a hash for the hash table implementation
 *
 * @param ptr the key to index the hash
 * @return hash of the @c key
 */
unsigned long hip_pid_socket_hash(const void *ptr)
{
    hip_opp_socket_t *entry = (hip_opp_socket_t *) ptr;
    uint8_t hash[HIP_AH_SHA_LEN];

    /*
     * The hash table is indexed with three fields:
     * pid, original socket, tid (thread id)
     */
    hip_build_digest(HIP_DIGEST_SHA1, entry,
                     sizeof(pid_t) + sizeof(int) + sizeof(pthread_t), hash);

    return *((unsigned long *) hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_pid_socket, const void)

/**
 * Comparison function for the hash table implementation
 *
 * @param ptr1 hash table key
 * @param ptr2 hash table key
 * @return return 0 if @c ptr1 and @cptr2 match, otherwise 1
 */
int hip_socketdb_cmp(const void *ptr1, const void *ptr2)
{
    unsigned long key1, key2;

    key1 = hip_pid_socket_hash(ptr1);
    key2 = hip_pid_socket_hash(ptr2);
    _HIP_DEBUG("key1=0x%x key2=0x%x\n", key1, key2);
    return key1 != key2;
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_socketdb, const void)

/**
 * Initialize the opportunistic database
 *
 */
void hip_init_socket_db()
{
    socketdb = hip_ht_init(LHASH_HASH_FN(hip_pid_socket),
                           LHASH_COMP_FN(hip_socketdb));

    if (!socketdb) {
        HIP_ERROR("hip_init_socket_db() error!\n");
    }
}

/**
 * delete one entry for the opportunistic database
 *
 * @param entry the oppportunistic entry to be deleted
 */
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
    _HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
               entry->pid, entry->orig_socket);
    if (!hip_ht_delete(socketdb, entry)) {
        HIP_DEBUG("No entry was found to delete.\n");
    }
}

/**
 * uninitialize the opportunistic mode database
 *
 */
void hip_uninit_socket_db()
{
    int i = 0;
    hip_list_t *item, *tmp;
    hip_opp_socket_t *entry;

    _HIP_DEBUG("DEBUG: DUMP SOCKETDB LISTS\n");

    _HIP_DEBUG("DELETING\n");
    list_for_each_safe(item, tmp, socketdb, i)
    {
        entry = (hip_opp_socket_t *) list_entry(item);
        hip_socketdb_del_entry_by_entry(entry);
    }
}

/**
 * This function searches for a hip_opp_socket_t entry from the socketdb
 * by pid and orig_socket.
 *
 * @param pid the pid of the calling sockets API function
 * @param the socket of the calling sockets API function
 * @param tid the thread id of the calling sockets API function
 * @return NULL or the database entry if found
 */
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket, pthread_t tid)
{
    hip_opp_socket_t opp, *ret;

    opp.pid         = pid;
    opp.orig_socket = socket;
    opp.tid         = tid;
    _HIP_DEBUG("pid %d socket %d computed key\n", pid, socket);

    ret             = (hip_opp_socket_t *) hip_ht_find(socketdb, (void *) &opp);

    return ret;
}

/**
 * display the contents of the database
 *
 */
void hip_socketdb_dump()
{
    int i;
    hip_list_t *item, *tmp;
    hip_opp_socket_t *entry;

    HIP_DEBUG("start socketdb dump\n");

    list_for_each_safe(item, tmp, socketdb, i)
    {
        entry = (hip_opp_socket_t *) list_entry(item);

        HIP_DEBUG("pid=%d orig_socket=%d tid=%d new_socket=%d domain=%d\n",
                  entry->pid, entry->orig_socket, entry->tid,
                  entry->translated_socket,
                  entry->domain);
    }

    HIP_DEBUG("end socketdb dump\n");
}

/**
 * add a new translated entry to the opportunistic HIP database
 *
 * @param pid process id of the sockets API function caller
 * @param socket socket descriptor of the sockets API function caller
 * @param tid thread id of the sockets API function caller
 * @return zero on success or non-zero on error
 */
int hip_socketdb_add_entry(int pid, int socket, pthread_t tid)
{
    hip_opp_socket_t *new_item = NULL;
    int err                    = 0;

    new_item = (hip_opp_socket_t *) malloc(sizeof(hip_opp_socket_t));
    if (!new_item) {
        HIP_ERROR("new_item malloc failed\n");
        err = -ENOMEM;
        return err;
    }

    memset(new_item, 0, sizeof(hip_opp_socket_t));

    new_item->pid         = pid;
    new_item->orig_socket = socket;
    new_item->tid         = tid;
    err                   = hip_ht_add(socketdb, new_item);
    _HIP_DEBUG("pid %d, orig_sock %d, tid %d are added to HT socketdb, entry=%p\n",
               new_item->pid, new_item->orig_socket, new_item->tid, new_item);

    return err;
}

/**
 * delete an entry from the opportunistic HIP database
 *
 * @param pid process id of the sockets API function caller
 * @param socket socket descriptor of the sockets API function caller
 * @param tid thread id of the sockets API function caller
 * @return zero on success or non-zero on error
 */
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

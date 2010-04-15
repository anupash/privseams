/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <limits.h>
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "hipd/hadb.h"

struct hip_opp_socket_entry {
    unsigned long           hash_key;     /* pid XOR old_socket */
    pid_t                   pid;
    int                     orig_socket;
    int                     translated_socket;
    int                     domain;
    int                     type;
    int                     protocol;
    int                     local_id_is_translated;
    int                     peer_id_is_translated;
    int                     force_orig;
    struct sockaddr_storage orig_local_id;
    struct sockaddr_storage orig_peer_id;
    struct sockaddr_storage translated_local_id;
    struct sockaddr_storage translated_peer_id;
    socklen_t               orig_local_id_len;
    socklen_t               orig_peer_id_len;
    socklen_t               translated_local_id_len;
    socklen_t               translated_peer_id_len;
};

typedef struct hip_opp_socket_entry hip_opp_socket_t;

HIP_HASHTABLE *socketdb = NULL;

static unsigned long hip_hash_pid_socket(const void *ptr)
{
    unsigned long key = ((hip_opp_socket_t *) ptr)->hash_key;
    _HIP_DEBUG("hip_hash_pid_socket(%p): 0x%x\n", ptr, key);
    return key;
}

static int hip_socketdb_match(const void *ptr1, const void *ptr2)
{
    unsigned long key1, key2;
    key1 = ((hip_opp_socket_t *) ptr1)->hash_key;
    key2 = ((hip_opp_socket_t *) ptr2)->hash_key;
    _HIP_DEBUG("key1=0x%x key2=0x%x\n", key1, key2);
    return key1 != key2;
}

static inline void *hip_socketdb_get_key(void *entry)
{
    return &(((hip_opp_socket_t *) entry)->hash_key);
}

static inline void hip_xor_pid_socket(unsigned int *key, int pid, int socket)
{
    *key = pid ^ socket;
}

static void hip_init_socket_db(void)
{
    socketdb          = (HIP_HASHTABLE *) hip_ht_init(hip_hash_pid_socket,
                                                      hip_socketdb_match);
    if (!socketdb) {
        HIP_ERROR("could not init socketdb!\n");
    }
}

static void hip_uninit_socket_db(void)
{
    int n;
    hip_list_t *item, *tmp;

    list_for_each_safe(item, tmp, socketdb, n)
    {
        free(list_entry(item));
    }

    hip_ht_uninit(socketdb);
}

static hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket)
{
    unsigned int key = 0;

    hip_xor_pid_socket(&key, pid, socket);
    HIP_DEBUG("pid %d socket %d computed key 0x%x\n", pid, socket, key);

    return (hip_opp_socket_t *) hip_ht_find(socketdb, (void *) &key);
}

static int hip_socketdb_add_entry(pid_t pid, int socket)
{
    int err                    = 0;
    hip_opp_socket_t *new_item = NULL;

    new_item = malloc(sizeof(hip_opp_socket_t));
    if (!new_item) {
        HIP_ERROR("new_item malloc failed\n");
        err = -ENOMEM;
        return err;
    }

    memset(new_item, 0, sizeof(hip_opp_socket_t));

    hip_xor_pid_socket((unsigned int *) &new_item->hash_key, pid, socket);
    new_item->pid         = pid;
    new_item->orig_socket = socket;
    HIP_DEBUG("added entry %p %d\n", pid, socket);
    err                   = hip_ht_add(socketdb, new_item);
    if (err) {
        HIP_ERROR("hip_ht_add() failed!\n");
    }

    return err;
}

static void hip_socketdb_dump(void)
{
    int n;
    hip_list_t *item, *tmp;
    hip_opp_socket_t *data;

    HIP_DEBUG("start socketdb dump\n");

    list_for_each_safe(item, tmp, socketdb, n)
    {
        data = (hip_opp_socket_t *) list_entry(item);
        HIP_DEBUG("pid=%d orig_socket=%d new_socket=%d hash_key=%d"
                  " domain=%d type=%d protocol=%d src_ip=%s dst_ip=%s"
                  " src_hit=%s dst_hit=%s lock=%d refcnt=%d\n",
                  data->pid, data->orig_socket);
    }
    HIP_DEBUG("end socketdb dump\n");
}

static void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry)
{
    _HIP_DEBUG("entry=0x%p pid=%d, orig_socket=%d\n", entry,
               entry->pid, entry->orig_socket);
    hip_ht_delete(socketdb, entry);
    free(entry);
}

static int hip_socketdb_del_entry(int pid, int socket)
{
    hip_opp_socket_t *entry = NULL;

    entry = hip_socketdb_find_entry(pid, socket);
    if (!entry) {
        return -ENOENT;
    }
    hip_socketdb_del_entry_by_entry(entry);
    return 0;
}

// used to test socketdb
static void test_db(void)
{
    pid_t pid               = getpid();
    int socket              = 1;
    int err                 = 0;
    hip_opp_socket_t *entry = NULL;

    HIP_DEBUG("testing db\n");

    HIP_DEBUG("1111 pid=%d, socket=%d\n", pid, socket);
    entry =   hip_socketdb_find_entry(pid, socket);
    HIP_ASSERT(!entry);
    err   = hip_socketdb_add_entry(pid, socket);
    HIP_ASSERT(!err);
    entry =  hip_socketdb_find_entry(pid, socket);
    HIP_ASSERT(entry);
    hip_socketdb_dump();

    socket++;
    HIP_DEBUG("2222 pid=%d, socket=%d\n", pid, socket);
    entry                    = NULL;
    entry                    = hip_socketdb_find_entry(pid, socket);
    HIP_ASSERT(!entry);
    err                      = hip_socketdb_add_entry(pid, socket);
    HIP_ASSERT(!err);
    entry                    = hip_socketdb_find_entry(pid, socket);
    HIP_ASSERT(entry);
    entry->translated_socket = socket + 100;
    hip_socketdb_dump();

    socket++;
    HIP_DEBUG("3333 pid=%d, socket=%d\n", pid, socket);
    entry = NULL;
    entry = hip_socketdb_find_entry(pid, socket);
    HIP_ASSERT(!entry);
    err   = hip_socketdb_add_entry(pid, socket);
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
    err   = hip_socketdb_del_entry(pid, socket);
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

int main(int argc, char **argv)
{
    hip_init_socket_db();
    test_db();
    hip_uninit_socket_db();
    return 0;
}

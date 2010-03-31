/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_LIB_OPPHIP_WRAP_DB_H
#define HIP_LIB_OPPHIP_WRAP_DB_H

#include <sys/types.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"

struct hip_opp_socket_entry {
    pid_t                   pid;
    int                     orig_socket;
    pthread_t               tid;
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

// not implemented for hs either
#define HIP_LOCK_SOCKET_INIT(entry)
#define HIP_UNLOCK_SOCKET_INIT(entry)
#define HIP_LOCK_SOCKET(entry)
#define HIP_UNLOCK_SOCKET(entry)
#define HIP_SOCKETDB_SIZE 533
#define SOFILE "libc.so.6"

void hip_init_socket_db(void);
void hip_uninit_socket_db(void);
void hip_socketdb_dump(void);
//void hip_socketdb_get_entry(hip_opp_socket_t *entry, int pid, int socket);
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket, pthread_t tid);
int hip_socketdb_add_entry(int pid, int socket, pthread_t tid);
int hip_socketdb_del_entry(int pid, int socket, pthread_t tid);
// functions in wrap_db.c
int request_pseudo_hit_from_hipd(const struct in6_addr *ip,
                                 struct in6_addr *phit);
int request_peer_hit_from_hipd(const struct in6_addr *ip,
                               struct in6_addr *peer_hit,
                               const struct in6_addr *local_hit);
int exists_mapping(int pid, int socket);
int hip_exists_translation(int pid, int socket, pthread_t tid);
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry);

extern hip_hit_t *get_local_hits_wrapper(void);

#endif

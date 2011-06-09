/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_HIPD_HIDB_H
#define HIP_HIPD_HIDB_H

#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/lhash.h>

#include "lib/core/hashtable.h"
#include "lib/core/list.h"
#include "lib/core/protodefs.h"
#include "cookie.h"


struct local_host_id {
    hip_hit_t          hit;
    bool               anonymous;         /**< Is this an anonymous HI */
    hip_lsi_t          lsi;
    struct hip_host_id host_id;
    void              *private_key;       /* RSA or DSA */
    struct hip_r1entry r1[HIP_R1TABLESIZE];       /* precreated R1s */
    /* Handler to call after insert with an argument, return 0 if OK*/
    int (*insert)(struct local_host_id *, void **arg);
    /* Handler to call before remove with an argument, return 0 if OK*/
    int   (*remove)(struct local_host_id *, void **arg);
    void *arg;
};

/* Use this to point your target while accessing a database */
#define HIP_DB_LOCAL_HID   (hip_local_hostid_db)

/* ... and not this! */
extern HIP_HASHTABLE *hip_local_hostid_db;

struct local_host_id *hip_get_hostid_entry_by_lhi_and_algo(HIP_HASHTABLE *db,
                                                           const struct in6_addr *hit,
                                                           int algo, int anon);
int hip_get_host_id_and_priv_key(HIP_HASHTABLE *db, struct in6_addr *hit,
                                 int algo, struct hip_host_id **host_id, void **key);

void hip_uninit_host_id_dbs(void);

int hip_handle_add_local_hi(const struct hip_common *input);

int hip_handle_del_local_hi(const struct hip_common *input);
int hip_for_each_hi(int (*func)(struct local_host_id *entry, void *opaq), void *opaque);

/*lsi support*/
int hip_hidb_exists_lsi(hip_lsi_t *lsi);
int hip_hidb_associate_default_hit_lsi(hip_hit_t *default_hit, hip_lsi_t *default_lsi);
int hip_hidb_get_lsi_by_hit(const hip_hit_t *our, hip_lsi_t *our_lsi);

/* existence */
int hip_hidb_hit_is_our(const hip_hit_t *src);

unsigned long hip_hidb_hash(const void *ptr);
int hip_hidb_match(const void *ptr1, const void *ptr2);
void hip_init_hostid_db(void);
int hip_get_default_hit(struct in6_addr *hit);
int hip_get_default_hit_msg(struct hip_common *msg);
int hip_get_default_lsi(struct in_addr *lsi);

#endif /* HIP_HIPD_HIDB_H */

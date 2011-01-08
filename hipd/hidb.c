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

/**
 * @file
 * @brief A database to local Host Identifiers and the related accessor functions.
 *
 * @author Janne Lundberg <jlu#tcs.hut.fi>
 * @author Miika Komu <miika#iki.fi>
 * @author Mika Kousa <mkousa#iki.fi>
 * @author Kristian Slavov <kslavov#hiit.fi>
 * @author Teresa Finez <tfinezmo#hut.tkk.fi>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>

#include "lib/core/builder.h"
#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/hostid.h"
#include "lib/core/hit.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/straddr.h"
#include "lib/tool/nlink.h"
#include "lib/tool/pk.h"
#include "config.h"
#include "cookie.h"
#include "hipd.h"
#include "netdev.h"
#include "hidb.h"


HIP_HASHTABLE *hip_local_hostid_db = NULL;
#define HIP_MAX_HOST_ID_LEN 1600

static const char *lsi_addresses[] = {"1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"};

/**
 * Strips a ECDSA public key out of a host id with private key component
 *
 * @param host_id the host identifier with its private key component
 * @return An allocated hip_host_id structure. Caller must deallocate.
 */
static struct hip_host_id *hip_get_ecdsa_public_key(const struct hip_host_id_priv *const host_id)
{
    int err = 0;
    struct hip_ecdsa_keylen key_lens;
    struct hip_host_id *host_id_pub;

    HIP_IFEL(hip_get_ecdsa_keylen(host_id, &key_lens),
             -1, "Failed computing key sizes.\n");

    HIP_IFEL(!(host_id_pub = (struct hip_host_id *) malloc(sizeof(struct hip_host_id))),
             -ENOMEM, "Could not allocate memory for hip_host_id\n");
    memcpy(host_id_pub, host_id, sizeof(struct hip_host_id) - sizeof(host_id_pub->key) - sizeof(host_id_pub->hostname));
    memcpy(host_id_pub->key, host_id->key, key_lens.Y_len+2);
    host_id_pub->hi_length = htons(key_lens.Y_len+2+sizeof(struct hip_host_id_key_rdata));

    hip_set_param_contents_len((struct hip_tlv_common *) host_id_pub, sizeof(struct hip_host_id)-sizeof(struct hip_tlv_common));

    return host_id_pub;

out_err:
    free(host_id_pub);
    return NULL;
}


/**
 * Strips a DSA public key out of a host id with private key component
 *
 * @param hi the host identifier with its private key component
 * @return An allocated hip_host_id structure. Caller must deallocate.
 */
static struct hip_host_id *hip_get_dsa_public_key(const struct hip_host_id_priv *const hi)
{
    int key_len;
    /* T could easily have been an int, since the compiler will
     * probably add 3 alignment bytes here anyway. */
    uint8_t T;
    uint16_t temp;
    struct hip_host_id *ret;

    /* check T, Miika won't like this */
    T = *((const uint8_t *) (hi->key));
    if (T > 8) {
        HIP_ERROR("Invalid T-value in DSA key (0x%x)\n", T);
        return NULL;
    }
    if (T != 8) {
        HIP_DEBUG("T-value in DSA-key not 8 (0x%x)!\n", T);
    }
    key_len        = 64 + (T * 8);

    ret            = malloc(sizeof(struct hip_host_id));
    memcpy(ret, hi, sizeof(struct hip_host_id));

    /* the secret component of the DSA key is always 20 bytes */
    temp = ntohs(hi->hi_length) - DSA_PRIV;
    ret->hi_length = htons(temp);
    memset((char *) (&ret->key) + ntohs(ret->hi_length) - sizeof(hi->rdata),
           0, sizeof(ret->key) - ntohs(ret->hi_length));
    ret->length    = htons(sizeof(struct hip_host_id));

    return ret;
}

/**
 * Strips the RSA public key from a Host Identity
 *
 * @param tmp a pointer to a Host Identity.
 * @return    A pointer to a newly allocated host identity with only the public key.
 *            Caller deallocates.
 */
static struct hip_host_id *hip_get_rsa_public_key(const struct hip_host_id_priv *const tmp)
{
    int rsa_pub_len;
    struct hip_rsa_keylen keylen;
    struct hip_host_id *ret;

    /** @todo check some value in the RSA key? */

    hip_get_rsa_keylen(tmp, &keylen, 1);
    rsa_pub_len    = keylen.e_len + keylen.e + keylen.n;

    ret            = malloc(sizeof(struct hip_host_id));
    memcpy(ret, tmp, sizeof(struct hip_host_id) -
           sizeof(ret->key) - sizeof(ret->hostname));
    ret->hi_length = htons(rsa_pub_len + sizeof(struct hip_host_id_key_rdata));
    memcpy(ret->key, tmp->key, rsa_pub_len);
    memcpy(ret->hostname, tmp->hostname, sizeof(ret->hostname));
    ret->length    = htons(sizeof(struct hip_host_id));

    return ret;
}

/**
 * Transforms a private/public key pair to a public key, private key is deleted.
 *
 * @param hid a pointer to a host identity.
 * @return    a pointer to a host identity if the transformation was
 *            successful, NULL otherwise.
 */
static struct hip_host_id *hip_get_public_key(const struct hip_host_id_priv *hid)
{
    int alg = hip_get_host_id_algo((const struct hip_host_id *) hid);
    switch (alg) {
    case HIP_HI_RSA:
        return hip_get_rsa_public_key(hid);
    case HIP_HI_DSA:
        return hip_get_dsa_public_key(hid);
    case HIP_HI_ECDSA:
        return hip_get_ecdsa_public_key(hid);
    default:
        HIP_ERROR("Unsupported HI algorithm (%d)\n", alg);
        return NULL;
    }
}

/** @todo All get_any's should be removed (tkoponen). */
/** @todo These should be hashes instead of plain linked lists. */

/* Static functions follow. These functions _MUST_ only be used in conjunction
 * with adequate locking. If the operation only fetches data, then READ lock is
 * enough. All contexts except the hip thread _SHOULD_ use READ locks.
 * The hip thread(s) is/are allowed to write to the databases. For this purpose
 * it/they will acquire the WRITE lock.
 */

/* Do not access these databases directly: use the accessors in this file. */

/**
 * hashing function required by hashtable/linked list implementation
 *
 * @param ptr a pointer to a hip_host_id_entry structure
 * @return the calculated hash value
 */
unsigned long hip_hidb_hash(const void *ptr)
{
    const hip_hit_t *hit = &((const struct hip_host_id_entry *) ptr)->lhi.hit;
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, hit, sizeof(hip_hit_t), hash);

    return *((unsigned long *) hash);
}

/**
 * matching function required by hashtable/linked list implementation
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1 a pointer to hip_host_id_entry
 * @param ptr2 a pointer to hip_host_id_entry
 * @return zero on match or non-zero on unmatch
 */
int hip_hidb_match(const void *ptr1, const void *ptr2)
{
    const hip_hit_t *hit1 = &((const struct hip_host_id_entry *) ptr1)->lhi.hit;
    const hip_hit_t *hit2 = &((const struct hip_host_id_entry *) ptr2)->lhi.hit;
    return memcmp(hit1, hit2, sizeof(*hit1));
}

/**
 * initialize host identity database
 */
void hip_init_hostid_db(void)
{
    hip_local_hostid_db = hip_ht_init(hip_hidb_hash, hip_hidb_match);
}

/**
 * Deletes the given HI (network byte order) from the database. Matches HIs
 * based on the HIT.
 *
 * @param db  database from which to delete.
 * @param lhi the HIT to be deleted from the database.
 * @return    zero on success, otherwise negative.
 */
static int hip_del_host_id(HIP_HASHTABLE *db, struct hip_lhi *lhi)
{
    int err                      = -ENOENT;
    struct hip_host_id_entry *id = NULL;

    HIP_ASSERT(lhi != NULL);

    id = hip_get_hostid_entry_by_lhi_and_algo(db, &lhi->hit, HIP_ANY_ALGO, -1);
    if (id == NULL) {
        HIP_WRITE_UNLOCK_DB(db);
        HIP_ERROR("lhi not found\n");
        err = -ENOENT;
        return err;
    }

    /* Call the handler to execute whatever required after the
     * host id is no more in the database */
    if (id->remove) {
        id->remove(id, &id->arg);
    }

    /* free the dynamically reserved memory and
     * set host_id to null to signal that it is free */
    if (id->r1) {
        hip_uninit_r1(id->r1);
    }

    if (hip_get_host_id_algo(id->host_id) == HIP_HI_RSA) {
        RSA_free(id->private_key);
    } else if (hip_get_host_id_algo(id->host_id) == HIP_HI_ECDSA) {
        EC_KEY_free(id->private_key);
    } else if (hip_get_host_id_algo(id->host_id) == HIP_HI_DSA) {
        DSA_free(id->private_key);
    } else {
        HIP_ERROR("Cannot free key, because key type is unkown.\n");
    }

    free(id->host_id);
    list_del(id, db);
    free(id);
    id  = NULL;

    err = 0;
    return err;
}

/**
 * Uninitializes local/peer Host Id table. All elements of the @c db are
 * deleted. Since local and peer host id databases include dynamically allocated
 * host_id element, it is also freed.
 *
 * @param db database structure to delete.
 */
static void hip_uninit_hostid_db(HIP_HASHTABLE *db)
{
    hip_list_t *curr, *iter;
    struct hip_host_id_entry *tmp;
    int count, err;

    HIP_WRITE_LOCK_DB(db);

    list_for_each_safe(curr, iter, db, count) {
        struct hip_lhi lhi;

        tmp = list_entry(curr);

        memcpy(&lhi, &tmp->lhi, sizeof(lhi));
        err = hip_del_host_id(db, &lhi);
    }

    hip_ht_uninit(db);

    HIP_WRITE_UNLOCK_DB(db);
}

/**
 * Finds the host id corresponding to the given @c hit.
 *
 * If @c hit is null, finds the first used host id.
 * If algo is HIP_ANY_ALGO, ignore algore comparison.
 *
 * @param db   database to be searched. Usually either HIP_DB_PEER_HID or
 *             HIP_DB_LOCAL_HID
 * @param hit  the local host id to be searched
 * @param anon -1 if you don't care, 1 if anon, 0 if public
 * @param algo the algorithm
 * @return     NULL, if failed or non-NULL if succeeded.
 */
struct hip_host_id_entry *hip_get_hostid_entry_by_lhi_and_algo(HIP_HASHTABLE *db,
                                                               const struct in6_addr *hit,
                                                               int algo,
                                                               int anon)
{
    struct hip_host_id_entry *id_entry;
    hip_list_t *item;
    int c;
    list_for_each(item, db, c) {
        id_entry = list_entry(item);

        if ((hit == NULL || !ipv6_addr_cmp(&id_entry->lhi.hit, hit)) &&
            (algo == HIP_ANY_ALGO ||
             (hip_get_host_id_algo(id_entry->host_id) == algo)) &&
            (anon == -1 || id_entry->lhi.anonymous == anon)) {
            return id_entry;
        }
    }
    HIP_DEBUG("Failed to find a host ID entry, Returning NULL.\n");
    return NULL;
}


/**
 * test if a given HIT belongs to the local host
 *
 * @param our the hit to be tested
 * @return one if the HIT belongs to the local host or zero otherwise
 */
int hip_hidb_hit_is_our(const hip_hit_t *our)
{
    return hip_get_hostid_entry_by_lhi_and_algo(hip_local_hostid_db, our,
                                                HIP_ANY_ALGO, -1) != NULL;
}

/**
 * map a local HIT to a local LSI from the local host identifier database
 *
 * @param our a local HIT
 * @param our_lsi the mapped LSI
 * @return zero on success or non-zero on failure
 */
int hip_hidb_get_lsi_by_hit(const hip_hit_t *our, hip_lsi_t *our_lsi)
{
    struct hip_host_id_entry *id_entry;
    hip_list_t *item;
    int c, err = 1;

    list_for_each(item, hip_local_hostid_db, c) {
        id_entry = list_entry(item);
        if (memcmp(&id_entry->lhi.hit, our, sizeof(*our)) == 0) {
            memcpy(our_lsi, &id_entry->lsi, sizeof(hip_lsi_t));
            return 0;
        }
    }
    return err;
}

/**
 * Assign a free LSI to a host id entry
 *
 * @param db database structure
 * @param id_entry contains an entry to the db, will contain an unsigned lsi
 * @return zero on success, or negative error value on failure.
 */
static int hip_hidb_add_lsi(HIP_HASHTABLE *db, struct hip_host_id_entry *id_entry)
{
    struct hip_host_id_entry *id_entry_aux;
    hip_list_t *item;
    hip_lsi_t lsi_aux;
    int err = 0, used_lsi, c, i;
    int len = sizeof(lsi_addresses) / sizeof(*lsi_addresses);

    for (i = 0; i < len; i++) {
        inet_aton(lsi_addresses[i], &lsi_aux);
        used_lsi = 0;

        list_for_each(item, db, c) {
            id_entry_aux = list_entry(item);
            if (hip_lsi_are_equal(&lsi_aux, &id_entry_aux->lsi)) {
                used_lsi = 1;
                c        = -1;
            }
        }

        if (!used_lsi) {
            memcpy(&id_entry->lsi, &lsi_aux, sizeof(hip_lsi_t));
            break;
        }
    }
    return err;
}

/*
 * Interface functions to access databases.
 *
 */

/***
 * ARG/TYPE arguments in following functions.
 *
 * arg is used as a database key. It is _REQUIRED_ to be of type
 * struct in6_addr *, _OR_ uint32. The first type is used IF AND ONLY IF,
 * the type argument equals to HIP_ARG_HIT. For all other values of
 * type, arg is assumed to be uint32 and the database is searched for
 * a corresponding own_spi.
 * In HIP_ARG_HIT case, the database is searched for corresponding
 * hit_peer field.
 */

/**
 * Delete host id databases
 */
void hip_uninit_host_id_dbs(void)
{
    hip_uninit_hostid_db(hip_local_hostid_db);
}

/**
 * Adds the given HI into the database. Checks for duplicates. If one is found,
 * the current HI is @b NOT stored.
 *
 * @param db      database structure.
 * @param lhi     HIT
 * @param host_id HI
 * @param add     the handler to call right after the host id is added
 * @param del     the handler to call right before the host id is removed
 * @param arg     argument passed for the handlers
 * @param lsi     the LSI
 * @return        0 on success, otherwise an negative error value is returned.
 */
static int hip_add_host_id(HIP_HASHTABLE *db,
                           const struct hip_lhi *lhi,
                           hip_lsi_t *lsi,
                           const struct hip_host_id_priv *host_id,
                           int (*add)(struct hip_host_id_entry *, void **arg),
                           int (*del)(struct hip_host_id_entry *, void **arg),
                           void *arg)
{
    int err                            = 0;
    struct hip_host_id_entry *id_entry = NULL;
    struct hip_host_id_entry *old_entry;

    HIP_WRITE_LOCK_DB(db);

    HIP_ASSERT(&lhi->hit != NULL);
    HIP_IFEL(!(id_entry = malloc(sizeof(struct hip_host_id_entry))),
             -ENOMEM, "No memory available for host id\n");
    memset(id_entry, 0, sizeof(struct hip_host_id_entry));

    ipv6_addr_copy(&id_entry->lhi.hit, &lhi->hit);
    id_entry->lhi.anonymous = lhi->anonymous;

    /* check for duplicates */
    old_entry               = hip_get_hostid_entry_by_lhi_and_algo(db, &lhi->hit,
                                                                   HIP_ANY_ALGO, -1);
    if (old_entry != NULL) {
        HIP_WRITE_UNLOCK_DB(db);
        HIP_ERROR("Trying to add duplicate lhi\n");
        err = -EEXIST;
        goto out_err;
    }

    /* assign a free lsi address */
    HIP_IFEL((hip_hidb_add_lsi(db, id_entry)) < 0, -EEXIST, "No LSI free\n");

    memcpy(lsi, &id_entry->lsi, sizeof(hip_lsi_t));
    id_entry->insert = add;
    id_entry->remove = del;
    id_entry->arg    = arg;

    list_add(id_entry, db);

    if (hip_get_host_id_algo((const struct hip_host_id *) host_id) == HIP_HI_RSA) {
        id_entry->private_key = hip_key_rr_to_rsa(host_id, 1);
    } else if (hip_get_host_id_algo((const struct hip_host_id *) host_id) == HIP_HI_ECDSA) {
        id_entry->private_key = hip_key_rr_to_ecdsa(host_id, 1);
    } else { /* DSA */
        id_entry->private_key = hip_key_rr_to_dsa(host_id, 1);
    }

    HIP_DEBUG("Generating a new R1 set.\n");
    HIP_IFEL(!(id_entry->r1 = hip_init_r1()), -ENOMEM, "Unable to allocate R1s.\n");
    id_entry->host_id = hip_get_public_key(host_id);
    switch (hip_get_host_id_algo(id_entry->host_id)) {
    case HIP_HI_RSA:
        HIP_IFEL(!hip_precreate_r1(id_entry->r1,
                                   &lhi->hit,
                                   hip_rsa_sign,
                                   id_entry->private_key, id_entry->host_id),
                 -ENOENT,
                 "Unable to precreate R1s.\n");
        break;
    case HIP_HI_DSA:
        HIP_IFEL(!hip_precreate_r1(id_entry->r1,
                                   &lhi->hit,
                                   hip_dsa_sign,
                                   id_entry->private_key, id_entry->host_id),
                 -ENOENT,
                 "Unable to precreate R1s.\n");
        break;
    case HIP_HI_ECDSA:
        HIP_IFEL(!hip_precreate_r1(id_entry->r1,
                                   &lhi->hit,
                                   hip_ecdsa_sign,
                                   id_entry->private_key, id_entry->host_id),
                 -ENOENT,
                 "Unable to precreate R1s.\n");
        break;
    default:
        HIP_ERROR("Unsupported algorithms\n");
        err = -1;
        goto out_err;
    }

    /* Called while the database is locked, perhaps not the best
     * option but HIs are not added often */
    if (add) {
        add(id_entry, &arg);
    }

out_err:
    if (err && id_entry) {
        if (id_entry->host_id) {
            if (hip_get_host_id_algo(id_entry->host_id) == HIP_HI_RSA) {
                RSA_free(id_entry->private_key);
            } else if (hip_get_host_id_algo(id_entry->host_id) == HIP_HI_ECDSA) {
                EC_KEY_free(id_entry->private_key);
            } else {
                DSA_free(id_entry->private_key);
            }
            free(id_entry->host_id);
        }
        free(id_entry);
    }

    HIP_WRITE_UNLOCK_DB(db);
    return err;
}

/**
 * Handles the adding of a localhost host identity.
 *
 * @param input contains the hi parameter in fqdn format (includes private key).
 * @return      zero on success, or negative error value on failure.
 */
int hip_handle_add_local_hi(const struct hip_common *input)
{
    int err                                      = 0;
    const struct hip_host_id_priv *host_identity = NULL;
    struct hip_lhi lhi;
    const struct hip_tlv_common *param           = NULL;
    const struct hip_eid_endpoint *eid_endpoint  = NULL;
    struct in6_addr in6_lsi;
    hip_lsi_t lsi = {0};

    HIP_DEBUG("/* --------- */ \n");
    HIP_DEBUG_IN6ADDR("input->hits = ", &input->hits);
    HIP_DEBUG_IN6ADDR("input->hitr = ", &input->hitr);
    if ((err = hip_get_msg_err(input)) != 0) {
        HIP_ERROR("daemon failed (%d)\n", err);
        goto out_err;
    }

    /* Iterate through all host identities in the input */
    while ((param = hip_get_next_param(input, param)) != NULL) {
        /* NOTE: changed to use hip_eid_endpoint structs instead of
        *  hip_host_id:s when passing IDs from user space to kernel */
        if  (hip_get_param_type(param) != HIP_PARAM_EID_ENDPOINT) {
            continue;
        }
        HIP_DEBUG("host id found in the msg\n");

        eid_endpoint = (const struct hip_eid_endpoint *) param;

        HIP_IFEL(!eid_endpoint, -ENOENT, "No host endpoint in input\n");

        host_identity = &eid_endpoint->endpoint.id.host_id;

        HIP_IFEL(hip_private_host_id_to_hit(host_identity, &lhi.hit,
                                            HIP_HIT_TYPE_HASH100),
                 -EFAULT, "Host id to hit conversion failed\n");

        lhi.anonymous =
            (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON)
            ?
            1 : 0;

        err = hip_add_host_id(HIP_DB_LOCAL_HID, &lhi,
                              &lsi, host_identity,
                              NULL, NULL, NULL);

        /* Currently only RSA pub is added by default (bug id 592127).
         * Ignore redundant adding in case user wants to enable
         * multiple HITs. */
        HIP_IFEL((err == -EEXIST), 0,
                 "Ignoring redundant HI\n");

        /* Adding the pair <HI,LSI> */
        HIP_IFEL(err,
                 -EFAULT, "adding of local host identity failed\n");


        IPV4_TO_IPV6_MAP(&lsi, &in6_lsi);
        /* Adding routes just in case they don't exist */
        hip_add_iface_local_route(&lhi.hit);
        hip_add_iface_local_route(&in6_lsi);

        /* Adding HITs and LSIs to the interface */
        HIP_IFEL(hip_add_iface_local_hit(&lhi.hit), -1,
                 "Failed to add HIT to the device\n");
        HIP_IFEL(hip_add_iface_local_hit(&in6_lsi), -1,
                 "Failed to add LSI to the device\n");
    }

    HIP_DEBUG("Adding of HIP localhost identities was successful\n");

out_err:
    return err;
}

/**
 * Handles the deletion of a localhost host identity.
 *
 * @param input the message containing the hit to be deleted.
 * @return    zero on success, or negative error value on failure.
 */
int hip_handle_del_local_hi(const struct hip_common *input)
{
    const struct in6_addr *hit;
    struct hip_lhi lhi;
    char buf[46];
    int err = 0;

    hit = hip_get_param_contents(input, HIP_PARAM_HIT);
    HIP_IFEL(!hit, -ENODATA, "no hit\n");

    hip_in6_ntop(hit, buf);
    HIP_INFO("del HIT: %s\n", buf);

    ipv6_addr_copy(&lhi.hit, hit);

    if ((err = hip_del_host_id(HIP_DB_LOCAL_HID, &lhi))) {
        HIP_ERROR("deleting of local host identity failed\n");
        goto out_err;
    }

    /** @todo remove associations from hadb & beetdb by the deleted HI. */
    HIP_DEBUG("Removal of HIP localhost identity was successful\n");
out_err:
    return err;
}

/**
 * Copies to the @c target the first local HIT that is found.
 *
 * @param target placeholder for the target
 * @param algo   the algoritm to match, but if HIP_ANY_ALGO comparison is
 * '               ignored.
 * @param anon   -1 if you don't care, 1 if anon, 0 if public
 * @return       0 if ok, and negative if failed.
 */
int hip_get_any_localhost_hit(struct in6_addr *target, int algo, int anon)
{
    struct hip_host_id_entry *entry;
    int err = 0;

    HIP_READ_LOCK_DB(hip_local_hostid_db);

    entry = hip_get_hostid_entry_by_lhi_and_algo(hip_local_hostid_db,
                                                 NULL, algo, anon);
    if (!entry) {
        err = -ENOENT;
        goto out;
    }

    ipv6_addr_copy(target, &entry->lhi.hit);
    err = 0;

out:
    HIP_READ_UNLOCK_DB(hip_local_hostid_db);
    return err;
}

/**
 * Search if a local lsi exists already in the hidb
 *
 * @param lsi the local lsi we are searching
 * @return 0 if it's not in the hidb, 1 if it is
 */
int hip_hidb_exists_lsi(hip_lsi_t *lsi)
{
    struct hip_host_id_entry *id_entry;
    hip_list_t *item;
    int c, res = 0;

    list_for_each(item, hip_local_hostid_db, c) {
        id_entry = list_entry(item);
        if (hip_lsi_are_equal(&id_entry->lsi, lsi)) {
            return 1;
        }
    }
    return res;
}

/**
 * Lists every local hit in the database.
 *
 * @param func   a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       ...
 *
 * @note Works like hip_for_each_ha().
 */
int hip_for_each_hi(int (*func)(struct hip_host_id_entry *entry, void *opaq), void *opaque)
{
    hip_list_t *curr, *iter;
    struct hip_host_id_entry *tmp;
    int err = 0, c;

    HIP_READ_LOCK_DB(hip_local_hostid_db);

    list_for_each_safe(curr, iter, hip_local_hostid_db, c)
    {
        tmp = list_entry(curr);
        HIP_DEBUG_HIT("Found HIT", &tmp->lhi.hit);
        HIP_DEBUG_LSI("Found LSI", &tmp->lsi);
        err = func(tmp, opaque);
        if (err) {
            goto out_err;
        }
    }

out_err:
    HIP_READ_UNLOCK_DB(hip_local_hostid_db);

    return err;
}

/**
 * find the local host identifier corresponding to the local LSI
 *
 * @param db the local host identifier database to be searched for
 * @param lsi the local LSI to be matched
 * @return the local host identifier structure
 */
static struct hip_host_id_entry *hip_hidb_get_entry_by_lsi(HIP_HASHTABLE *db,
                                                           const struct in_addr *lsi)
{
    struct hip_host_id_entry *id_entry;
    hip_list_t *item;
    int c;

    list_for_each(item, db, c) {
        id_entry = list_entry(item);
        if (!ipv4_addr_cmp(&id_entry->lsi, lsi)) {
            return id_entry;
        }
    }
    return NULL;
}

/**
 * associate the given local LSI to the local host identifier denoted by the given HIT
 *
 * @param default_hit the HIT to be searched for
 * @param default_lsi the LSI to associate with
 * @return zero on success or negative on error
 */
int hip_hidb_associate_default_hit_lsi(hip_hit_t *default_hit, hip_lsi_t *default_lsi)
{
    int err = 0;
    hip_lsi_t aux_lsi;
    struct hip_host_id_entry *tmp1;
    struct hip_host_id_entry *tmp2;

    //1. Check if default_hit already associated with default_lsi
    HIP_IFEL((err = hip_hidb_get_lsi_by_hit(default_hit, &aux_lsi)),
             -1,
             "Error no lsi associated to hit\n");

    if (ipv4_addr_cmp(&aux_lsi, default_lsi)) {
        HIP_IFEL(!(tmp1 = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID,
                                                               default_hit,
                                                               HIP_ANY_ALGO,
                                                               -1)),
                 -1, "Default hit not found in hidb\n");
        HIP_IFEL(!(tmp2 = hip_hidb_get_entry_by_lsi(HIP_DB_LOCAL_HID, default_lsi)), -1,
                 "Default lsi not found in hidb\n");

        memcpy(&tmp2->lsi, &tmp1->lsi, sizeof(tmp1->lsi));
        memcpy(&tmp1->lsi, default_lsi, sizeof(tmp2->lsi));
    }

out_err:
    return err;
}

/**
 * find a host identifier from the database
 *
 * @param db the host identifier databased
 * @param hit the HIT to be searched for
 * @param algo the algorithm for the HI
 * @param host_id A copy of the host is stored here. Caller deallocates.
 * @param key a pointer to the private key (caller should not deallocate)
 * @return zero on success or negative on error
 */
int hip_get_host_id_and_priv_key(HIP_HASHTABLE *db, struct in6_addr *hit,
                                 int algo, struct hip_host_id **host_id, void **key)
{
    int err                         = 0, host_id_len;
    struct hip_host_id_entry *entry = NULL;

    HIP_READ_LOCK_DB(db);

    entry       = hip_get_hostid_entry_by_lhi_and_algo(db, hit, algo, -1);
    HIP_IFE(!entry, -1);

    host_id_len = hip_get_param_total_len(entry->host_id);
    HIP_IFE(host_id_len > HIP_MAX_HOST_ID_LEN, -1);

    *host_id    = malloc(host_id_len);
    HIP_IFE(!*host_id, -ENOMEM);
    memcpy(*host_id, entry->host_id, host_id_len);

    *key        = entry->private_key;
    HIP_IFE(!*key, -1);

out_err:
    HIP_READ_UNLOCK_DB(db);
    return err;
}

/**
 * append a HOST id parameter and signature into the message to be sent on the wire
 *
 * @param msg the msg where the host id and signature should be appended
 * @param hit the local HIT corresding to the host id
 * @return zero on success or negative on error
 */
int hip_build_host_id_and_signature(struct hip_common *msg,  hip_hit_t *hit)
{
    struct hip_host_id *hi_public = NULL;
    int err                       = 0;
    int alg                       = -1;
    void *private_key;

    HIP_IFEL((hit == NULL), -1, "Null HIT\n");

    /*
     * Below is the code for getting host id and appending it to the message
     * (after removing private key from it hi_public)
     * Where as hi_private is used to create signature on message
     * Both of these are appended to the message sequally
     */

    if ((err = hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID,
                                            hit,
                                            HIP_ANY_ALGO,
                                            &hi_public,
                                            &private_key)))
    {
        HIP_ERROR("Unable to locate HI from HID with HIT as key");
        goto out_err;
    }

    HIP_IFE(hip_build_param(msg, hi_public), -1);

    alg = hip_get_host_id_algo(hi_public);
    switch (alg) {
    case HIP_HI_RSA:
        err = hip_rsa_sign(private_key, msg);
        break;
    case HIP_HI_DSA:
        err = hip_dsa_sign(private_key, msg);
        break;
    case HIP_HI_ECDSA:
        err = hip_ecdsa_sign(private_key, msg);
    default:
        HIP_ERROR("Unsupported HI algorithm (%d)\n", alg);
        break;
    }

out_err:
    free(hi_public);
    return err;
}

/**
 * get the default HIT of the local host
 *
 * @param hit the local default HIT will be written here
 * @return zero on success or negative on error
 */
int hip_get_default_hit(struct in6_addr *hit)
{
    return hip_get_any_localhost_hit(hit, HIP_HI_RSA, 0);
}

/**
 * get the default HIT of the local host and write into a
 * user message
 *
 * @param msg the message where the HIT will be written
 * @return zero on success or negative on error
 */
int hip_get_default_hit_msg(struct hip_common *msg)
{
    int err = 0;
    hip_hit_t hit;
    hip_lsi_t lsi;

    HIP_IFE(hip_get_default_hit(&hit), -1);
    HIP_IFE(hip_get_default_lsi(&lsi), -1);
    HIP_DEBUG_HIT("Default hit is ", &hit);
    HIP_DEBUG_LSI("Default lsi is ", &lsi);
    HIP_IFE(hip_build_param_contents(msg, &hit, HIP_PARAM_HIT, sizeof(hit)),
            -1);
    HIP_IFE(hip_build_param_contents(msg, &lsi, HIP_PARAM_LSI, sizeof(lsi)),
            -1);

out_err:

    return err;
}

/**
 * get the default LSI of the local host
 *
 * @param lsi the default LSI will be written here
 * @return zero on success or negative on error
 */
int hip_get_default_lsi(struct in_addr *lsi)
{
    int err                       = 0, family = AF_INET;
    struct idxmap *idxmap[16]     = { 0 };
    struct in6_addr lsi_addr;
    struct in6_addr lsi_aux6;
    hip_lsi_t lsi_tmpl;

    memset(&lsi_tmpl, 0, sizeof(lsi_tmpl));
    set_lsi_prefix(&lsi_tmpl);
    IPV4_TO_IPV6_MAP(&lsi_tmpl, &lsi_addr);
    HIP_IFEL(hip_iproute_get(&hip_nl_route, &lsi_aux6, &lsi_addr, NULL,
                             NULL, family, idxmap), -1,
             "Failed to find IP route.\n");

    if (IN6_IS_ADDR_V4MAPPED(&lsi_aux6)) {
        IPV6_TO_IPV4_MAP(&lsi_aux6, lsi);
    }
out_err:

    return err;
}

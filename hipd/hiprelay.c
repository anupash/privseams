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
 * This file defines the rendezvous extension and the UDP relay for HIP packets
 * for the Host Identity Protocol (HIP). See header file for usage
 * instructions. Supports access control in the form in white lists in
 * the HIPL_SYSCONFDIR/relay_config file.
 *
 * The HIP relay combines the functionalites of an rendezvous server (RVS) and
 * a HIP UDP relay. The HIP relay consists of a hashtable for storing IP address
 * to HIT mappings and of functions that do the actual relaying action. The
 * hashtable is based on lhash library and its functionalites are the same
 * except that the HIP relay stores data (allocated memory for relay records)
 * instead of pointers.
 *
 * A few simple rules apply:
 * <ul>
 * <li>Allocate memory for relay records that are to be put into the hashtable
 * only with hip_relrec_alloc().</li>
 * <li>Once a relay record is <b>successfully</b> put into the hashtable, the
 * only way delete it is to call hip_relht_rec_free(). This will remove the
 * entry from the hashtable and free the memory allocated for the relay record.
 * </li>
 * </ul>
 *
 * Usage:
 * <ul>
 * <li>Inserting a new relay record:
 * <pre>
 * hip_relrec_t rr = hip_relrec_alloc(...);
 * hip_relht_put(rr);
 * if (hip_relht_get(rr) == NULL) { // The put was unsuccessful.
 *     free(rr);
 * }
 * </pre>
 * </li>
 * <li>Fetching a relay record. We do not need (but can use) a fully populated
 * relay record as a search key. A dummy record with hit_r field populated
 * is sufficient. Note that there is no need to re-put the relay record into the
 * hashtable once it has been succesfully inserted into the hashtable - except
 * if we change the hit_r field of the relay record. If a relay record with same
 * HIT is put into the hashtable, the existing element is deleted.
 *
 * <pre>
 * hip_relrec_t dummy, *fetch_record = NULL;
 * memcpy(&dummy.hit_r, hit, sizeof(hit));
 * fetch_record = hip_relht_get(&dummy);
 * if (fetch_record != NULL) {
 *     // Do something with the record.
 * }
 * </pre>
 * </li>
 * <li>Deleting a relay record. A dummy record can be used:
 * <pre>
 * hip_relrec_t dummy;
 * memcpy(&dummy.hit_r, hit, sizeof(hit));
 * hip_relht_rec_free(&dummy);
 * </pre>
 * </li>
 * </ul>
 *
 * @author  Lauri Silvennoinen
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5204.txt">
 *          Host Identity Protocol (HIP) Rendezvous Extension</a>
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-03.txt">
 *          draft-ietf-hip-nat-traversal-03</a>
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
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5204.txt">
 *          Host Identity Protocol (HIP) Rendezvous Extension</a>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "config.h"
#include "configfilereader.h"
#include "hadb.h"
#include "input.h"
#include "output.h"
#include "hiprelay.h"


/** HIP relay config file default content. If the file @c HIP_RELAY_CONFIG_FILE
 *  cannot be opened for reading, we write a new config file from scratch using
 *  this content.
 *  @note @c HIP_RC_FILE_FORMAT_STRING must match the printf format of this
 *        string.
 */
#define HIP_RC_FILE_CONTENT \
"# HIP relay / RVS configuration file.\n" \
"#\n" \
"# This file consists of stanzas of the following form:\n" \
"# \n" \
"# parametername = \"value1\", \"value2\", ... \"valueN\"\n" \
"#\n" \
"# where there can be as many values as needed per line with the limitation of\n" \
"# total line length of ", HIP_RELAY_MAX_LINE_LEN, " characters. The 'parametername' is at most ", HIP_RELAY_MAX_PAR_LEN, "\n" \
"# characters long and 'values' are at most ", HIP_RELAY_MAX_VAL_LEN, " characters long. A value itself\n" \
"# may not contain a '", HIP_RELAY_VAL_SEP, "' character.\n" \
"#\n" \
"# The '", HIP_RELAY_COMMENT, "' character is used for comments. End of line comments are not allowed.\n" \
"\n" \
"# Relay whitelist status. When this is set to 'yes', only clients whose HIT is\n" \
"# listed on the whitelist are allowed to register to the relay / RVS service.\n" \
"# When this is set to 'no', any client is allowed to register. This defaults as\n" \
"# 'yes' when no value is given.\n" \
"whitelist_enabled = \"no\"\n" \
"\n" \
"# Relay whitelist. The HITs of the clients that are allowed to register to\n" \
"# the relay / RVS service. You may use multiple stanzas of the same name.\n" \
"whitelist = \"\"\n" \
"\n" \
"# The minimum number of seconds the relay / RVS client is granted the service.\n" \
"# If the service request defines a value smaller than this value, this value is\n" \
"# used.\n" \
"minimum_lifetime = \"60\"\n" \
"\n" \
"# The maximum number of seconds the relay / RVS client is granted the service.\n" \
"# If the service request defines a value bigger than this value, this value is\n" \
"# used.\n" "maximum_lifetime = \"3600\"\n"
/** The printf format string of @c HIP_RC_FILE_CONTENT. */
#define HIP_RC_FILE_FORMAT_STRING "%s%d%s%d%s%d%s%c%s%c%s"

/** HIP relay config file name and path. */
#define HIP_RELAY_CONFIG_FILE  HIPL_SYSCONFDIR "/relay_config"

/** A hashtable for storing the relay records. */
static HIP_HASHTABLE *hiprelay_ht       = NULL;
/** A hashtable for storing the the HITs of the clients that are allowed to use
 *  the relay / RVS service. */
static HIP_HASHTABLE *hiprelay_wl       = NULL;

/** Minimum relay record life time as a 8-bit integer. */
uint8_t hiprelay_min_lifetime           = HIP_RELREC_MIN_LIFETIME;
/** Maximum relay record life time as a 8-bit integer. */
uint8_t hiprelay_max_lifetime           = HIP_RELREC_MAX_LIFETIME;
/**
 * A boolean to indicating if the RVS / relay is enabled. User sets this value
 * using the hipconf tool.
 */
hip_relay_status_t relay_enabled        = HIP_RELAY_OFF;
/**
 * A boolean to indicating if the RVS / relay whitelist is enabled. User sets
 * this value from the relay configuration file.
 */
hip_relay_wl_status_t whitelist_enabled = HIP_RELAY_WL_ON;

/**
 * Returns a hash calculated over a HIT.
 *
 * @param  hit a HIT value over which the hash is calculated.
 * @return a hash value.
 */
static inline unsigned long hip_hash_func(const hip_hit_t *hit)
{
    uint32_t bits_1st  = 0;
    unsigned long hash = 0;

    /* HITs are of the form: 2001:001x:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
     * We have four groups of 32 bit sequences here, but the first 28 bits
     * are constant and have no hash value. Therefore, we create a new
     * replacement sequence for first 32 bit sequence. */

    bits_1st  = (~hit->s6_addr[3]) << 28;
    bits_1st |= hit->s6_addr[3] << 24;
    bits_1st |= hit->s6_addr[7] << 16;
    bits_1st |= hit->s6_addr[11] << 8;
    bits_1st |= hit->s6_addr[15];

    /* We calculate the hash by avalanching the bits. The avalanching
     * ensures that we make use of all bits when dealing with 64 bits
     * architectures. */
    hash      =  (bits_1st ^ hit->s6_addr32[1]);
    hash     ^= hash << 3;
    hash     ^= (hit->s6_addr32[2] ^ hit->s6_addr32[3]);
    hash     += hash >> 5;
    hash     ^= hash << 4;
    hash     += hash >> 17;
    hash     ^= hash << 25;
    hash     += hash >> 6;

    return hash;
}

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the element if the matching element's type is of @c type. The
 * deletion is based on the hash calculated from the relay fecord
 * @c hit_r field, and therefore the parameter record does not need to be fully
 * populated. If the parameter relay record is the same record that is being
 * deleted (i.e. is located in the same memory location) then the parameter
 * @c rec itself is freed. If a dummy record is used (i.e. is located in a
 * different memory location thatn the hashtable entry), then @c rec is left
 * untouched.
 *
 * @param rec a pointer to a relay record.
 * @param type the type to match
 */
static void hip_relht_rec_free_type_doall_arg(hip_relrec_t *rec, const hip_relrec_type_t *type)
{
    hip_relrec_t *fetch_record = hip_relht_get(rec);

    if (fetch_record != NULL && fetch_record->type == *type) {
        hip_relht_rec_free_doall(rec);
    }
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
STATIC_IMPLEMENT_LHASH_DOALL_ARG_FN(hip_relht_rec_free_type,
                                    hip_relrec_t, hip_relrec_type_t)

/**
 * Returns relay status.
 *
 * @return HIP_RELAY_ON if the RVS / relay is "on", HIP_RELAY_OFF otherwise.
 */
hip_relay_status_t hip_relay_get_status(void)
{
    return relay_enabled;
}

/**
 * Sets the status of the RVS / relay. Sets the relay "on" or "off".
 *
 * @param status zero if the relay is to be disabled, anything else to enable
 *               the relay.
 */
void hip_relay_set_status(hip_relay_status_t status)
{
    relay_enabled = status;
}

/**
 * The hash function of the @c hiprelay_ht hashtable. Calculates a hash from
 * parameter relay record HIT.
 *
 * @param rec a pointer to a relay record.
 * @return    the calculated hash or zero if @c rec or hit_r is NULL.
 */
static unsigned long hip_relht_hash(const hip_relrec_t *rec)
{
    if (rec == NULL || &(rec->hit_r) == NULL) {
        return 0;
    }

    return hip_hash_func(&(rec->hit_r));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_HASH_FN(hip_relht, const hip_relrec_t)

/**
 * relay hash table comparison function
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param rec1 a hip_relrec_t structure
 * @param rec2 a hip_relrec_t structure
 * @return zero if the structures are equal or one otherwise
 */
static int hip_relht_cmp(const hip_relrec_t *rec1, const hip_relrec_t *rec2)
{
    if (rec1 == NULL || rec2 == NULL) {
        return 1;
    }

    return memcmp(&rec1->hit_r, &rec2->hit_r, sizeof(rec1->hit_r));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_COMP_FN(hip_relht, const hip_relrec_t)

/**
 * Puts a relay record into the hashtable. Puts the relay record pointed by
 * @c rec into the hashtable @c hiprelay_ht. If there already is an entry with
 * the same key the old value is replaced, and <b>the memory allocated for the
 * existing element is freed</b>. Note that we store pointers here, the data are
 * not copied. There should be no need to put a relay record more than once into
 * the hashtable. If the fields of an individual relay record need to be
 * changed, just retrieve the record with @c hip_relht_get() and alter the
 * fields of it, but do not re-put it into the hashtable.
 *
 * @param rec a pointer to a relay record to be inserted into the hashtable.
 * @return    -1 if there was a hash collision i.e. an entry with duplicate HIT
 *            is inserted, zero otherwise.
 * @note      <b style="color: #f00;">Do not put records allocated from stack
 *            into the hashtable.</b> Instead put only records created with
 *            hip_relrec_alloc().
 * @note      In case of a hash collision, the existing relay record is freed.
 *            If you store references to relay records that are in the hashtable
 *            elsewhere outside the hashtable, NULL pointers can result.
 */
int hip_relht_put(hip_relrec_t *rec)
{
    hip_relrec_t key, *match;

    if (hiprelay_ht == NULL || rec == NULL) {
        return -1;
    }

    /* If we are trying to insert a duplicate element (same HIT), we have to
     * delete the previous entry. If we do not do so, only the pointer in
     * the hashtable is replaced and the reference to the previous element
     * is lost resulting in a memory leak. */
    memcpy(&(key.hit_r), &(rec->hit_r), sizeof(rec->hit_r));
    match = hip_relht_get(rec);

    if (match != NULL) {
        hip_relht_rec_free_doall(&key);
        list_add(rec, hiprelay_ht);
        return -1;
    } else {
        list_add(rec, hiprelay_ht);
        return 0;
    }
}

/**
 * Retrieves a relay record from the hashtable @c hiprelay_ht. The parameter
 * record @c rec only needs to have field @c hit_r populated.
 *
 * @param rec a pointer to a relay record.
 * @return    a pointer to a fully populated relay record if found, NULL
 *            otherwise.
 */
hip_relrec_t *hip_relht_get(const hip_relrec_t *rec)
{
    if (hiprelay_ht == NULL || rec == NULL) {
        return NULL;
    }

    return (hip_relrec_t *) list_find(rec, hiprelay_ht);
}

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the element. The deletion is based on the hash calculated from
 * the relay fecord @c hit_r field, and therefore the parameter record does not
 * need to be fully populated. If the parameter relay record is the same record
 * that is being deleted (i.e. is located in the same memory location) then
 * the parameter @c rec itself is freed. If a dummy record is used (i.e. is
 * located in a different memory location thatn the hashtable entry), then
 * @c rec is left untouched.
 *
 * @param rec a pointer to a relay record.
 */
void hip_relht_rec_free_doall(hip_relrec_t *rec)
{
    if (hiprelay_ht == NULL || rec == NULL) {
        return;
    }

    /* Check if such element exist, and delete the pointer from the hashtable. */
    hip_relrec_t *deleted_rec = list_del(rec, hiprelay_ht);

    /* Free the memory allocated for the element. */
    if (deleted_rec != NULL) {
        /* We set the memory to '\0' because the user may still have a
         * reference to the memory region that is freed here. */
        memset(deleted_rec, '\0', sizeof(*deleted_rec));
        free(deleted_rec);
        HIP_DEBUG("Relay record deleted.\n");
    }
}

/** A callback wrapper of the prototype required by @c lh_doall(). */
STATIC_IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free, hip_relrec_t)

/**
 * Deletes a single entry from the relay record hashtable and frees the memory
 * allocated for the record, if the record has expired. The relay record is
 * deleted if it has been last contacted more than @c hiprelay_lifetime seconds
 * ago. If the parameter relay record is the same record that is being deleted
 * (i.e. is located in the same memory location) then the parameter @c rec
 * itself is freed. If a dummy record is used (i.e. is located in a different
 * memory location thatn the hashtable entry), then @c rec is left untouched.
 *
 * @param rec a pointer to a relay record.
 */
static void hip_relht_rec_free_expired_doall(hip_relrec_t *rec)
{
    if (rec == NULL) {  // No need to check hiprelay_ht
        return;
    }

    if (time(NULL) - rec->created > rec->lifetime) {
        HIP_DEBUG("Relay record expired, deleting.\n");
        hip_relht_rec_free_doall(rec);
    }
}

/** A callback wrapper of the prototype required by @c lh_doall(). */
STATIC_IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free_expired, hip_relrec_t)

/**
 * Returns the number of relay records in the hashtable @c hiprelay_ht.
 *
 * @return  number of relay records in the hashtable.
 */
unsigned long hip_relht_size(void)
{
    if (hiprelay_ht == NULL) {
        return 0;
    }

    return ((struct lhash_st *) hiprelay_ht)->num_items;
}

/**
 * @brief Clear the expired records from the relay hashtable.
 *
 * Periodic maintenance function of the hip relay. This function should be
 * called once in every maintenance cycle of the hip daemon. It clears the
 * expired relay records by calling @c hip_relht_rec_free_expired() for every
 * element in the hashtable.
 * @todo a REG_RESPONSE with zero lifetime should be sent to each client whose
 *       registration is cancelled.
 */
int hip_relht_maintenance(void)
{
    if (hiprelay_ht == NULL) {
        return 0;
    }

    unsigned int tmp = ((struct lhash_st *) hiprelay_ht)->down_load;
    ((struct lhash_st *) hiprelay_ht)->down_load = 0;
    hip_ht_doall(hiprelay_ht, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(hip_relht_rec_free_expired));
    ((struct lhash_st *) hiprelay_ht)->down_load = tmp;

    return 0;
}

/**
 * Deletes all entries of @c type from the relay record hashtable and frees the
 * memory allocated for the deleted elements.
 *
 * @param type the type of the records to be deleted.
 */
void hip_relht_free_all_of_type(hip_relrec_type_t type)
{
    if (hiprelay_ht == NULL) {
        return;
    }

    unsigned int tmp = ((struct lhash_st *) hiprelay_ht)->down_load;
    ((struct lhash_st *) hiprelay_ht)->down_load = 0;
    hip_ht_doall_arg(hiprelay_ht, (LHASH_DOALL_ARG_FN_TYPE) LHASH_DOALL_ARG_FN(hip_relht_rec_free_type), &type);
    ((struct lhash_st *) hiprelay_ht)->down_load = tmp;
}

/**
 * Sets the lifetime of a relay record.
 * The service lifetime is set to 2^((lifetime - 64)/8) seconds.
 *
 * @param rec      a pointer to a relay record.
 * @param lifetime the lifetime of the above formula.
 */
static void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime)
{
    if (rec != NULL) {
        rec->lifetime = pow(2, ((double) (lifetime - 64) / 8));
    }
}

/**
 * Allocates a new relay record.
 *
 * @param type     the type of this relay record (HIP_FULLRELAY or
 *                 HIP_RVSRELAY).
 * @param lifetime the lifetime of this relayrecord as defined in registration
 *                 draft.
 * @param hit_r    a pointer to Responder (relay client) HIT.
 * @param ip_r     a pointer to Responder (relay client) IP address.
 * @param port     responder's UDP port.
 * @param hmac     HMAC to copy into the new record
 * @return         a pointer to a new relay record, or NULL if failed to
 *                 allocate.
 * @note           All records to be put in the hashtable should be created with
 *                 this function.
 */
hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
                               const uint8_t lifetime,
                               const struct in6_addr *hit_r, const hip_hit_t *ip_r,
                               const in_port_t port,
                               const hip_crypto_key_t *hmac)
{
    if (hit_r == NULL || ip_r == NULL || hmac == NULL) {
        return NULL;
    }

    hip_relrec_t *rec = malloc(sizeof(hip_relrec_t));

    if (rec == NULL) {
        HIP_ERROR("Error allocating memory for HIP relay record.\n");
        return NULL;
    }
    rec->type       = type;
    memcpy(&(rec->hit_r), hit_r, sizeof(*hit_r));
    memcpy(&(rec->ip_r), ip_r, sizeof(*ip_r));
    rec->udp_port_r = port;
    memcpy(&(rec->hmac_relay), hmac, sizeof(*hmac));
    hip_relrec_set_lifetime(rec, lifetime);
    rec->created    = time(NULL);

    return rec;
}

/**
 * The hash function of the @c hiprelay_wl hashtable. Calculates a hash from
 * parameter HIT.
 *
 * @param hit a pointer to a HIT.
 * @return    the calculated hash or zero if @c hit is NULL.
 */
static unsigned long hip_relwl_hash(const hip_hit_t *hit)
{
    if (hit == NULL) {
        return 0;
    }

    return hip_hash_func(hit);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_HASH_FN(hip_relwl, const hip_hit_t)

/**
 * The compare function of the @c hiprelay_wl hashtable.
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param hit1 a pointer to a HIT.
 * @param hit2 a pointer to a HIT.
 * @return     0 if keys are equal and neither is NULL, non-zero otherwise.
 */
static int hip_relwl_cmp(const hip_hit_t *hit1, const hip_hit_t *hit2)
{
    if (hit1 == NULL || hit2 == NULL) {
        return 1;
    }

    return memcmp(hit1, hit2, sizeof(*hit1));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_COMP_FN(hip_relwl, const hip_hit_t)

/**
 * Deletes a single entry from the whitelist hashtable and frees the memory
 * allocated for the element. The parameter HIT is itself left untouched, it is
 * only used as an search key.
 *
 * @param hit a pointer to a HIT.
 */
static void hip_relwl_hit_free_doall(hip_hit_t *hit)
{
    if (hiprelay_wl == NULL || hit == NULL) {
        return;
    }

    /* Check if such element exist, and delete the pointer from the hashtable. */
    hip_hit_t *deleted_hit = list_del(hit, hiprelay_wl);

    /* Free the memory allocated for the element. */
    if (deleted_hit != NULL) {
        /* We set the memory to '\0' because the user may still have a
         * reference to the memory region that is freed here. */
        memset(deleted_hit, '\0', sizeof(*deleted_hit));
        free(deleted_hit);
        HIP_DEBUG("HIT deleted from the relay whitelist.\n");
    }
}

/**
 * Puts a HIT into the whitelist. Puts the HIT pointed by @c hit into the
 * whitelist hashtable @c hiprelay_wl. If there already is an entry with the
 * same HIT, the old value is replaced, and <b>the memory allocated for the
 * existing element is freed</b>. Note that we store pointers here, the data are
 * not copied.
 *
 * @param hit a pointer to a HIT to be inserted into the whitelist.
 * @return    -1 if there was a hash collision i.e. a duplicate HIT is inserted,
 *            zero otherwise.
 * @note      <b style="color: #f00;">Do not put HITs allocated from the stack
 *            into the whitelist.</b> Instead put only HITs created with
 *            malloc().
 * @note      In case of a hash collision, the existing HIT is freed. If you
 *            store references to HITs that are in the whitelist elsewhere
 *            outside the whitelist, NULL pointers can result.
 */
static int hip_relwl_put(hip_hit_t *hit)
{
    if (hiprelay_wl == NULL || hit == NULL) {
        return -1;
    }

    /* If we are trying to insert a duplicate element (same HIT), we have to
     * delete the previous entry. If we do not do so, only the pointer in
     * the hashtable is replaced and the reference to the previous element
     * is lost resulting in a memory leak. */
    hip_hit_t *dummy = hip_relwl_get(hit);
    if (dummy != NULL) {
        hip_relwl_hit_free_doall(dummy);
        list_add(hit, hiprelay_wl);
        return -1;
    } else {
        list_add(hit, hiprelay_wl);
        return 0;
    }
}

/**
 * Retrieves a HIT from the hashtable @c hiprelay_wl.
 *
 * @param hit a pointer to a HIT.
 * @return    a pointer to a matching HIT, NULL otherwise.
 */
hip_hit_t *hip_relwl_get(const hip_hit_t *hit)
{
    if (hiprelay_wl == NULL || hit == NULL) {
        return NULL;
    }

    return (hip_hit_t *) list_find(hit, hiprelay_wl);
}

#ifdef CONFIG_HIP_DEBUG
/**
 * Returns the number of HITs in the hashtable @c hiprelay_wl.
 *
 * @return  number of HITs in the hashtable.
 */
static unsigned long hip_relwl_size(void)
{
    if (hiprelay_wl == NULL) {
        return 0;
    }

    return ((struct lhash_st *) hiprelay_wl)->num_items;
}

#endif /* CONFIG_HIP_DEBUG */

/** A callback wrapper of the prototype required by @c lh_doall(). */
STATIC_IMPLEMENT_LHASH_DOALL_FN(hip_relwl_hit_free, hip_hit_t)

/**
 * Returns the whitelist status.
 *
 * @return HIP_RELAY_ON if the RVS / relay whitelist is "on", HIP_RELAY_OFF
 *         otherwise.
 */
hip_relay_wl_status_t hip_relwl_get_status(void)
{
    return whitelist_enabled;
}

/**
 * Validates a requested RVS service lifetime. If
 * @c requested_lifetime is smaller than @c hiprelay_min_lifetime then
 * @c granted_lifetime is set to @c hiprelay_min_lifetime. If
 * @c requested_lifetime is greater than @c hiprelay_max_lifetime then
 * @c granted_lifetime is set to @c hiprelay_max_lifetime. Else
 * @c granted_lifetime is set to @c requested_lifetime.
 *
 * @param  requested_lifetime the lifetime that is to be validated.
 * @param  granted_lifetime   a target buffer for the validated lifetime.
 * @return                    -1 if @c requested_lifetime is outside boundaries,
 *                            i.e. is smaller than @c hiprelay_min_lifetime or
 *                            is greater than @c hiprelay_max_lifetime. Zero
 *                            otherwise.
 */
int hip_rvs_validate_lifetime(uint8_t requested_lifetime,
                              uint8_t *granted_lifetime)
{
    if (requested_lifetime < hiprelay_min_lifetime) {
        *granted_lifetime = hiprelay_min_lifetime;
        return -1;
    } else if (requested_lifetime > hiprelay_max_lifetime)   {
        *granted_lifetime = hiprelay_max_lifetime;
        return -1;
    } else {
        *granted_lifetime = requested_lifetime;
        return 0;
    }
}

/**
 * Reads RVS / HIP Relay configuration from a file. Reads configuration
 * information from @c HIP_RELAY_CONFIG_FILE.
 *
 * @return zero on success, -ENOENT if the file could not be opened for reading.
 * @note   The white list @c hiprelay_wl must be initialized before this
 *         function is called.
 */
static int hip_relay_read_config(void)
{
    FILE *fp    = NULL;
    int lineerr = 0, parseerr = 0, err = 0;
    char parameter[HIP_RELAY_MAX_PAR_LEN + 1];
    hip_configvaluelist_t values;
    hip_hit_t hit, *wl_hit = NULL;
    uint8_t max = 255;     /* Theoretical maximum lifetime value. */

    HIP_IFEL(((fp = fopen(HIP_RELAY_CONFIG_FILE, "r")) == NULL), -ENOENT,
             "Cannot open file %s for reading.\n", HIP_RELAY_CONFIG_FILE);

    do {
        parseerr = 0;
        memset(parameter, '\0', sizeof(parameter));
        hip_cvl_init(&values);
        lineerr  = hip_cf_get_line_data(fp, parameter, &values, &parseerr);

        if (parseerr == 0) {
            hip_configfilevalue_t *current = NULL;
            if (strcmp(parameter, "whitelist_enabled") == 0) {
                current = hip_cvl_get_next(&values, current);
                if (strcmp(current->data, "no") == 0) {
                    whitelist_enabled = HIP_RELAY_WL_OFF;
                }
            } else if (strcmp(parameter, "whitelist") == 0) {
                while ((current =
                            hip_cvl_get_next(&values, current))
                       != NULL) {
                    /* Try to convert the characters to an
                     * IPv6 address. */
                    if (inet_pton(AF_INET6, current->data,
                                  &hit) > 0) {
                        /* store the HIT to the whitelist. */
                        wl_hit = malloc(sizeof(hip_hit_t));
                        if (wl_hit == NULL) {
                            HIP_ERROR("Error " \
                                      "allocating " \
                                      "memory for " \
                                      "whitelist " \
                                      "HIT.\n");
                            break;
                        }
                        memcpy(wl_hit, &hit, sizeof(hit));
                        hip_relwl_put(wl_hit);
                        print_node(current);
                    }
                }
            } else if (strcmp(parameter, "minimum_lifetime") == 0) {
                time_t tmp  = 0;
                uint8_t val = 0;
                current = hip_cvl_get_next(&values, current);
                tmp     = atol(current->data);

                if (hip_get_lifetime_value(tmp, &val) == 0) {
                    /* hip_get_lifetime_value() truncates the
                     * value. We want the minimum to be at
                     * least the value specified. */
                    if (val < max) {
                        val++;
                    }
                    hiprelay_min_lifetime = val;
                }
            } else if (strcmp(parameter, "maximum_lifetime") == 0) {
                time_t tmp  = 0;
                uint8_t val = 0;
                current = hip_cvl_get_next(&values, current);
                tmp     = atol(current->data);

                if (hip_get_lifetime_value(tmp, &val) == 0) {
                    hiprelay_max_lifetime = val;
                }
            }
        }

        hip_cvl_uninit(&values);
    } while (lineerr != EOF);

    if (fclose(fp) != 0) {
        HIP_ERROR("Cannot close file %s.\n", HIP_RELAY_CONFIG_FILE);
    }

    /* Check that the read values are sane. If not, rollback to defaults. */
    if (hiprelay_min_lifetime > hiprelay_max_lifetime) {
        hiprelay_min_lifetime = HIP_RELREC_MIN_LIFETIME;
        hiprelay_max_lifetime = HIP_RELREC_MAX_LIFETIME;
    }

    HIP_DEBUG("\nRead relay configuration file with following values:\n" \
              "Whitelist enabled: %s\nNumber of HITs in the whitelist: " \
              "%lu\nMinimum lifetime: %ld\nMaximum lifetime: %ld\n",
              (whitelist_enabled) ? "YES" : "NO", hip_relwl_size(),
              hiprelay_min_lifetime, hiprelay_max_lifetime);

out_err:

    return err;
}

/**
 * Writes RVS / HIP Relay configuration file with default content. Writes a RVS
 * / HIP Relay configuration file to @c HIP_RELAY_CONFIG_FILE. The file is
 * opened with "w" argument mode, which means that a possibly existing file is
 * truncated to zero length.
 *
 * @return zero on success, -ENOENT if the file could not be opened for writing.
 * @note   Truncates existing file to zero length.
 */
static int hip_relay_write_config(void)
{
    int err  = 0;
    FILE *fp = NULL;

    HIP_IFEL(((fp = fopen(HIP_RELAY_CONFIG_FILE, "w")) == NULL), -ENOENT,
             "Cannot open file %s for writing.\n", HIP_RELAY_CONFIG_FILE);

    fprintf(fp, HIP_RC_FILE_FORMAT_STRING, HIP_RC_FILE_CONTENT);

    if (fclose(fp) != 0) {
        HIP_ERROR("Cannot close file %s.\n", HIP_RELAY_CONFIG_FILE);
    }

out_err:

    return err;
}

/**
 * forward a control packet in relay or rvs mode
 *
 * @param ctx the packet context corresponding to the packet
 * @param rec the relay record corresponding to the packet
 * @param type_hdr message type
 * @return zero on success and negative on failure
 */
int hip_relay_forward(const struct hip_packet_context *ctx,
                      hip_relrec_t *rec,
                      const uint8_t type_hdr)
{
    hip_common_t *msg_to_be_relayed            = NULL;
    const struct hip_tlv_common *current_param = NULL;
    int err                                    = 0, from_added = 0;
    hip_tlv_type_t param_type                  = 0;

    HIP_DEBUG("Msg type :      %s (%d)\n",
              hip_message_type_name(hip_get_msg_type(ctx->input_msg)),
              hip_get_msg_type(ctx->input_msg));
    HIP_DEBUG_IN6ADDR("source address", &ctx->src_addr);
    HIP_DEBUG_IN6ADDR("destination address", &ctx->dst_addr);
    HIP_DEBUG_HIT("Relay record hit", &rec->hit_r);
    HIP_DEBUG("Relay record port: %d.\n", rec->udp_port_r);
    HIP_DEBUG("source port: %u, destination port: %u\n",
              ctx->msg_ports.src_port, ctx->msg_ports.dst_port);

    if (rec->type == HIP_RVSRELAY) {
        HIP_DEBUG("Relay type is RVS\n");
        param_type = HIP_PARAM_FROM;
    } else {
        HIP_DEBUG("Relay type is relay\n");
        param_type = HIP_PARAM_RELAY_FROM;
    }

    HIP_IFEL(!(msg_to_be_relayed = hip_msg_alloc()), -ENOMEM,
             "No memory\n");

    hip_build_network_hdr(msg_to_be_relayed, type_hdr, 0,
                          &ctx->input_msg->hits, &ctx->input_msg->hitr);

    /* Notice that in most cases the incoming I1 has no paramaters at all,
     * and this "while" loop is skipped. Multiple rvses en route to responder
     * is one (the only?) case when the incoming I1 packet has parameters. */
    while ((current_param = hip_get_next_param(ctx->input_msg,
                                               current_param))) {
        HIP_DEBUG("Found parameter in the packet.\n");
        /* Copy while type is smaller than or equal to FROM (RELAY_FROM)
         * or a new FROM (RELAY_FROM) has already been added. */
        if (from_added || hip_get_param_type(current_param) <= param_type) {
            HIP_DEBUG("Copying existing parameter to the packet " \
                      "to be relayed.\n");
            hip_build_param(msg_to_be_relayed, current_param);
        } else {
           /* Parameter under inspection has greater type than FROM
            * (RELAY_FROM) parameter: insert a new FROM (RELAY_FROM) parameter
            * between the previous parameter and "current_param". */
            HIP_DEBUG("Created new param %d and copied " \
                      "current parameter to relayed packet.\n",
                      param_type);
            if (param_type == HIP_PARAM_RELAY_FROM) {
                hip_build_param_relay_from(msg_to_be_relayed,
                                           &ctx->src_addr,
                                           ctx->msg_ports.src_port);
            } else {
                hip_build_param_from(msg_to_be_relayed, &ctx->src_addr);
            }
            hip_build_param(msg_to_be_relayed, current_param);
            from_added = 1;
        }
    }

    /* If the incoming packet had no parameters after the existing FROM
     * (RELAY_FROM) parameters, new FROM (RELAY_FROM) parameter is not added
     * until here. */
    if (!from_added) {
        HIP_DEBUG("No parameters found, adding a new param %d.\n",
                  param_type);
        if (param_type == HIP_PARAM_RELAY_FROM) {
            hip_build_param_relay_from(msg_to_be_relayed,
                                       &ctx->src_addr,
                                       ctx->msg_ports.src_port);
        } else {
            hip_build_param_from(msg_to_be_relayed, &ctx->src_addr);
        }
    }

    hip_zero_msg_checksum(msg_to_be_relayed);

    if (rec->type == HIP_RVSRELAY) {
        param_type = HIP_PARAM_RVS_HMAC;
    } else {
        param_type = HIP_PARAM_RELAY_HMAC;
    }

    /* Adding RVS_HMAC or RELAY_HMAC parameter as the last parameter
     * of the relayed packet. Notice that this presumes that there
     * are no parameters whose type value is greater than RVS_HMAC or
     * RELAY_HMAC in the incoming I1/I2 packet. */
    HIP_IFEL(hip_build_param_hmac(msg_to_be_relayed,
                                  &(rec->hmac_relay),
                                  param_type),
             -1, "Building of RVS_HMAC or RELAY_HMAC failed.\n");

    /* Note that we use NULL as source IP address instead of
     * i1_daddr. A source address is selected in the send function. */
    HIP_IFEL(hip_send_pkt(NULL, &rec->ip_r, hip_get_local_nat_udp_port(),
                          rec->udp_port_r, msg_to_be_relayed, NULL, 0),
             -ECOMM, "Relaying the packet failed.\n");

    rec->last_contact = time(NULL);

    HIP_DEBUG_HIT("Relayed the packet to", &rec->ip_r);

out_err:
    free(msg_to_be_relayed);
    return err;
}

/**
 * forward a HIP control packet with relay_to parameter
 *
 * @param r the HIP control message to be relayed
 * @param type_hdr message type
 * @param r_saddr the original source address
 * @param r_daddr the original destination address
 * @param relay_to_addr the address where to relay the packet
 * @param relay_to_port the port where to relay the packet
 * @return zero on success or negative on error
 */
static int hip_relay_forward_response(const hip_common_t *r,
                                      const uint8_t type_hdr,
                                      const struct in6_addr *r_saddr,
                                      const struct in6_addr *r_daddr,
                                      const struct in6_addr *relay_to_addr,
                                      const in_port_t relay_to_port)
{
    struct hip_common *r_to_be_relayed         = NULL;
    const struct hip_tlv_common *current_param = NULL;
    int err                                    = 0;

    HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  source address", r_saddr);
    HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  destination address", r_daddr);
    HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  relay to address", relay_to_addr);
    HIP_DEBUG("Relay_to port: %d.\n", relay_to_port);

    HIP_IFEL(!(r_to_be_relayed = hip_msg_alloc()), -ENOMEM,
             "No memory to copy original I1\n");

    hip_build_network_hdr(r_to_be_relayed, type_hdr, 0,
                          &(r->hits), &(r->hitr));

    while ((current_param = hip_get_next_param(r, current_param)) != NULL) {
        HIP_DEBUG("Found parameter in R.\n");
        HIP_DEBUG("Copying existing parameter to R packet " \
                  "to be relayed.\n");
        hip_build_param(r_to_be_relayed, current_param);
    }

    hip_zero_msg_checksum(r_to_be_relayed);

    if (relay_to_port == 0) {
        HIP_IFEL(hip_send_pkt(NULL, relay_to_addr, hip_get_local_nat_udp_port(),
                              relay_to_port, r_to_be_relayed, NULL, 0),
                 -ECOMM, "forwarding response failed in raw\n");
    } else {
        HIP_IFEL(hip_send_pkt(NULL, relay_to_addr, hip_get_local_nat_udp_port(),
                              relay_to_port, r_to_be_relayed, NULL, 0),
                 -ECOMM, "forwarding response failed in UDP\n");
    }

    HIP_DEBUG_HIT("hip_relay_forward_response: Relayed  to", relay_to_addr);

out_err:
    free(r_to_be_relayed);
    return err;
}

/**
 * handle a HIP control message with relay_to parameter
 *
 * @return zero on success or negative on error
 */
int hip_relay_handle_relay_to(const uint8_t packet_type,
                              UNUSED const uint32_t ha_state,
                              struct hip_packet_context *ctx)
{
    int err           = 0;
    hip_relrec_t *rec = NULL, dummy;
    const struct hip_relay_to *relay_to;
    //check if full relay service is active

    if (hip_relay_get_status() == HIP_RELAY_OFF) {
        /* Should we set err to -1? */
        goto out_err;
    }

    HIP_DEBUG("handle_relay_to: full relay is on\n");
    // check if the relay has been registered

    /* Check if we have a relay record in our database matching the
     * I's HIT. We should find one, if the I is
     * registered to relay.*/
    HIP_DEBUG_HIT("Searching relay record on HIT:",
                  &ctx->input_msg->hits);

    memcpy(&(dummy.hit_r), &ctx->input_msg->hits, sizeof(ctx->input_msg->hits));
    rec = hip_relht_get(&dummy);

    if (rec == NULL) {
        HIP_DEBUG("handle_relay_to: No matching relay record found.\n");
        goto out_err;
    } else if (rec->type == HIP_RVSRELAY) {
        goto out_err;
    }

    HIP_DEBUG("handle_relay_to: Matching relay record found:Full-Relay.\n");

    //check if there is a relay_to parameter
    relay_to = hip_get_param(ctx->input_msg, HIP_PARAM_RELAY_TO);
    HIP_IFEL(!relay_to, 0, "No relay_to  found\n");

    // check msg type
    switch (packet_type) {
    case HIP_R1:
    case HIP_R2:
    case HIP_UPDATE:
    case HIP_NOTIFY:
        HIP_DEBUG_IN6ADDR("the relay to address: ", &relay_to->address);
        HIP_DEBUG("the relay to ntohs(port): %d",
                  ntohs(relay_to->port));
        hip_relay_forward_response(ctx->input_msg,
                                   packet_type,
                                   &ctx->src_addr,
                                   &ctx->dst_addr,
                                   &relay_to->address,
                                   ntohs(relay_to->port));
        //  state = HIP_STATE_NONE;
        err = 1;
        goto out_err;
    }

out_err:
    return err;
}

/**
 * store the address of a peer's rendezvous server to the host association
 *
 * @param source_msg the I1 message
 * @param entry the host association
 * @return zero on success or negative on error
 *
 * @todo handle also the relay case
 */
int hip_relay_add_rvs_to_ha(const hip_common_t *source_msg, hip_ha_t *entry)
{
    const struct hip_via_rvs *via_rvs = NULL;
    int err                     = 0;

    // Get rendezvous server's IP addresses
    via_rvs = hip_get_param(source_msg, HIP_PARAM_VIA_RVS);

    if (!via_rvs) {
        return -1;
    }

    if (!entry->rendezvous_addr) {
        HIP_IFEL(!(entry->rendezvous_addr = malloc(sizeof(struct in6_addr))),
                 -1, "Malloc failed for in6_addr\n");
    }

    memcpy(entry->rendezvous_addr, &via_rvs->address, sizeof(struct in6_addr));
    if (!entry->rendezvous_addr) {
        HIP_DEBUG("Couldn't get rendezvous IP address.");
        return -1;
    }

    HIP_DEBUG_IN6ADDR("The rvs address: ", entry->rendezvous_addr);

out_err:
    return err;
}

/**
 * handle from/relay_from parameter in a HIP control message
 *
 * @param source_msg the HIP control message
 * @param relay_ip the source IP address of the message
 * @param dest_ip the relayed destination will be written here
 * @param dest_port the relayed destination port will be written here
 * @return 0 if no FROM/RELAY FROM parameter is found, parameter type
 *         if one is found, negative on error
 */
int hip_relay_handle_relay_from(hip_common_t *source_msg,
                                RVS struct in6_addr *relay_ip,
                                struct in6_addr *dest_ip, in_port_t *dest_port)
{
    int param_type;
    const struct hip_relay_from *relay_from = NULL;
    const struct hip_from *from             = NULL;
#ifdef CONFIG_HIP_RVS
    hip_ha_t *relay_ha_entry                = NULL;
#endif

    /* Check if the incoming I1 packet has  RELAY_FROM parameters. */
    relay_from = hip_get_param(source_msg, HIP_PARAM_RELAY_FROM);

    /* Copy parameter data to target buffers. */
    if (relay_from == NULL) {
        from = hip_get_param(source_msg, HIP_PARAM_FROM);
        if (from == NULL) {
            HIP_DEBUG("No FROM/RELAY_FROM parameters found in I.\n");
            return 0;
        } else {
            HIP_DEBUG("Found FROM parameter in I1.\n");
            param_type = HIP_PARAM_FROM;
            memcpy(dest_ip, &from->address, sizeof(from->address));
            /* No port number in RVS FROM. hip_send_r1() fills in this later */
            *dest_port = 0;
            HIP_DEBUG("FROM port in I1: %d \n", *dest_port);
        }
    } else {
        HIP_DEBUG("Found RELAY_FROM parameter in I.\n");
        // set the relay ip and port to the destination address and port.
        param_type = HIP_PARAM_RELAY_FROM;

        memcpy(dest_ip, &relay_from->address, sizeof(relay_from->address));
        *dest_port = ntohs(relay_from->port);
        HIP_DEBUG("RELAY_FROM port in I. %d \n", *dest_port);
    }

    /* The relayed I1 packet has the initiator's HIT as source HIT, and the
     * responder HIT as destination HIT. We would like to verify the HMAC
     * against the host association that was created when the responder
     * registered to the rvs. That particular host association has the
     * responder's HIT as source HIT and the rvs' HIT as destination HIT.
     * Because we do not have the HIT of Relay in the incoming I1 message, we
     * have to get the host association using the responder's HIT and the IP
     * address of the Relay as search keys.
     *
     * the fucntion hip_hadb_find_rvs_candidate_entry is designed for RVS case, but
     * we reuse it in Relay also.
     */
#ifdef CONFIG_HIP_RVS
    relay_ha_entry =
        hip_hadb_find_rvs_candidate_entry(&source_msg->hitr, relay_ip);

    if (relay_ha_entry == NULL) {
        HIP_DEBUG_HIT("relay hit not found in the entry table rvs_ip:",
                      relay_ip);
        HIP_DEBUG_HIT("relay hit not found in the entry table " \
                      "&source_msg->hitr:", &source_msg->hitr);
        HIP_DEBUG("The I1 packet was received from Relay, but the host " \
                  "association created during registration is not found. "
                  "RVS_HMAC cannot be verified.\n");
        return -1;
    }

    HIP_DEBUG("RVS host or relay host association found.\n");

    if (relay_from != NULL &&
        hip_verify_packet_hmac_general(source_msg,
                                       &relay_ha_entry->hip_hmac_out,
                                       HIP_PARAM_RELAY_HMAC ) != 0) {
        /* Notice that the HMAC is currently ignored to allow rvs/relay e.g.
         * in the following use case: I <----IPv4 ----> RVS <----IPv6---> R
         * Otherwise we have to loop through all host associations and try
         * all HMAC keys. See bug id 592172 */
        HIP_DEBUG("Full_Relay_HMAC verification failed.\n");
        HIP_DEBUG("Ignoring HMAC verification\n");
    } else if (from != NULL &&
               hip_verify_packet_hmac_general(source_msg,
                                              &relay_ha_entry->hip_hmac_out,
                                              HIP_PARAM_RVS_HMAC ) != 0) {
        HIP_DEBUG("RVS_HMAC verification failed.\n");
        HIP_DEBUG("Ignoring HMAC verification\n");
    }

    HIP_DEBUG("RVS_HMAC or Full_Relay verified.\n");
#endif  /* CONFIG_HIP_RVS */

    return param_type;
}

/**
 * handle the relay_to parameter at the Initiator
 *
 * @return zero on success or negative on error
 */
int hip_relay_handle_relay_to_in_client(const uint8_t packet_type,
                                        UNUSED const uint32_t ha_state,
                                        struct hip_packet_context *ctx)
{
    int err = 0;
    const struct hip_relay_to *relay_to;
    //check if full relay service is active

    if (!ctx->hadb_entry) {
        HIP_DEBUG("handle relay_to in client is failed\n");
        goto out_err;
    }


    HIP_DEBUG("handle relay_to in client is on\n");
    // check if the relay has been registered

    //check if there is a relay_to parameter
    relay_to = hip_get_param(ctx->input_msg, HIP_PARAM_RELAY_TO);
    HIP_IFEL(!relay_to, 0, "No relay_to  found\n");

    // check msg type
    switch (packet_type) {
    case HIP_R1:
    case HIP_R2:
        HIP_DEBUG_IN6ADDR("the relay to address: ", &relay_to->address);
        HIP_DEBUG("the relay to ntohs(port): %d, local udp port %d\n",
                  ntohs(relay_to->port), ctx->hadb_entry->local_udp_port);

        if (ipv6_addr_cmp(&relay_to->address, &ctx->hadb_entry->our_addr)) {
            HIP_DEBUG("relay_to address is saved as reflexive addr. \n");
            ctx->hadb_entry->local_reflexive_udp_port = ntohs(relay_to->port);
            memcpy(&ctx->hadb_entry->local_reflexive_address,
                   &relay_to->address, sizeof(struct in6_addr));
        }
        err = 1;
        goto out_err;
    }

out_err:
    return err;
}

/**
 * Initializes the global HIP relay hashtable. Allocates memory for
 * @c hiprelay_ht.
 *
 * @return zero on success, -1 otherwise.
 * @note   do not call this function directly, instead call hip_relay_init().
 */
static int hip_relht_init(void)
{
    /* Check that the relay hashtable is not already initialized. */
    if (hiprelay_ht != NULL) {
        return -1;
    }

    hiprelay_ht = hip_ht_init(LHASH_HASH_FN(hip_relht),
                              LHASH_COMP_FN(hip_relht));

    if (hiprelay_ht == NULL) {
        return -1;
    }

    return 0;
}

/**
 * Uninitializes the HIP relay record hashtable @c hiprelay_ht. Frees the memory
 * allocated for the hashtable and for the relay records. Thus, after calling
 * this function, all memory allocated from the heap related to the relay record
 * hashtable is free.
 *
 * @note do not call this function directly, instead call hip_relay_uninit().
 */
static void hip_relht_uninit(void)
{
    if (hiprelay_ht == NULL) {
        return;
    }

    hip_ht_doall(hiprelay_ht, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(hip_relht_rec_free));
    hip_ht_uninit(hiprelay_ht);
    hiprelay_ht = NULL;
}
/**
 * Initializes the global HIP relay whitelist. Allocates memory for
 * @c hiprelay_wl.
 *
 * @return zero on success, -1 otherwise.
 * @note   do not call this function directly, instead call hip_relay_init().
 */

static int hip_relwl_init(void)
{
    /* Check that the relay whitelist is not already initialized. */
    if (hiprelay_wl != NULL) {
        return -1;
    }

    hiprelay_wl = hip_ht_init(LHASH_HASH_FN(hip_relwl),
                              LHASH_COMP_FN(hip_relwl));

    if (hiprelay_wl == NULL) {
        return -1;
    }

    return 0;
}

/**
 * Uninitializes the HIP relay whitelist hashtable @c hiprelay_wl. Frees the
 * memory allocated for the hashtable and for the HITs. Thus, after calling
 * this function, all memory allocated from the heap related to the whitelist
 * is free.
 *
 * @note do not call this function directly, instead call hip_relay_uninit().
 */
static void hip_relwl_uninit(void)
{
    if (hiprelay_wl == NULL) {
        return;
    }

    hip_ht_doall(hiprelay_wl, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(hip_relwl_hit_free));
    hip_ht_uninit(hiprelay_wl);
    hiprelay_wl = NULL;
}

/**
 * Initializes the HIP relay / RVS. Initializes the HIP relay hashtable and
 * whitelist.
 */
int hip_relay_init(void)
{
    int err = 0;

    HIP_IFEL(hip_relht_init(), -1,
             "Unable to initialize HIP relay / RVS database.\n");
    HIP_IFEL(hip_relwl_init(), -1,
             "Unable to initialize HIP relay / RVS whitelist.\n");

    if (hip_relay_read_config() == -ENOENT) {
        HIP_ERROR("The configuration file \"%s\" could not be read.\n" \
                  "Trying to write a new configuration file from " \
                  "scratch.\n", HIP_RELAY_CONFIG_FILE);
        if (hip_relay_write_config() == -ENOENT) {
            HIP_ERROR("Could not create a configuration file " \
                      "\"%s\".\n", HIP_RELAY_CONFIG_FILE);
        } else {
            HIP_DEBUG("Created a new configuration file \"%s\".\n",
                      HIP_RELAY_CONFIG_FILE);
        }
    } else {
        HIP_DEBUG("Read configuration file \"%s\" successfully.\n",
                  HIP_RELAY_CONFIG_FILE);
    }

out_err:
    if (hiprelay_wl == NULL) {
        hip_relht_uninit();
    }

    return err;
}

/**
 * Uninitializes the HIP relay / RVS. Uninitializes the HIP relay hashtable and
 * whitelist.
 */
void hip_relay_uninit(void)
{
    hip_relht_uninit();
    hip_relwl_uninit();
}

/**
 * Reinitializes the HIP relay / RVS. Deletes the old values from the relay
 * whitelist and reads new values from the configuration file
 * @c HIP_RELAY_CONFIG_FILE. Besides the whitelist values also every other
 * value read from the configuration file is reinitialized. These include the
 * lifetime values etc. However, the existing relay records are left as they
 * were. This means that the relay / RVS clients that have already registered
 * continue to be served as before - even if their HIT nomore exists in the
 * whitelist.
 *
 * @return zero if the configuration file was read succesfully, -1 otherwise.
 */
int hip_relay_reinit(void)
{
    int err = 0;

    hip_relwl_uninit();
    HIP_IFEL(hip_relwl_init(), -1, "Could not initialize the HIP relay / ",
             "RVS whitelist.\n");
    HIP_IFEL(hip_relay_read_config(), -1, "Could not read the ",
             "configuration file \"%s\"\n", HIP_RELAY_CONFIG_FILE);

out_err:
    return err;
}

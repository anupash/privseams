/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * Stores security association for IPsec connections and makes them
 * accessible through HITs and {dst IP, SPI}.
 *
 * @brief Security association database for IPsec connections
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <sys/time.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/esp_prot_common.h"
#include "lib/core/hashchain.h"
#include "lib/core/hashtable.h"
#include "lib/core/ife.h"
#include "lib/core/keylen.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/state.h"
#include "esp_prot_api.h"
#include "esp_prot_defines.h"
#include "firewall.h"
#include "user_ipsec_sadb.h"


/* hash functions used for calculating the entries' hashes
 *
 * TODO use own function to hash hits to improve performance
 */
#define INDEX_HASH_FN           HIP_DIGEST_SHA1
/* the length of the hash value used for indexing */
#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

/* Structure for demultiplexing inbound ipsec packets, indexed by dst_addr and spi */
typedef struct hip_link_entry {
    struct in6_addr  dst_addr;        /* destination address of outer IP header */
    uint32_t         spi;             /* ipsec spi, needed for demultiplexing incoming packets */
    hip_sa_entry_t * linked_sa_entry; /* direct link to sa entry */
} hip_link_entry_t;

/* database storing the sa entries, indexed by src _and_ dst hits */
HIP_HASHTABLE *sadb   = NULL;
/* database storing shortcuts to sa entries for incoming packets */
HIP_HASHTABLE *linkdb = NULL;


/**
 * hashes the inner addresses (for now) to lookup the corresponding SA entry
 *
 * @param sa_entry  partial SA entry containing inner addresses and IPsec mode
 * @return          hash of inner addresses
 */
static unsigned long hip_sa_entry_hash(const hip_sa_entry_t *sa_entry)
{
    struct in6_addr addr_pair[2];               /* in BEET-mode these are HITs */
    unsigned char hash[INDEX_HASH_LENGTH];
    int err = 0;

    memset(&hash, 0, INDEX_HASH_LENGTH);

    if (sa_entry->mode == 3) {
        /* use hits to index in beet mode
         *
         * NOTE: the index won't change during ongoing connection
         * NOTE: the HIT fields of an host association struct cannot be assumed to
         * be alligned consecutively. Therefore, we must copy them to a temporary
         * array. */
        memcpy(&addr_pair[0], &sa_entry->inner_src_addr, sizeof(struct in6_addr));
        memcpy(&addr_pair[1], &sa_entry->inner_dst_addr, sizeof(struct in6_addr));
    } else {
        HIP_ERROR("indexing for non-BEET-mode not implemented!\n");

        err = -1;
        goto out_err;
    }

    HIP_IFEL(hip_build_digest(INDEX_HASH_FN, addr_pair,
                              2 * sizeof(struct in6_addr), hash), -1,
                              "failed to hash addresses\n");

out_err:
    if (err) {
        memset(&hash, 0, INDEX_HASH_LENGTH);
    }

    // just consider sub-string of 4 bytes here
    return *((unsigned long *) hash);
}

/**
 * compares the hashes of 2 SA entries to check if they are the same
 *
 * @param sa_entry1     first SA entry to be compared with
 * @param sa_entry2     second SA entry to be compared with
 * @return              1 if different entries, else 0
 */
static int hip_sa_entries_cmp(const hip_sa_entry_t *sa_entry1,
                              const hip_sa_entry_t *sa_entry2)
{
    int err             = 0;
    unsigned long hash1 = 0;
    unsigned long hash2 = 0;

    // values have to be present
    HIP_ASSERT(sa_entry1 && sa_entry2);

    HIP_IFEL(!(hash1 = hip_sa_entry_hash(sa_entry1)), -1,
             "failed to hash sa entry\n");
    HIP_IFEL(!(hash2 = hip_sa_entry_hash(sa_entry2)), -1,
             "failed to hash sa entry\n");

    err = (hash1 != hash2);

out_err:
    return err;
}

/**
 * hashes the outer dst address and IPsec SPI to lookup the corresponding SA entry
 *
 * @param link_entry  link entry containing outer dst address and IPsec SPI
 * @return            hash of outer dst address and IPsec SPI
 */
static unsigned long hip_link_entry_hash(const hip_link_entry_t *link_entry)
{
    int input_length = sizeof(struct in6_addr) + sizeof(uint32_t);
    unsigned char hash_input[input_length];
    unsigned char hash[INDEX_HASH_LENGTH];
    int err          = 0;

    // values have to be present
    HIP_ASSERT(link_entry != NULL && link_entry->spi != 0);

    memset(hash, 0, INDEX_HASH_LENGTH);

    /* concatenate dst_addr and spi */
    memcpy(&hash_input[0], &link_entry->dst_addr, sizeof(struct in6_addr));
    memcpy(&hash_input[sizeof(struct in6_addr)], &link_entry->spi,
           sizeof(uint32_t));

    HIP_IFEL(hip_build_digest(INDEX_HASH_FN, hash_input,
                              input_length, hash),
             -1, "failed to hash addresses\n");

out_err:
    if (err) {
        memset(&hash, 0, INDEX_HASH_LENGTH);
    }

    // just consider sub-string of 4 bytes here
    return *((unsigned long *) hash);
}

/**
 * compares the hashes of 2 link entries to check if they are the same
 *
 * @param link_entry1   first link entry to be compared with
 * @param link_entry2   second link entry to be compared with
 * @return              1 if different entries, else 0
 */
static int hip_link_entries_cmp(const hip_link_entry_t *link_entry1,
                                const hip_link_entry_t *link_entry2)
{
    int err             = 0;
    unsigned long hash1 = 0;
    unsigned long hash2 = 0;

    // values have to be present
    HIP_ASSERT(link_entry1 != NULL && link_entry1->spi != 0);
    HIP_ASSERT(link_entry2 != NULL && link_entry2->spi != 0);

    HIP_IFEL(!(hash1 = hip_link_entry_hash(link_entry1)), -1,
             "failed to hash link entry\n");
    HIP_IFEL(!(hash2 = hip_link_entry_hash(link_entry2)), -1,
             "failed to hash link entry\n");

    err = (hash1 != hash2);

out_err:
    return err;
}

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 *
 * @param hip_sa_entry      function pointer
 * @param hip_sa_entry_t    type to be casted to
 *
 * @note appends _hash to given function
 */
static IMPLEMENT_LHASH_HASH_FN(hip_sa_entry, hip_sa_entry_t)

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 *
 * @param hip_sa_entries    function pointer
 * @param hip_sa_entry_t    type to be casted to
 *
 * @note appends _cmp to given function
 */
static IMPLEMENT_LHASH_COMP_FN(hip_sa_entries, hip_sa_entry_t)

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 *
 * @param hip_link_entry    function pointer
 * @param hip_link_entry_t  type to be casted to
 *
 * @note appends _hash to given function
 */
static IMPLEMENT_LHASH_HASH_FN(hip_link_entry, hip_link_entry_t)

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 *
 * @param hip_link_entries  function pointer
 * @param hip_link_entry_t  type to be casted to
 *
 * @note appends _cmp to given function
 */
static IMPLEMENT_LHASH_COMP_FN(hip_link_entries, hip_link_entry_t)

/**
 * finds a link entry in the linkdb
 *
 * @param dst_addr  outer destination address
 * @param spi       IPsec SPI number
 * @return          corresponding link entry
 */
static hip_link_entry_t * hip_link_entry_find(const struct in6_addr *dst_addr,
                                              uint32_t spi)
{
    hip_link_entry_t search_link;
    hip_link_entry_t *stored_link = NULL;
    int err = 0;

    // search the linkdb for the link to the corresponding entry
    memcpy(&search_link.dst_addr, dst_addr, sizeof(struct in6_addr));
    search_link.spi = spi;

    HIP_DEBUG("looking up link entry with following index attributes:\n");
    HIP_DEBUG_HIT("dst_addr", &search_link.dst_addr);
    HIP_DEBUG("spi: 0x%lx\n", search_link.spi);

    HIP_IFEL(!(stored_link = hip_ht_find(linkdb, &search_link)), -1,
             "failed to retrieve link entry\n");

out_err:
    if (err) {
        stored_link = NULL;
    }

    return stored_link;
}

/**
 * adds a link entry to the linkdb
 *
 * @param dst_addr  outer destination address
 * @param entry     SA entry this link points to
 * @return          0 on success, else -1
 */
static int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry)
{
    hip_link_entry_t *link = NULL;
    int err                = 0;

    HIP_IFEL(!(link = malloc(sizeof(hip_link_entry_t))),
             -1, "failed to allocate memory\n");

    memcpy(&link->dst_addr, dst_addr, sizeof(struct in6_addr));
    link->spi             = entry->spi;
    link->linked_sa_entry = entry;

    HIP_IFEL(hip_ht_add(linkdb, link), -1,
             "failed to add the link entry to linkdb\n");

out_err:
    return err;
}

/**
 * removes a link entry from the linkdb
 *
 * @param dst_addr  outer destination address
 * @param spi       SPI number
 * @return          0 on success, else -1
 */
static int hip_link_entry_delete(struct in6_addr *dst_addr, uint32_t spi)
{
    hip_link_entry_t *stored_link = NULL;
    int err                       = 0;

    // find link entry and free members
    HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, spi)), -1,
             "failed to retrieve link entry\n");

    /* @note do NOT free dst_addr, as this is a pointer to the same memory used
     *       by the sa entry */

    // delete the link
    // TODO check return type
    hip_ht_delete(linkdb, stored_link);
    // we still have to free the link itself
    free(stored_link);

    HIP_DEBUG("link entry deleted\n");

out_err:
    return err;
}

/**
 * sets the values of a SA entry
 *
 * @param entry             SA entry for which the values should be set
 * @param direction         direction of the SA
 * @param spi               IPsec SPI number
 * @param mode              ESP mode
 * @param src_addr          source address of outer IP header
 * @param dst_addr          destination address of outer IP header
 * @param inner_src_addr    inner source addresses for tunnel and BEET SAs
 * @param inner_dst_addr    inner destination addresses for tunnel and BEET SAs
 * @param encap_mode        encapsulation mode
 * @param src_port          src port for UDP encaps. ESP
 * @param dst_port          dst port for UDP encaps. ESP
 * @param ealg              crypto transform in use
 * @param auth_key          raw authentication key
 * @param enc_key           raw encryption key
 * @param lifetime          seconds until expiration
 * @param esp_prot_transform mode used for securing ipsec traffic
 * @param hash_item_length  length of the hash item
 * @param esp_num_anchors   number of anchors for parallel mode
 * @param esp_prot_anchors  hash item anchors
 * @param update            notification if this is an update
 * @return                  0 on success, else -1
 */
static int hip_sa_entry_set(hip_sa_entry_t *entry,
                            int direction,
                            uint32_t spi,
                            uint32_t mode,
                            struct in6_addr *src_addr,
                            struct in6_addr *dst_addr,
                            struct in6_addr *inner_src_addr,
                            struct in6_addr *inner_dst_addr,
                            uint8_t encap_mode,
                            uint16_t src_port,
                            uint16_t dst_port,
                            int ealg, struct hip_crypto_key *auth_key,
                            struct hip_crypto_key *enc_key,
                            uint64_t lifetime, uint8_t esp_prot_transform,
                            uint32_t hash_item_length,
                            uint16_t esp_num_anchors,
                            unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                            int update)
{
    int key_len         = 0;                            /* for 3-DES */
    unsigned char key1[8], key2[8], key3[8];            /* for 3-DES */
    int enc_key_changed = 0;
    int err             = 0;

    // TODO handle update case with credit-based authentication
    // -> introduce backup of spi and keying material

    /* copy values for non-zero members */
    entry->direction = direction;
    entry->spi       = spi;
    entry->mode      = mode;
    memcpy(&entry->src_addr, src_addr, sizeof(struct in6_addr));
    memcpy(&entry->dst_addr, dst_addr, sizeof(struct in6_addr));
    if (entry->mode == 3) {
        memcpy(&entry->inner_src_addr, inner_src_addr, sizeof(struct in6_addr));
        memcpy(&entry->inner_dst_addr, inner_dst_addr, sizeof(struct in6_addr));
    }
    entry->encap_mode = encap_mode;
    entry->src_port   = src_port;
    entry->dst_port   = dst_port;

    entry->ealg       = ealg;

    // copy raw keys, if they changed
    if (memcmp(entry->auth_key, auth_key, hip_auth_key_length_esp(ealg))) {
        memcpy(entry->auth_key, auth_key, hip_auth_key_length_esp(ealg));
    }

    if (hip_enc_key_length(ealg) > 0 && memcmp(entry->enc_key, enc_key,
                                               hip_enc_key_length(ealg))) {

        memcpy(entry->enc_key, enc_key, hip_enc_key_length(ealg));
        enc_key_changed = 1;
    }

    // set up encrpytion keys, if raw keys changed
    if (enc_key_changed) {
        // set up keys for the transform in use
        switch (ealg) {
        case HIP_ESP_3DES_SHA1:
        case HIP_ESP_3DES_MD5:
            key_len = hip_enc_key_length(ealg) / 3;

            memset(key1, 0, key_len);
            memset(key2, 0, key_len);
            memset(key3, 0, key_len);

            memcpy(key1, &enc_key[0], key_len);
            memcpy(key2, &enc_key[8], key_len);
            memcpy(key3, &enc_key[16], key_len);

            des_set_odd_parity((des_cblock *) key1);
            des_set_odd_parity((des_cblock *) key2);
            des_set_odd_parity((des_cblock *) key3);

            err  = des_set_key_checked((des_cblock *) key1, entry->ks[0]);
            err += des_set_key_checked((des_cblock *) key2, entry->ks[1]);
            err += des_set_key_checked((des_cblock *) key3, entry->ks[2]);

            HIP_IFEL(err, -1, "3DES key problem\n");

            break;
        case HIP_ESP_AES_SHA1:
            HIP_IFEL(!entry->enc_key, -1, "enc_key required!\n");

            /* AES key differs for encryption/decryption, so we need
             * to distinguish the directions here */
            if (direction == HIP_SPI_DIRECTION_OUT) {
                // needs length of key in bits
                HIP_IFEL(AES_set_encrypt_key(entry->enc_key->key,
                                             8 * hip_enc_key_length(entry->ealg),
                                             &entry->aes_key), -1, "AES key problem!\n");
            } else {
                HIP_IFEL(AES_set_decrypt_key(entry->enc_key->key,
                                             8 * hip_enc_key_length(entry->ealg),
                                             &entry->aes_key), -1, "AES key problem!\n");
            }

            break;
        case HIP_ESP_BLOWFISH_SHA1:
            BF_set_key(&entry->bf_key, hip_enc_key_length(ealg), enc_key->key);

            break;
        case HIP_ESP_NULL_SHA1:
        // same encryption chiper as next transform
        case HIP_ESP_NULL_MD5:
            // nothing needs to be set up
            break;
        default:
            HIP_ERROR("Unsupported encryption transform: %i.\n", ealg);

            err = -1;
            goto out_err;
        }
    }

    // only set the seq no in case there is NO update
    if (!update) {
        entry->sequence = 1;
    }
    entry->lifetime = lifetime;

    HIP_IFEL(esp_prot_sa_entry_set(entry, esp_prot_transform, hash_item_length,
                                   esp_num_anchors, esp_prot_anchors, update),
            -1, "failed to set esp protection members\n");

out_err:
    return err;
}

/**
 * updates an existing SA entry
 *
 * @param direction         direction of the SA
 * @param spi               IPsec SPI number
 * @param mode              ESP mode
 * @param src_addr          source address of outer IP header
 * @param dst_addr          destination address of outer IP header
 * @param inner_src_addr    inner source addresses for tunnel and BEET SAs
 * @param inner_dst_addr    inner destination addresses for tunnel and BEET SAs
 * @param encap_mode        encapsulation mode
 * @param src_port          src port for UDP encaps. ESP
 * @param dst_port          dst port for UDP encaps. ESP
 * @param ealg              crypto transform in use
 * @param auth_key          raw authentication key
 * @param enc_key           raw encryption key
 * @param lifetime          seconds until expiration
 * @param esp_prot_transform mode used for securing ipsec traffic
 * @param hash_item_length  length of the hash item
 * @param esp_num_anchors   number of anchors for parallel mode
 * @param esp_prot_anchors  hash item anchors
 * @param update            notification if this is an update
 * @return                  0 on success, else -1
 */
static int hip_sa_entry_update(int direction,
                               uint32_t spi,
                               uint32_t mode,
                               struct in6_addr *src_addr,
                               struct in6_addr *dst_addr,
                               struct in6_addr *inner_src_addr,
                               struct in6_addr *inner_dst_addr,
                               uint8_t encap_mode,
                               uint16_t src_port,
                               uint16_t dst_port,
                               int ealg,
                               struct hip_crypto_key *auth_key,
                               struct hip_crypto_key *enc_key,
                               uint64_t lifetime,
                               uint8_t esp_prot_transform,
                               uint32_t hash_item_length,
                               uint16_t esp_num_anchors,
                               unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                               int update)
{
    hip_sa_entry_t *stored_entry = NULL;
    int err                      = 0;

    // we need the sadb entry to go through entries in the linkdb
    HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(inner_src_addr,
                                                         inner_dst_addr)), -1,
                                                         "failed to retrieve sa entry\n");

    /* delete all links
     *
     * XX TODO more efficient to delete entries in inbound db for all (addr, oldspi)
     * or just those with (oldaddr, spi) */
    HIP_IFEL(hip_link_entry_delete(&stored_entry->dst_addr, stored_entry->spi),
             -1, "failed to remove links\n");

    /* change members of entry in sadb and add new links */
    HIP_IFEL(hip_sa_entry_set(stored_entry, direction, spi, mode, src_addr,
                              dst_addr, inner_src_addr, inner_dst_addr,
                              encap_mode, src_port, dst_port, ealg, auth_key,
                              enc_key, lifetime, esp_prot_transform,
                              hash_item_length, esp_num_anchors,
                              esp_prot_anchors, update),
                              -1, "failed to update the entry members\n");

    HIP_IFEL(hip_link_entry_add(&stored_entry->dst_addr, stored_entry), -1,
             "failed to add links\n");

    HIP_DEBUG("sa entry updated\n");

out_err:
    return err;
}

/**
 * frees an SA entry
 *
 * @param   entry SA entry to be freed
 */
static void hip_sa_entry_free(hip_sa_entry_t *entry)
{
    if (entry) {
        if (entry->auth_key) {
            free(entry->auth_key);
        }
        if (entry->enc_key) {
            free(entry->enc_key);
        }

        // also free all hchain related members
        esp_prot_sa_entry_free(entry);
    }
}

/**
 * adds an SA entry
 *
 * @param direction         direction of the SA
 * @param spi               IPsec SPI number
 * @param mode              ESP mode
 * @param src_addr          source address of outer IP header
 * @param dst_addr          destination address of outer IP header
 * @param inner_src_addr    inner source addresses for tunnel and BEET SAs
 * @param inner_dst_addr    inner destination addresses for tunnel and BEET SAs
 * @param encap_mode        encapsulation mode
 * @param src_port          src port for UDP encaps. ESP
 * @param dst_port          dst port for UDP encaps. ESP
 * @param ealg              crypto transform in use
 * @param auth_key          raw authentication key
 * @param enc_key           raw encryption key
 * @param lifetime          seconds until expiration
 * @param esp_prot_transform mode used for securing ipsec traffic
 * @param hash_item_length  length of the hash item
 * @param esp_num_anchors   number of anchors for parallel mode
 * @param esp_prot_anchors  hash item anchors
 * @param update            notification if this is an update
 * @return                  0 on success, else -1
 */
static int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
                            struct in6_addr *src_addr, struct in6_addr *dst_addr,
                            struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
                            uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
                            int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
                            uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
                            uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                            int update)
{
    hip_sa_entry_t *entry = NULL;
    int err               = 0;

    /* initialize members to 0/NULL */
    HIP_IFEL(!(entry = malloc(sizeof(hip_sa_entry_t))), -1,
             "failed to allocate memory\n");
    memset(entry, 0, sizeof(hip_sa_entry_t));

    HIP_IFEL(!(entry->auth_key = malloc(hip_auth_key_length_esp(ealg))),
             -1, "failed to allocate memory\n");
    memset(entry->auth_key, 0, hip_auth_key_length_esp(ealg));
    if (hip_enc_key_length(ealg) > 0) {
        HIP_IFEL(!(entry->enc_key = malloc(hip_enc_key_length(ealg))),
                 -1, "failed to allocate memory\n");
        memset(entry->enc_key, 0, hip_enc_key_length(ealg));
    }

    HIP_IFEL(hip_sa_entry_set(entry, direction, spi, mode, src_addr, dst_addr,
                              inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
                              auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
                              esp_num_anchors, esp_prot_anchors, update), -1, "failed to set the entry members\n");

    HIP_DEBUG("adding sa entry with following index attributes:\n");
    HIP_DEBUG_HIT("inner_src_addr", &entry->inner_src_addr);
    HIP_DEBUG_HIT("inner_dst_addr", &entry->inner_dst_addr);
    HIP_DEBUG("mode: %i\n", entry->mode);

    /* returns the replaced item or NULL on normal operation and error.
     * A new entry should not replace another one! */
    HIP_IFEL(hip_ht_add(sadb, entry), -1, "hash collision detected!\n");

    // add links to this entry for incoming packets
    HIP_IFEL(hip_link_entry_add(&entry->dst_addr, entry), -1, "failed to add link entries\n");

    HIP_DEBUG("sa entry added successfully\n");

out_err:
    if (err) {
        if (entry) {
            hip_link_entry_delete(&entry->dst_addr, entry->spi);
            hip_sa_entry_free(entry);
            free(entry);
        }
        entry = NULL;
    }

    return err;
}

/**
 * deletes a single SA entry
 *
 * @param src_addr the source address
 * @param dst_addr the destination address
 */
static int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
    hip_sa_entry_t *stored_entry = NULL;
    int err                      = 0;

    /* find entry in sadb and delete entries in linkdb for all (addr, spi)-matches */
    HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(src_addr, dst_addr)), -1,
             "failed to retrieve sa entry\n");

    HIP_IFEL(hip_link_entry_delete(&stored_entry->dst_addr, stored_entry->spi), -1, "failed to delete links\n");

    // delete the entry from the sadb
    hip_ht_delete(sadb, stored_entry);
    // free all entry members
    hip_sa_entry_free(stored_entry);
    // we still have to free the entry itself
    free(stored_entry);

    HIP_DEBUG("sa entry deleted\n");

out_err:
    return err;
}

/** initializes the sadb and the linkdb
 *
 * @return -1, if error occurred, else 0
 */
int hip_sadb_init(void)
{
    int err = 0;

    HIP_IFEL(!(sadb = hip_ht_init(LHASH_HASH_FN(hip_sa_entry),
                                  LHASH_COMP_FN(hip_sa_entries))), -1,
             "failed to initialize sadb\n");
    HIP_IFEL(!(linkdb = hip_ht_init(LHASH_HASH_FN(hip_link_entry),
                                    LHASH_COMP_FN(hip_link_entries))), -1,
             "failed to initialize linkdb\n");

    HIP_DEBUG("sadb initialized\n");

out_err:
    return err;
}

/**
 * uninits the sadb and linkdb by deleting all entries stored in there
 *
 * @return -1, if error occurred, else 0
 */
int hip_sadb_uninit(void)
{
    int err = 0;

    if ((err = hip_sadb_flush())) {
        HIP_ERROR("failed to flush sadb\n");
    }

    if (sadb) {
        free(sadb);
    }
    if (linkdb) {
        free(linkdb);
    }

    return err;
}

/**
 * adds or updates SA entry
 *
 * @param direction         direction of the SA
 * @param spi               IPsec SPI number
 * @param mode              ESP mode
 * @param src_addr          source address of outer IP header
 * @param dst_addr          destination address of outer IP header
 * @param inner_src_addr    inner source addresses for tunnel and BEET SAs
 * @param inner_dst_addr    inner destination addresses for tunnel and BEET SAs
 * @param encap_mode        encapsulation mode
 * @param local_port          src port for UDP encaps. ESP
 * @param peer_port          dst port for UDP encaps. ESP
 * @param ealg              crypto transform in use
 * @param auth_key          raw authentication key
 * @param enc_key           raw encryption key
 * @param lifetime          seconds until expiration
 * @param esp_prot_transform mode used for securing ipsec traffic
 * @param hash_item_length  length of the hash item
 * @param esp_num_anchors   number of anchors for parallel mode
 * @param esp_prot_anchors  hash item anchors
 * @param update            notification if this is an update
 * @param local_port        local port
 * @param peer_port         peer port
 * @param retransmission    retransmission
 * @return                  0 on success, else -1
 */
int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
                 struct in6_addr *src_addr, struct in6_addr *dst_addr,
                 struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
                 uint8_t encap_mode, uint16_t local_port, uint16_t peer_port,
                 int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
                 uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
                 uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                 UNUSED int retransmission, int update)
{
    int err                          = 0;
    struct in6_addr *check_local_hit = NULL;
    struct in6_addr *default_hit     = NULL;
    in_port_t src_port, dst_port;

    /* TODO handle retransmission correctly */

    default_hit = hip_fw_get_default_hit();

    /*
     * Switch port numbers depending on direction and make sure that we
     * are testing correct local hit.
     */
    if (direction == HIP_SPI_DIRECTION_OUT) {
        src_port        = local_port;
        dst_port        = peer_port;
        check_local_hit = inner_src_addr;
    } else {
        src_port        = peer_port;
        dst_port        = local_port;
        check_local_hit = inner_dst_addr;
    }

    HIP_DEBUG_HIT("default hit", default_hit);
    HIP_DEBUG_HIT("check hit", check_local_hit);

    HIP_IFEL(ipv6_addr_cmp(default_hit, check_local_hit), -1,
             "only default HIT supported in userspace ipsec\n");


    if (update) {
        HIP_IFEL(hip_sa_entry_update(direction, spi, mode, src_addr, dst_addr,
                                     inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
                                     auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
                                     esp_num_anchors, esp_prot_anchors, update), -1, "failed to update sa entry\n");
    } else {
        HIP_IFEL(hip_sa_entry_add(direction, spi, mode, src_addr, dst_addr,
                                  inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
                                  auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
                                  esp_num_anchors, esp_prot_anchors, update), -1, "failed to add sa entry\n");
    }

out_err:
    return err;
}

/**
 * removes an SA entry and all corresponding links from the sadb
 *
 * @param dst_addr  destination ip address of the entry
 * @param spi spi   number of the entry
 * @return          -1, if error occurred, else 0
 */
int hip_sadb_delete(struct in6_addr *dst_addr, uint32_t spi)
{
    hip_sa_entry_t *entry = NULL;
    int err               = 0;

    HIP_IFEL(!(entry = hip_sa_entry_find_inbound(dst_addr, spi)), -1,
             "failed to retrieve sa entry\n");

    HIP_IFEL(hip_sa_entry_delete(&entry->inner_src_addr, &entry->inner_dst_addr), -1,
             "failed to delete entry\n");

out_err:
    return err;
}

/**
 * flushes all entries in the sadb
 *
 * @return      -1, if error occurred, else 0
 */
int hip_sadb_flush(void)
{
    int err               = 0, i = 0;
    hip_list_t *item      = NULL, *tmp = NULL;
    hip_sa_entry_t *entry = NULL;

    // iterating over all elements
    list_for_each_safe(item, tmp, sadb, i)
    {
        HIP_IFEL(!(entry = (hip_sa_entry_t *) list_entry(item)), -1, "failed to get list entry\n");
        HIP_IFEL(hip_sa_entry_delete(&entry->inner_src_addr, &entry->inner_dst_addr), -1,
                 "failed to delete sa entry\n");
    }

    HIP_DEBUG("sadb flushed\n");

out_err:
    return err;
}

/**
 * searches the linkdb for corresponding SA entry
 *
 * @param dst_addr  outer destination address of the ip packet
 * @param spi       SPI number of the searched entry
 * @return          SA entry on success or NULL if no matching entry was found
 */
hip_sa_entry_t *hip_sa_entry_find_inbound(const struct in6_addr *dst_addr, uint32_t spi)
{
    hip_link_entry_t *stored_link = NULL;
    hip_sa_entry_t *stored_entry  = NULL;
    int err                       = 0;

    HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, spi)), -1,
             "failed to find link entry\n");

    stored_entry = stored_link->linked_sa_entry;

out_err:
    if (err) {
        stored_entry = NULL;
    }

    return stored_entry;
}

/**
 * searches the sadb for a SA entry
 *
 * @param src_hit   inner source address
 * @param dst_hit   inner destination address
 * @return          SA entry on success or NULL if no matching entry found
 */
hip_sa_entry_t *hip_sa_entry_find_outbound(const struct in6_addr *src_hit,
                                           const struct in6_addr *dst_hit)
{
    hip_sa_entry_t search_entry;
    hip_sa_entry_t *stored_entry = NULL;
    int err                      = 0;

    // fill search entry with information needed by the hash function
    memcpy(&search_entry.inner_src_addr, src_hit, sizeof(struct in6_addr));
    memcpy(&search_entry.inner_dst_addr, dst_hit, sizeof(struct in6_addr));
    search_entry.mode = BEET_MODE;

    HIP_DEBUG("looking up sa entry with following index attributes:\n");
    HIP_DEBUG_HIT("inner_src_addr", &search_entry.inner_src_addr);
    HIP_DEBUG_HIT("inner_dst_addr", &search_entry.inner_dst_addr);
    HIP_DEBUG("mode: %i\n", search_entry.mode);

    // find entry in sadb db
    HIP_IFEL(!(stored_entry = hip_ht_find(sadb, &search_entry)), -1,
             "failed to retrieve sa entry\n");

out_err:
    if (err) {
        stored_entry = NULL;
    }

    return stored_entry;
}

/** @file
 * This file defines tools of  blind extension for the Host Identity Protocol
 * See <a href="http://lib.tkk.fi/Diss/2008/isbn9789512295319/article6.pdf">Ylitalo et al, BLIND: a Complete Identity Protection Framework for End-hosts, April 2004</a> and the corresponding IETF draft <a href="http://tools.ietf.org/html/draft-zhang-hip-privacy-protection">Zhang et al,
An Extension of HIP Base Exchange to Support Identity Privacy, IETF draft, Work in Progress, March 2010</a>.
 *
 * @author  Laura Takkinen
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#define _BSD_SOURCE

#include <stdlib.h>

#include "blind.h"
#include "lib/core/hit.h"
#include "lib/core/hostid.h"

static int hip_blind_fingerprints(hip_ha_t *entry);

/**
 * find the blinded local host identifier from the HIDB
 *
 * @param nonce the nonce used to blind the HIT
 * @param test_hit the blinded HIT
 * @param local_hit the unblinded HIT will be copied here
 * @return zero on success or negative on error
 */
static int hip_blind_find_local_hi(uint16_t *nonce,  struct in6_addr *test_hit,
                                   struct in6_addr *local_hit)
{
    hip_list_t *curr, *iter;
    struct hip_host_id_entry *tmp;
    int err                    = 0, c;
    char *key                  = NULL;
    unsigned int key_len       = sizeof(struct in6_addr);
    struct in6_addr *blind_hit = NULL;

    // generate key = nonce|hit_our
    HIP_IFEL((key = malloc(sizeof(uint16_t) + sizeof(struct in6_addr))) == NULL,
             -1, "Couldn't allocate memory\n");

    HIP_IFEL((blind_hit = malloc(sizeof(struct in6_addr))) == NULL,
             -1, "Couldn't allocate memory\n");

    HIP_READ_LOCK_DB(hip_local_hostid_db);

    list_for_each_safe(curr, iter, hip_local_hostid_db, c)
    {
        tmp = (struct hip_host_id_entry *) list_entry(curr);
        HIP_HEXDUMP("Found HIT", &tmp->lhi.hit, 16);

        // let's test the hit
        memcpy(key, &tmp->lhi.hit, sizeof(struct in6_addr));
        memcpy(key + sizeof(struct in6_addr), &nonce, sizeof(uint16_t));
        HIP_IFEL(hip_do_blind(key, key_len, blind_hit), -1, "hip_do_blind failed \n");
        if (blind_hit == NULL) {
            err = -1;
            goto out_err;
        }
        HIP_HEXDUMP("test HIT:", test_hit, 16);
        if (hip_match_hit(test_hit, blind_hit)) {
            HIP_HEXDUMP("Plain HIT found:", &tmp->lhi.hit, 16);
            memcpy(local_hit, &tmp->lhi.hit, sizeof(struct in6_addr));
            goto out_err;
        }
    }

    HIP_READ_UNLOCK_DB(hip_local_hostid_db);

out_err:
    if (key) {
        free(key);
    }
    if (blind_hit) {
        free(blind_hit);
    }
    return err;
}

/**
 * test whether we should use blind or not based on an inbound packet
 *
 * @param msg a HIP control message
 * @param entry related host association
 * @param use_blind An output argument where the result will be written
 *                  One if blind should be used or zero otherwise.
 * @return zero on success or negative on error
o */
int hip_check_whether_to_use_blind(hip_common_t *msg, hip_ha_t *entry,  int *use_blind)
{
    /* Check for error conditions. */
    if (msg == NULL || use_blind == 0) {
        *use_blind = 0;
        return -1;
    }
    /* If packet controls define that BLIND should not be used, it does not
     * matter whether our host wishes to use BLIND or not.*/
    if (((ntohs(msg->control) & HIP_PACKET_CTRL_BLIND)) == 0) {
        *use_blind = 0;
        return 0;
    }
    /* Packet controls define that we should use BLIND. Let's check if we
     * have BLIND activated. */

    /* If the host association state defines that BLIND should be used, we
     * don't have to take into account the global BLIND status. The global
     * BLIND bit is set using hipconf, but we may have already created some
     * HIP associations having BLIND bit on. */
    if (entry != NULL && entry->blind != 0) {
        *use_blind = 1;
        return 0;
    } else if (entry == NULL) {
        *use_blind = 0;
        return 0;
    } else if (entry->blind == 0) {
        *use_blind = 0;
        return 0;
    } else {
        *use_blind = 0;
        return -1;
    }
}

/**
 * enable blind for a given host assocation
 *
 * @param entry a host association
 * @param not_used not used
 * @return zero
 */
static int hip_set_blind_on_sa(hip_ha_t *entry, void *not_used)
{
    int err = 0;

    if (entry) {
        entry->blind = 1;
    }

    return err;
}

/**
 * disable blind for a given host assocation
 *
 * @param entry a host association
 * @param not_used not used
 * @return zero
 */
static int hip_set_blind_off_sa(hip_ha_t *entry, void *not_used)
{
    int err = 0;

    if (entry) {
        entry->blind = 0;
    }

    return err;
}

/**
 * Enable blind globally for all host associations
 *
 * @return zero
 * @note this function has no effect if host association
 *       is in established state
 */
int hip_set_blind_on(void)
{
    int err = 0;

    hip_blind_status = 1;
    HIP_IFEL(hip_for_each_ha(hip_set_blind_on_sa, NULL), 0,
             "for_each_ha err.\n");

out_err:
    return err;
}

/**
 * Disable blind globally for all host associations
 *
 * @return zero
 * @note this function has no effect if host association
 *       is in established state
 */
int hip_set_blind_off(void)
{
    int err = 0;

    hip_blind_status = 0;
    HIP_IFEL(hip_for_each_ha(hip_set_blind_off_sa, NULL), 0,
             "for_each_ha err.\n");

out_err:
    return err;
}

/**
 * This functions is used to query if the blind is in use.
 *
 * @return Zero if blind is off and 1 if blind is on.
 */
int hip_blind_get_status(void)
{
    return hip_blind_status;
}

/**
 * Extract uint16_t type blind nonce from HIP control message
 *
 * @param msg message the message from where the nonce is extracted
 * @param msg_nonce the nonce will be written here
 * @return zero on success or negative on error
 */
int hip_blind_get_nonce(struct hip_common *msg, uint16_t *msg_nonce)
{
    int err                       = 0;
    struct hip_blind_nonce *nonce = NULL;

    // get value of the nonce from the i1 message
    HIP_IFEL((nonce = hip_get_param(msg, HIP_PARAM_BLIND_NONCE)) == NULL,
             -1, "hip_get_param_nonce failed\n");
    *msg_nonce = ntohs(nonce->nonce);
out_err:
    return err;
}

/**
 * Forms a plain HIT from a blinded one.
 *
 * @param  nonce     Nonce that is used to calculate the plain HIT.
 * @param  blind_hit Blinded HIT from where the plain HIT is formed.
 * @param  plain_hit Calculated plain HIT
 * @return zero on success or negative on error
 */
int hip_plain_fingerprint(uint16_t *nonce,  struct in6_addr *blind_hit,
                          struct in6_addr *plain_hit)
{
    int err = 0;

    HIP_IFEL(hip_blind_find_local_hi(nonce, blind_hit, plain_hit),
             -1, "hip_blind_find_local_hit failed\n");

out_err:
    return err;
}

/**
 * Form the blinded HIT from the key (SHA1 hash from the key).
 *
 * @param key Key from where the hash is calculated
 * @param key_len Length of the key
 * @param blind_hit Calculated blind HIT (hash)
 * @return zero on success or negative on error
 */
int hip_do_blind(char *key, unsigned int key_len, struct in6_addr *blind_hit)
{
    int err = 0;
    uint8_t digest[HIP_AH_SHA_LEN];

    HIP_DEBUG("\n");

    HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)),
             err, "Building of digest failed\n");

    bzero(blind_hit, sizeof(hip_hit_t));
    HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
                        ((uint8_t *) blind_hit) + 3,
                        sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
             -1, "encoding failed\n");

    HIP_DEBUG_HIT("HIT before prefix: ", blind_hit);
    set_hit_prefix(blind_hit);
    HIP_DEBUG_HIT("HIT after prefix: ", blind_hit);

out_err:
    return err;
}

/**
 * Sets nonce and calculates the blinded fingerprints for the hip_ha_t entry.
 *
 * @param entry hip_ha_t entry which blind fields are adjusted
 * @return zero on success or negative on error
 */
static int hip_blind_fingerprints(hip_ha_t *entry)
{
    int err              = 0;
    char *key_our        = NULL, *key_peer = NULL;
    unsigned int key_len = sizeof(struct in6_addr);

    HIP_DEBUG("\n");

    // get nonce
    get_random_bytes(&entry->blind_nonce_i, sizeof(uint16_t));

    // generate key = nonce|hit_our
    HIP_IFEL((key_our = malloc(sizeof(uint16_t) + sizeof(struct in6_addr))) == NULL,
             -1, "Couldn't allocate memory\n");
    memcpy(key_our, &entry->hit_our, sizeof(struct in6_addr));
    memcpy(key_our + sizeof(struct in6_addr), &entry->blind_nonce_i, sizeof(uint16_t));

    // generate key = nonce|hit_peer
    HIP_IFEL((key_peer = malloc(sizeof(uint16_t) + sizeof(struct in6_addr))) == NULL,
             -1, "Couldn't allocate memory\n");
    memcpy(key_peer, &entry->hit_peer, sizeof(struct in6_addr));
    memcpy(key_peer + sizeof(struct in6_addr), &entry->blind_nonce_i, sizeof(uint16_t));

    // build digests
    HIP_IFEL((err = hip_do_blind(key_our, key_len, &entry->hit_our_blind)),
             err, "Building of digest failed\n");
    HIP_IFEL((err = hip_do_blind(key_peer, key_len, &entry->hit_peer_blind)),
             err, "Building of digest failed\n");

out_err:
    return err;
}

/**
 * Tests if plain_hit blinded with nonce is same as @blind_hit
 *
 * @param nonce the nonce used for blinding the hit
 * @param plain_hit the plain HIT to be tested
 * @param blind_hit the blinded HIT
 *
 * @return zero on success or negative on error
 */
int hip_blind_verify(uint16_t *nonce, struct in6_addr *plain_hit,
                     struct in6_addr *blind_hit)
{
    int ret                   = 0;
    char *key                 = NULL;
    unsigned int key_len      = sizeof(struct in6_addr);
    struct in6_addr *test_hit = NULL;

    HIP_DEBUG("\n");

    test_hit = malloc(sizeof(struct in6_addr));
    if (test_hit == NULL) {
        HIP_ERROR("Couldn't allocate memory\n");
        ret = -1;
        goto out_err;
    }

    // generate key = nonce|hit_our
    key = malloc(sizeof(uint16_t) + sizeof(struct in6_addr));
    if (key == NULL) {
        HIP_ERROR("Couldn't allocate memory\n");
        ret = -1;
        goto out_err;
    }

    memcpy(key, plain_hit, sizeof(struct in6_addr));
    memcpy(key + sizeof(struct in6_addr), nonce, sizeof(uint16_t));

    // build digests
    ret = hip_do_blind(key, key_len, test_hit);
    if (ret == -1) {
        HIP_ERROR("Building of digest failed\n");
        goto out_err;
    }
    HIP_DEBUG_HIT("test_hit", test_hit);
    HIP_DEBUG_HIT("blind_hit", blind_hit);
    ret = ipv6_addr_cmp(test_hit, blind_hit);    //memcmp return 0 if equal

out_err:
    if (test_hit) {
        free(test_hit);
    }
    return ret == 0;
}
/**
 * build a blinded i1 message
 *
 * @param entry the related host association
 * @param mask a mask template for I1 packet without blind
 */
struct hip_common *hip_blind_build_i1(hip_ha_t *entry, uint16_t *mask)
{
    struct hip_common *i1;
    int err = 0;

    i1 = hip_msg_alloc();
    if (i1 == NULL) {
        HIP_ERROR("Out of memory\n");
        return NULL;
    }
    *mask |= HIP_PACKET_CTRL_BLIND;

    if (entry->blind) {
        HIP_DEBUG("Blind flag is on\n");
    } else {
        HIP_DEBUG("Blind flag is off\n");
    }

    // Set blinded fingerprints
    err = hip_blind_fingerprints(entry);
    if (err) {
        HIP_ERROR("hip_blind_fingerprints failed\n");
        return NULL;
    }
    // Build network header by using blinded HITs
    entry->hadb_misc_func->hip_build_network_hdr(i1, HIP_I1, *mask,
                                                 &entry->hit_our_blind,
                                                 &entry->hit_peer_blind);
    HIP_DEBUG("add nonce to the message\n");
    err = hip_build_param_blind_nonce(i1, entry->blind_nonce_i);
    if (err) {
        HIP_ERROR("Unable to attach nonce to the message.\n");
        return NULL;
    }
    return i1;
}

/**
 * Fill in the r2 message with required blind parameters
 *
 * @param i2 the receive I2 message
 * @param r2 message to be sent
 * @param entry the related host association
 * @param the default control flags mask template
 *
 * @return zero on success or negative on error
 */
int hip_blind_build_r2(struct hip_common *i2, struct hip_common *r2, hip_ha_t *entry, uint16_t *mask)
{
    int err                 = 0, host_id_in_enc_len = 0;
    uint8_t *enc_in_msg     = NULL;
    uint8_t *host_id_in_enc = NULL;
    unsigned char *iv       = NULL;

    /************ Encrypted ***********/
    switch (entry->hip_transform) {
    case HIP_HIP_AES_SHA1:
        HIP_IFEL(hip_build_param_encrypted_aes_sha1(r2, (struct hip_tlv_common *) entry->our_pub),
                 -1, "Building of param encrypted failed.\n");
        enc_in_msg     = hip_get_param(r2, HIP_PARAM_ENCRYPTED);
        HIP_ASSERT(enc_in_msg); /* Builder internal error. */
        iv             = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
        get_random_bytes(iv, 16);
        host_id_in_enc = enc_in_msg + sizeof(struct hip_encrypted_aes_sha1);
        break;
    case HIP_HIP_3DES_SHA1:
        HIP_IFEL(hip_build_param_encrypted_3des_sha1(r2, (struct hip_tlv_common *) entry->our_pub),
                 -1, "Building of param encrypted failed.\n");
        enc_in_msg     = hip_get_param(r2, HIP_PARAM_ENCRYPTED);
        HIP_ASSERT(enc_in_msg); /* Builder internal error. */
        iv             = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
        get_random_bytes(iv, 8);
        host_id_in_enc = enc_in_msg + sizeof(struct hip_encrypted_3des_sha1);
        break;
    case HIP_HIP_NULL_SHA1:
        HIP_IFEL(hip_build_param_encrypted_null_sha1(r2, (struct hip_tlv_common *) entry->our_pub),
                 -1, "Building of param encrypted failed.\n");
        enc_in_msg     = hip_get_param(r2, HIP_PARAM_ENCRYPTED);
        HIP_ASSERT(enc_in_msg); /* Builder internal error. */
        iv             = NULL;
        host_id_in_enc = enc_in_msg + sizeof(struct hip_encrypted_null_sha1);
        break;
    default:
        HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
                 &entry->hip_transform);
    }


    /* Calculate the length of the host id inside the encrypted param */
    host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

    /* Adjust the host id length for AES (block size 16).
     * build_param_encrypted_aes has already taken care that there is
     * enough padding */
    if (entry->hip_transform == HIP_HIP_AES_SHA1) {
        /* remainder */
        int rem = host_id_in_enc_len % 16;
        if (rem) {
            HIP_DEBUG("Remainder %d (for AES)\n", remainder);
            host_id_in_enc_len += rem;
        }
    }

    HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
                                  entry->hip_transform,
                                  host_id_in_enc_len,
                                  entry->hip_enc_out.key,
                                  HIP_DIRECTION_ENCRYPT), -1,
             "Building of param encrypted failed\n");

out_err:
    return err;
}

/**
 * verify a blinded R2 message
 *
 * @param r2 the R2 control message
 * @param entry the related host association
 *
 * @return zero if the message was ok or negative otherwise
 */
int hip_blind_verify_r2(struct hip_common *r2, hip_ha_t *entry)
{
    int err                            = 0;
    char *tmp_enc                      = NULL, *enc = NULL;
    struct hip_host_id *host_id_in_enc = NULL;
    unsigned char *iv                  = NULL;
    uint16_t crypto_len;
    struct in6_addr *plain_peer_hit    = NULL;

    //initiator has a state related to blinded hits -> finding plain hits and key material easily
    // get encrypted parameter and decrypt it -> should contain responder public key
    // verify that the plain fingerprint corresponds decrypted

    /* Extract encrypted parameter and decrypt it. There should be public host id
     * of responder.
     */
    /* Decrypt the HOST_ID and verify it against the sender HIT. */
    HIP_IFEL(!(enc = hip_get_param(r2, HIP_PARAM_ENCRYPTED)),
             -ENOENT, "Could not find enc parameter\n");

    HIP_IFEL(!(tmp_enc = malloc(hip_get_param_total_len(enc))), -ENOMEM,
             "No memory for temporary host_id\n");
    memcpy(tmp_enc, enc, hip_get_param_total_len(enc));

    /* Decrypt ENCRYPTED field. */

    switch (entry->hip_transform) {
    case HIP_HIP_AES_SHA1:
        host_id_in_enc = (struct hip_host_id *)
                         (tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
        iv             = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
        /* 4 = reserved, 16 = iv */
        crypto_len     = hip_get_param_contents_len(enc) - 4 - 16;
        HIP_DEBUG("aes crypto len: %d\n", crypto_len);
        break;
    case HIP_HIP_3DES_SHA1:
        host_id_in_enc = (struct hip_host_id *)
                         (tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
        iv             = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
        /* 4 = reserved, 8 = iv */
        crypto_len     = hip_get_param_contents_len(enc) - 4 - 8;
        break;
    case HIP_HIP_NULL_SHA1:
        host_id_in_enc = (struct hip_host_id *)
                         (tmp_enc + sizeof(struct hip_encrypted_null_sha1));
        iv             = NULL;
        /* 4 = reserved */
        crypto_len     = hip_get_param_contents_len(enc) - 4;
        break;
    default:
        HIP_IFEL(1, -EINVAL, "Unknown HIP transform: %d\n", &entry->hip_transform);
    }

    HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv, entry->hip_transform,
                                  crypto_len, entry->hip_enc_in.key,
                                  HIP_DIRECTION_DECRYPT), -EINVAL,
             "Decryption of Host ID failed\n");

    HIP_HEXDUMP("Decrypted HOST_ID", host_id_in_enc,
                hip_get_param_total_len(host_id_in_enc));

    HIP_IFEL(hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID, -EINVAL,
             "The decrypted parameter is not a host id\n");

    HIP_IFEL((plain_peer_hit = malloc(sizeof(struct in6_addr))) == NULL,
             -1, "Couldn't allocate memory\n");
    HIP_IFEL(hip_host_id_to_hit(host_id_in_enc, plain_peer_hit, HIP_HIT_TYPE_HASH100),
             -1, "hip_host_id_to_hit faile\n");
    HIP_IFEL(hip_blind_verify(&entry->blind_nonce_i,
                              plain_peer_hit,
                              &r2->hits) != 1, -1, "hip_blind_verity failed\n");

    /* Store the peer's public key to HA and validate it */
    /** @todo Do not store the key if the verification fails. */
    HIP_IFE(hip_init_peer(entry, r2, host_id_in_enc), -EINVAL);
    HIP_IFEL(entry->verify(entry->peer_pub_key, r2), -EINVAL,
             "Verification of R1 signature failed\n");

out_err:
    if (tmp_enc) {
        free(tmp_enc);
    }
    if (plain_peer_hit) {
        free(plain_peer_hit);
    }
    return err;
}

/**
 * Constructs a new blinde R1 packet payload
 *
 * @param src_hit      a pointer to the source host identity tag used in the
 *                     packet.
 * @param sign         a funtion pointer to a signature funtion.
 * @param host_id_priv a pointer to ...
 * @param host_id_pub  a pointer to ...
 * @param cookie       a pointer to ...
 * @return             zero on success, or negative error value on error.
 */
struct hip_common *hip_blind_create_r1(const struct in6_addr *src_hit,
                                       int (*sign)(void *key, struct hip_common *m),
                                       void *private_key,
                                       const struct hip_host_id *host_id_pub,
                                       int cookie_k)
{
    hip_common_t *msg = NULL;
    int err                                     = 0, dh_size1 = 0, dh_size2 = 0, written1 = 0, written2 = 0;
    int mask                                    = 0;
    uint8_t *dh_data1                                = NULL, *dh_data2 = NULL;
    hip_srv_t service_list[HIP_TOTAL_EXISTING_SERVICES];
    unsigned int service_count                  = 0;

    /* Supported HIP and ESP transforms. */
    hip_transform_suite_t transform_hip_suite[] = {
        HIP_HIP_AES_SHA1,
        HIP_HIP_3DES_SHA1,
        HIP_HIP_NULL_SHA1
    };
    hip_transform_suite_t transform_esp_suite[] = {
        HIP_ESP_3DES_SHA1,
        HIP_ESP_AES_SHA1,
        HIP_ESP_NULL_SHA1
    };

    HIP_DEBUG("hip_blind_create_r1() invoked.\n");

    HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

    /* Allocate memory for writing the first Diffie-Hellman shared secret */
    HIP_IFEL((dh_size1 = hip_get_dh_size(HIP_FIRST_DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size1\n");
    HIP_IFEL(!(dh_data1 = malloc(dh_size1)),
             -1, "Failed to alloc memory for dh_data1\n");
    memset(dh_data1, 0, dh_size1);

    /* Allocate memory for writing the second Diffie-Hellman shared secret */
    HIP_IFEL((dh_size2 = hip_get_dh_size(HIP_SECOND_DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size2\n");
    HIP_IFEL(!(dh_data2 = malloc(dh_size2)),
             -1, "Failed to alloc memory for dh_data2\n");
    memset(dh_data2, 0, dh_size2);

    /* Ready to begin building of the R1 packet */
    mask |= HIP_PACKET_CTRL_BLIND;

    HIP_DEBUG("mask=0x%x\n", mask);
    /*! \todo TH: hip_build_network_hdr has to be replaced with an apprporiate function pointer */
    HIP_DEBUG_HIT("src_hit used to build r1 network header", src_hit);
    hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

    /********** R1_COUNTER (OPTIONAL) *********/

    /********** PUZZLE ************/
    HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
                                    42 /* 2^(42-32) sec lifetime */, 0, 0),
             -1, "Cookies were burned. Bummer!\n");

    /********** Diffie-Hellman **********/
    HIP_IFEL((written1 = hip_insert_dh(dh_data1, dh_size1,
                                       HIP_FIRST_DH_GROUP_ID)) < 0,
             -1, "Could not extract the first DH public key\n");
    HIP_IFEL((written2 = hip_insert_dh(dh_data2, dh_size2,
                                       HIP_SECOND_DH_GROUP_ID)) < 0,
             -1, "Could not extract the second DH public key\n");

    HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
                                                     HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
                                                     HIP_SECOND_DH_GROUP_ID, dh_data2, written2), -1,
             "Building of DH failed.\n");


    /********** HIP transform. **********/
    HIP_IFEL(hip_build_param_hip_transform(msg,
                                           transform_hip_suite,
                                           sizeof(transform_hip_suite) /
                                           sizeof(hip_transform_suite_t)), -1,
             "Building of HIP transform failed\n");

    /********** ESP-ENC transform. **********/
    HIP_IFEL(hip_build_param_esp_transform(msg,
                                           transform_esp_suite,
                                           sizeof(transform_esp_suite) /
                                           sizeof(hip_transform_suite_t)), -1,
             "Building of ESP transform failed\n");


    /********** Host_id  is not included in the the blinded R1 **********/


    /********** REG_INFO *********/
    hip_get_active_services(service_list, &service_count);
    hip_build_param_reg_info(msg, service_list, service_count);

    /********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

    //HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

    /********** Signature 2 **********/
    HIP_IFEL(sign(private_key, msg), -1, "Signing of R1 failed.\n");

    /********** ECHO_REQUEST (OPTIONAL) *********/

    /* Fill puzzle parameters */
    {
        struct hip_puzzle *pz;
        uint64_t random_i;

        HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1,
                 "Internal error\n");

        /* hardcode kludge */
        pz->opaque[0] = 'H';
        pz->opaque[1] = 'I';
        //pz->opaque[2] = 'P';
        /* todo: remove random_i variable */
        get_random_bytes(&random_i, sizeof(random_i));
        pz->I         = random_i;
    }

    /************** Packet ready ***************/

    if (dh_data1) {
        free(dh_data1);
    }
    if (dh_data2) {
        free(dh_data2);
    }

    return msg;

out_err:
    if (msg) {
        free(msg);
    }
    if (dh_data1) {
        free(dh_data1);
    }
    if (dh_data2) {
        free(dh_data2);
    }

    return NULL;
}

/**
 * recreate a blind spool of R1 messages
 *
 * @param r1table the R1 table to fill
 * @param hit the local HIT
 * @param sign the signature function pointer
 * @param privkey the private key for signing
 * @param pubkey the corresponding public key
 * @return zero on success or negative on error
 */
int hip_blind_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit,
                           int (*sign)(void *key, struct hip_common *m),
                           void *privkey, struct hip_host_id *pubkey)
{
    int i = 0;
    for (i = 0; i < HIP_R1TABLESIZE; i++) {
        int cookie_k;

        cookie_k      = hip_get_cookie_difficulty(NULL);

        r1table[i].r1 = hip_blind_create_r1(hit, sign, privkey, pubkey,
                                            cookie_k);
        if (!r1table[i].r1) {
            HIP_ERROR("Unable to precreate R1s\n");
            goto err_out;
        }

        HIP_DEBUG("Packet %d created\n", i);
    }

    return 1;

err_out:
    return 0;
}

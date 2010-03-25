/** @file
 * This file defines handling functions for incoming packets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Laura Takkinen
 * @author  Rene Hummen
 * @author  Samu Varjonen
 * @author  Tim Just
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
/* required for s6_addr32 */
#define _BSD_SOURCE

#include "config.h"
#include "input.h"
#include "hadb.h"
#include "oppdb.h"
#include "user.h"
#include "keymat.h"
#include "lib/core/crypto.h"
#include "lib/core/builder.h"
#include "lib/core/hip_udp.h"
#include "lib/core/solve.h"
#include "lib/core/transform.h"
#include "lib/core/keylen.h"
#include "dh.h"

#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "lib/tool/pk.h"
#include "netdev.h"
#include "lib/tool/lutil.h"
#include "lib/core/state.h"
#include "lib/core/hit.h"
#include "oppdb.h"
#include "registration.h"
#include "hipd.h"
#include "oppipdb.h"
#include "pkt_handling.h"

#ifdef CONFIG_HIP_PERFORMANCE
#include "lib/performance/performance.h"
#endif

/**
 * Verifies a HMAC.
 *
 * @param buffer    the packet data used in HMAC calculation.
 * @param hmac      the HMAC to be verified.
 * @param hmac_key  integrity key used with HMAC.
 * @param hmac_type type of the HMAC digest algorithm.
 * @return          0 if calculated HMAC is same as @c hmac, otherwise < 0. On
 *                  error < 0 is returned.
 * @note            Fix the packet len before calling this function!
 */
static int hip_verify_hmac(struct hip_common *buffer, uint16_t buf_len,
                           uint8_t *hmac, void *hmac_key, int hmac_type)
{
    int err = 0;
    uint8_t hmac_res[HIP_AH_SHA_LEN];

    HIP_HEXDUMP("HMAC data", buffer, buf_len);

    HIP_IFEL(hip_write_hmac(hmac_type, hmac_key, buffer,
                            buf_len, hmac_res),
             -EINVAL, "Could not build hmac\n");

    HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);
    HIP_IFE(memcmp(hmac_res, hmac, HIP_AH_SHA_LEN), -EINVAL);


out_err:

    return err;
}

/**
 * Verifies gerenal HMAC in HIP msg
 *
 * @param msg HIP packet
 * @param entry HA
 * @param parameter_type
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac_general(struct hip_common *msg,
                                   const struct hip_crypto_key *crypto_key,
                                   const hip_tlv_type_t parameter_type)
{
    int err               = 0, len = 0, orig_len = 0;
    struct hip_crypto_key tmpkey;
    struct hip_hmac *hmac = NULL;
    uint8_t orig_checksum      = 0;

    HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");

    HIP_IFEL(!(hmac = hip_get_param(msg, parameter_type)),
             -ENOMSG, "No HMAC parameter\n");

    /* hmac verification modifies the msg length temporarily, so we have
     * to restore the length */
    orig_len      = hip_get_msg_total_len(msg);

    /* hmac verification assumes that checksum is zero */
    orig_checksum = hip_get_msg_checksum(msg);
    hip_zero_msg_checksum(msg);

    len           = (uint8_t *) hmac - (uint8_t *) msg;
    hip_set_msg_total_len(msg, len);

    _HIP_HEXDUMP("HMAC key", crypto_key->key,
                 hip_hmac_key_length(HIP_ESP_AES_SHA1));
    _HIP_HEXDUMP("HMACced data:", msg, len);

    memcpy(&tmpkey, crypto_key, sizeof(tmpkey));
    HIP_IFEL(hip_verify_hmac(msg, hip_get_msg_total_len(msg),
                             hmac->hmac_data, tmpkey.key,
                             HIP_DIGEST_SHA1_HMAC),
             -1, "HMAC validation failed\n");

    /* revert the changes to the packet */
    hip_set_msg_total_len(msg, orig_len);
    hip_set_msg_checksum(msg, orig_checksum);

out_err:
    return err;
}

/**
 * Verifies packet HMAC
 *
 * @param msg HIP packet
 * @param entry HA
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac(struct hip_common *msg,
                           struct hip_crypto_key *crypto_key)
{
    return hip_verify_packet_hmac_general(msg, crypto_key, HIP_PARAM_HMAC);
}

/**
 * Verifies packet RVS_HMAC
 * @param msg HIP packet
 * @param entry HA
 *
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_rvs_hmac(struct hip_common *msg,
                               struct hip_crypto_key *crypto_key)
{
    return hip_verify_packet_hmac_general(msg, crypto_key,
                                          HIP_PARAM_RVS_HMAC);
}

/**
 * Verifies packet HMAC
 *
 * @param msg HIP packet
 * @param entry HA
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated. Assumes that the hmac includes only the header
 * and host id.
 */
static int hip_verify_packet_hmac2(struct hip_common *msg,
                                   struct hip_crypto_key *key,
                                   struct hip_host_id *host_id)
{
    struct hip_crypto_key tmpkey;
    struct hip_hmac *hmac;
    struct hip_common *msg_copy = NULL;
    int err                     = 0;

    _HIP_DEBUG("hip_verify_packet_hmac2() invoked.\n");
    HIP_IFE(!(msg_copy = hip_msg_alloc()), -ENOMEM);

    HIP_IFEL(hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
             "Pseudo hmac2 pkt failed\n");

    HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC2)), -ENOMSG,
             "Packet contained no HMAC parameter\n");
    HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));

    memcpy( &tmpkey,  key, sizeof(tmpkey));

    HIP_IFEL(hip_verify_hmac(msg_copy, hip_get_msg_total_len(msg_copy),
                             hmac->hmac_data, tmpkey.key,
                             HIP_DIGEST_SHA1_HMAC),
             -1, "HMAC validation failed\n");

out_err:
    if (msg_copy) {
        HIP_FREE(msg_copy);
    }

    return err;
}

/**
 * Creates shared secret and produce keying material
 * The initial ESP keys are drawn out of the keying material.
 *
 * TODO doxygen header incomplete
 * @param msg the HIP packet received from the peer
 * @param ctx context
 * @param dhpv pointer to the DH public value choosen
 * @return zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_packet_context *packet_ctx,
                                uint64_t I,
                                uint64_t J,
                                struct hip_dh_public_value **dhpv)
{
    char *dh_shared_key = NULL;
    int hip_transf_length, hmac_transf_length;
    int auth_transf_length, esp_transf_length, we_are_HITg = 0;
    int hip_tfm, esp_tfm, err = 0, dh_shared_len = 1024;
    struct hip_keymat_keymat km;
    struct hip_esp_info *esp_info;
    char *keymat                     = NULL;
    size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
    size_t keymat_len;     /* note SHA boundary */
    struct hip_tlv_common *param     = NULL;
    uint16_t esp_keymat_index, esp_default_keymat_index;
    struct hip_diffie_hellman *dhf;
    struct in6_addr *plain_local_hit = NULL;

    _HIP_DEBUG("hip_produce_keying_material() invoked.\n");
    /* Perform light operations first before allocating memory or
     * using lots of CPU time */
    HIP_IFEL(!(param = hip_get_param(packet_ctx->input_msg, HIP_PARAM_HIP_TRANSFORM)),
             -EINVAL,
             "Could not find HIP transform\n");
    HIP_IFEL((hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
             -EINVAL, "Could not select HIP transform\n");
    HIP_IFEL(!(param = hip_get_param(packet_ctx->input_msg, HIP_PARAM_ESP_TRANSFORM)),
             -EINVAL,
             "Could not find ESP transform\n");
    HIP_IFEL((esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
             -EINVAL, "Could not select proper ESP transform\n");

    hip_transf_length  = hip_transform_key_length(hip_tfm);
    hmac_transf_length = hip_hmac_key_length(esp_tfm);
    esp_transf_length  = hip_enc_key_length(esp_tfm);
    auth_transf_length = hip_auth_key_length_esp(esp_tfm);

    HIP_DEBUG("Transform lengths are:\n" \
              "\tHIP = %d, HMAC = %d, ESP = %d, auth = %d\n",
              hip_transf_length, hmac_transf_length, esp_transf_length,
              auth_transf_length);

    HIP_DEBUG("I and J values from the puzzle and its solution are:\n" \
              "\tI = 0x%llx\n\tJ = 0x%llx\n", I, J);

    /* Create only minumum amount of KEYMAT for now. From draft chapter
     * HIP KEYMAT we know how many bytes we need for all keys used in the
     * base exchange. */
    keymat_len_min = hip_transf_length + hmac_transf_length +
                     hip_transf_length + hmac_transf_length + esp_transf_length +
                     auth_transf_length + esp_transf_length + auth_transf_length;

    /* Assume ESP keys are after authentication keys */
    esp_default_keymat_index = hip_transf_length + hmac_transf_length +
                               hip_transf_length + hmac_transf_length;

    /* R1 contains no ESP_INFO */
    esp_info = hip_get_param(packet_ctx->input_msg, HIP_PARAM_ESP_INFO);

    if (esp_info) {
        esp_keymat_index = ntohs(esp_info->keymat_index);
    } else {
        esp_keymat_index = esp_default_keymat_index;
    }

    if (esp_keymat_index != esp_default_keymat_index) {
        /** @todo Add support for keying material. */
        HIP_ERROR("Varying keying material slices are not supported yet.\n");
        err = -1;
        goto out_err;
    }

    keymat_len = keymat_len_min;

    if (keymat_len % HIP_AH_SHA_LEN) {
        keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);
    }

    HIP_DEBUG("Keying material:\n\tminimum length = %u\n\t" \
              "keying material length = %u.\n", keymat_len_min, keymat_len);

    HIP_IFEL(!(keymat = HIP_MALLOC(keymat_len, 0)), -ENOMEM,
             "Error on allocating memory for keying material.\n");

    /* 1024 should be enough for shared secret. The length of the shared
     * secret actually depends on the DH Group. */
    /** @todo 1024 -> hip_get_dh_size ? */
    HIP_IFEL(!(dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_0)),
             -ENOMEM,
             "Error on allocating memory for Diffie-Hellman shared key.\n");

    memset(dh_shared_key, 0, dh_shared_len);

    HIP_IFEL(!(dhf = (struct hip_diffie_hellman *) hip_get_param(
                   packet_ctx->input_msg, HIP_PARAM_DIFFIE_HELLMAN)),
             -ENOENT,  "No Diffie-Hellman parameter found.\n");

    /* If the message has two DH keys, select (the stronger, usually) one. */
    *dhpv = hip_dh_select_key(dhf);

    _HIP_DEBUG("dhpv->group_id= %d\n", (*dhpv)->group_id);
    _HIP_DEBUG("dhpv->pub_len= %d\n", ntohs((*dhpv)->pub_len));

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_DH_CREATE\n");
    hip_perf_start_benchmark(perf_set, PERF_DH_CREATE);
#endif
    HIP_IFEL((dh_shared_len = hip_calculate_shared_secret(
                  (*dhpv)->public_value, (*dhpv)->group_id,
                  ntohs((*dhpv)->pub_len),
                  (unsigned char *) dh_shared_key,
                  dh_shared_len)) < 0,
             -EINVAL, "Calculation of shared secret failed.\n");

    _HIP_HEXDUMP("Diffie-Hellman shared parameter:\n", param,
                 hip_get_param_total_len(param));
    _HIP_HEXDUMP("Diffie-Hellman shared key:\n", dh_shared_key,
                 dh_shared_len);

    hip_make_keymat(dh_shared_key,
                    dh_shared_len,
                    &km,
                    keymat,
                    keymat_len,
                    &packet_ctx->input_msg->hits,
                    &packet_ctx->input_msg->hitr,
                    &packet_ctx->hadb_entry->keymat_calc_index,
                    I,
                    J);

    /* draw from km to keymat, copy keymat to dst, length of
     * keymat is len */

    we_are_HITg = hip_hit_is_bigger(&packet_ctx->input_msg->hitr,
                                    &packet_ctx->input_msg->hits);

    HIP_DEBUG("We are %s HIT.\n", we_are_HITg ? "greater" : "lesser");

    if (we_are_HITg) {
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_enc_out.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_hmac_out.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_enc_in.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_hmac_in.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->esp_out.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->auth_out.key, &km,
                                 auth_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->esp_in.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->auth_in.key, &km,
                                 auth_transf_length);
    } else {
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_enc_in.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_hmac_in.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_enc_out.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->hip_hmac_out.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->esp_in.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->auth_in.key, &km,
                                 auth_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->esp_out.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(packet_ctx->hadb_entry->auth_out.key, &km,
                                 auth_transf_length);
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_DH_CREATE\n");
    hip_perf_stop_benchmark(perf_set, PERF_DH_CREATE);
#endif
    HIP_HEXDUMP("HIP-gl encryption:", &packet_ctx->hadb_entry->hip_enc_out.key,
                hip_transf_length);
    HIP_HEXDUMP("HIP-gl integrity (HMAC) key:", &packet_ctx->hadb_entry->hip_hmac_out.key,
                hmac_transf_length);
    _HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n",
               hip_transf_length);
    HIP_HEXDUMP("HIP-lg encryption:", &packet_ctx->hadb_entry->hip_enc_in.key,
                hip_transf_length);
    HIP_HEXDUMP("HIP-lg integrity (HMAC) key:", &packet_ctx->hadb_entry->hip_hmac_in.key,
                hmac_transf_length);
    HIP_HEXDUMP("SA-gl ESP encryption key:", &packet_ctx->hadb_entry->esp_out.key,
                esp_transf_length);
    HIP_HEXDUMP("SA-gl ESP authentication key:", &packet_ctx->hadb_entry->auth_out.key,
                auth_transf_length);
    HIP_HEXDUMP("SA-lg ESP encryption key:", &packet_ctx->hadb_entry->esp_in.key,
                esp_transf_length);
    HIP_HEXDUMP("SA-lg ESP authentication key:", &packet_ctx->hadb_entry->auth_in.key,
                auth_transf_length);

    /* the next byte when creating new keymat */
    packet_ctx->hadb_entry->current_keymat_index = keymat_len_min;     /* offset value, so no +1 ? */
    packet_ctx->hadb_entry->keymat_calc_index    = (packet_ctx->hadb_entry->current_keymat_index / HIP_AH_SHA_LEN) + 1;
    packet_ctx->hadb_entry->esp_keymat_index     = esp_keymat_index;

    memcpy(packet_ctx->hadb_entry->current_keymat_K,
           keymat + (packet_ctx->hadb_entry->keymat_calc_index - 1) * HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

    _HIP_DEBUG("packet_ctx->hadb_entry: keymat_calc_index=%u current_keymat_index=%u\n",
               packet_ctx->hadb_entry->keymat_calc_index, packet_ctx->hadb_entry->current_keymat_index);
    _HIP_HEXDUMP("CTX CURRENT KEYMAT", packet_ctx->hadb_entry->current_keymat_K,
                 HIP_AH_SHA_LEN);

    /* store DH shared key */
    packet_ctx->hadb_entry->dh_shared_key     = dh_shared_key;
    packet_ctx->hadb_entry->dh_shared_key_len = dh_shared_len;

    /* on success HIP_FREE for dh_shared_key is called by caller */
out_err:
    if (err && dh_shared_key) {
        HIP_FREE(dh_shared_key);
    }
    if (keymat) {
        HIP_FREE(keymat);
    }
    if (plain_local_hit) {
        HIP_FREE(plain_local_hit);
    }
    return err;
}

/**
 * Drops a packet if necessary.
 *
 *
 * @param entry   host association entry
 * @param type    type of the packet
 * @param hitr    HIT of the destination
 *
 * @return        1 if the packet should be dropped, zero if the packet
 *                shouldn't be dropped
 */
static int hip_packet_to_drop(hip_ha_t *entry,
                              hip_hdr_type_t type,
                              struct in6_addr *hitr)
{
    // If we are a relay or rendezvous server, don't drop the packet
    if (!hip_hidb_hit_is_our(hitr)) {
        return 0;
    }

    switch (entry->state) {
    case HIP_STATE_I2_SENT:
        // Here we handle the "shotgun" case. We only accept the first valid R1
        // arrived and ignore all the rest.
        HIP_DEBUG("Number of items in the addresses list: %d\n",
                  ((struct lhash_st *) addresses)->num_items);
        if (entry->peer_addr_list_to_be_added) {
            HIP_DEBUG("Number of items in the peer addr list: %d ",
                      ((struct lhash_st *) entry->peer_addr_list_to_be_added)->num_items);
        }
        if (hip_shotgun_status == HIP_MSG_SHOTGUN_ON
            && type == HIP_R1
            && entry->peer_addr_list_to_be_added  &&
            (((struct lhash_st *) entry->peer_addr_list_to_be_added)->num_items > 1 ||
             ((struct lhash_st *) addresses)->num_items > 1)) {
            return 1;
        }
        break;
    case HIP_STATE_R2_SENT:
        if (type == HIP_R1 || type == HIP_R2) {
            return 1;
        }
    case HIP_STATE_ESTABLISHED:
        if (type == HIP_R1 || type == HIP_R2) {
            return 1;
        }
    }

    return 0;
}

/**
 * Decides what action to take for an incoming HIP control packet.
 *
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_control_packet(struct hip_packet_context *packet_ctx)
{
    int err = 0;
    struct in6_addr ipv6_any_addr = IN6ADDR_ANY_INIT;
    uint32_t type, state;

    /* Debug printing of received packet information. All received HIP
     * control packets are first passed to this function. Therefore
     * printing packet data here works for all packets. To avoid excessive
     * debug printing do not print this information inside the individual
     * receive or handle functions. */
    HIP_DEBUG_HIT("HIT Sender  ", &packet_ctx->input_msg->hits);
    HIP_DEBUG_HIT("HIT Receiver", &packet_ctx->input_msg->hitr);
    HIP_DEBUG("source port: %u, destination port: %u\n",
              packet_ctx->msg_ports->src_port,
              packet_ctx->msg_ports->dst_port);

    HIP_DUMP_MSG(packet_ctx->input_msg);

    if (hip_hidb_hit_is_our(&packet_ctx->input_msg->hits) &&
        (IN6_ARE_ADDR_EQUAL(&packet_ctx->input_msg->hitr,
                            &packet_ctx->input_msg->hits) ||
         IN6_ARE_ADDR_EQUAL(&packet_ctx->input_msg->hitr,
                            &ipv6_any_addr)) &&
        !hip_addr_is_loopback(packet_ctx->dst_addr) &&
        !hip_addr_is_loopback(packet_ctx->src_addr) &&
        !IN6_ARE_ADDR_EQUAL(packet_ctx->src_addr, packet_ctx->dst_addr)) {
        HIP_DEBUG("Invalid loopback packet. Dropping.\n");
        goto out_err;
    }

    HIP_IFEL(hip_check_network_msg(packet_ctx->input_msg),
             -1,
             "Checking control message failed.\n");

    type  = hip_get_msg_type(packet_ctx->input_msg);

    /** @todo Check packet csum.*/

    packet_ctx->hadb_entry = hip_hadb_find_byhits(&packet_ctx->input_msg->hits,
                                                  &packet_ctx->input_msg->hitr);

    // Check if we need to drop the packet
    if (packet_ctx->hadb_entry &&
        hip_packet_to_drop(packet_ctx->hadb_entry,
                           type,
                           &packet_ctx->input_msg->hitr) == 1) {
        HIP_DEBUG("Ignoring the packet sent.\n");
        err = -1;
        goto out_err;
    }

    if (packet_ctx->hadb_entry) {
        state = packet_ctx->hadb_entry->state;
    } else {
        state = HIP_STATE_NONE;
    }

#ifdef CONFIG_HIP_OPPORTUNISTIC
    if (!packet_ctx->hadb_entry && opportunistic_mode &&
        (type == HIP_I1 || type == HIP_R1)) {
        packet_ctx->hadb_entry =
                hip_oppdb_get_hadb_entry_i1_r1(packet_ctx->input_msg,
                                               packet_ctx->src_addr,
                                               packet_ctx->dst_addr,
                                               packet_ctx->msg_ports);
    }
#endif

#ifdef CONFIG_HIP_RVS
    /* check if it a relaying msg */
    if (hip_relay_handle_relay_to(type, state, packet_ctx)) {
        err = -ECANCELED;
        goto out_err;
    } else {
        HIP_DEBUG("handle relay to failed, continue the bex handler\n");
    }
#endif

    hip_run_handle_functions(type, state, packet_ctx);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_SIGN, PERF_DSA_SIGN_IMPL, PERF_RSA_SIGN_IMPL," \
              " PERF_VERIFY, PERF_DSA_VERIFY_IMPL, PERF_RSA_VERIFY_IMPL," \
              " PERF_DH_CREATE\n");
    hip_perf_write_benchmark(perf_set, PERF_SIGN);
    hip_perf_write_benchmark(perf_set, PERF_DSA_SIGN_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_RSA_SIGN_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_VERIFY);
    hip_perf_write_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_RSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_DH_CREATE);
#endif
    HIP_DEBUG("Done with control packet, err is %d.\n", err);

out_err:
    return err;
}

/**
 * Logic specific to HIP control packets received on UDP.
 *
 * Does the logic specific to HIP control packets received on UDP and calls
 * hip_receive_control_packet() after the UDP specific logic.
 * hip_receive_control_packet() is called with different IP source address
 * depending on whether the current machine is a rendezvous server or not:
 *
 * <ol>
 * <li>If the current machine is @b NOT a rendezvous server the source address
 * of hip_receive_control_packet() is the @c preferred_address of the matching
 * host association.</li>
 * <li>If the current machine @b IS a rendezvous server the source address
 * of hip_receive_control_packet() is the @c saddr of this function.</li>
 * </ol>
 *
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_udp_control_packet(struct hip_packet_context *packet_ctx)
{
    int err         = 0, type;
    hip_ha_t *entry = NULL;

    _HIP_DEBUG("hip_nat_receive_udp_control_packet() invoked.\n");

    type  = hip_get_msg_type(packet_ctx->input_msg);
    entry = hip_hadb_find_byhits(&packet_ctx->input_msg->hits,
                                 &packet_ctx->input_msg->hitr);

#ifndef CONFIG_HIP_RVS
    /* The ip of RVS is taken to be ip of the peer while using RVS server
     * to relay R1. Hence have removed this part for RVS --Abi */
    if (entry && (type == HIP_R1 || type == HIP_R2)) {
        /* When the responder equals to the NAT host, it can reply from
         * the private address instead of the public address. In this
         * case, the saddr will point to the private address, and using
         * it for I2 will fail the puzzle indexing (I1 was sent to the
         * public address). So, we make sure here that we're using the
         * same dst address for the I2 as for I1. Also, this address is
         * used for setting up the SAs: handle_r1 creates one-way SA and
         * handle_i2 the other way; let's make sure that they are the
         * same. */
        packet_ctx->src_addr = &entry->peer_addr;
    }
#endif
    HIP_IFEL(hip_receive_control_packet(packet_ctx), -1,
             "receiving of control packet failed\n");
out_err:
    return err;
}

//TODO doxygen header missing
int handle_locator(struct hip_locator *locator,
                   in6_addr_t         *r1_saddr,
                   in6_addr_t         *r1_daddr,
                   hip_ha_t           *entry,
                   hip_portpair_t     *r1_info)
{
    int n_addrs = 0, loc_size = 0, err = 0;

    // Lets save the LOCATOR to the entry 'till we
    //   get the esp_info in r2 then handle it
    n_addrs  = hip_get_locator_addr_item_count(locator);
    loc_size = sizeof(struct hip_locator) +
               (n_addrs * sizeof(struct hip_locator_info_addr_item));
    HIP_IFEL(!(entry->locator = malloc(loc_size)),
             -1, "Malloc for entry->locators failed\n");
    memcpy(entry->locator, locator, loc_size);

out_err:
    return err;
}

/**
 * Handles an incoming R1 packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return Success = 0,
 *         Error   = -1
 *
 * @todo           When rendezvous service is used, the I1 packet is relayed
 *                 to the responder via the rendezvous server. Responder then
 *                 replies directly to the initiator with an R1 packet that has
 *                 a @c VIA_RVS parameter. This parameter contains the IP
 *                 addresses of the traversed RVSes (usually just one). The
 *                 initiator should store these addresses to cope with the
 *                 double jump problem.
 */
int hip_handle_r1(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *packet_ctx)
{
    int mask = HIP_PACKET_CTRL_ANON, err = 0, retransmission = 0, written = 0, len;
    uint64_t solved_puzzle           = 0, I = 0;
    struct hip_puzzle *pz            = NULL;
    struct hip_diffie_hellman *dh_req       = NULL;
    struct hip_host_id *peer_host_id = NULL;
    struct hip_r1_counter *r1cntr    = NULL;
    struct hip_dh_public_value *dhpv = NULL;
    struct hip_locator *locator      = NULL;
    char *str                        = NULL;
    struct in6_addr daddr;
    uint16_t i2_mask = 0;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R1\n");
    hip_perf_start_benchmark(perf_set, PERF_R1);
#endif

    HIP_IFEL(!packet_ctx->hadb_entry, -1,
             "No entry in host association database when receiving R1." \
             "Dropping.\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
   hip_oppipdb_delentry(&(packet_ctx->hadb_entry->peer_addr));
#endif

   if (ipv6_addr_any(&(packet_ctx->input_msg)->hitr)) {
       HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
   }

   HIP_IFEL(!hip_controls_sane(ntohs(packet_ctx->input_msg->control), mask), 0,
            "Received illegal controls in R1: 0x%x Dropping\n",
            ntohs(packet_ctx->input_msg->control));

   /* An implicit and insecure REA. If sender's address is different than
    * the one that was mapped, then we will overwrite the mapping with the
    * newer address. This enables us to use the rendezvous server, while
    * not supporting the REA TLV. */
   hip_hadb_get_peer_addr(packet_ctx->hadb_entry, &daddr);
   if (ipv6_addr_cmp(&daddr, packet_ctx->src_addr) != 0) {
       HIP_DEBUG("Mapped address didn't match received address\n");
       HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
       HIP_HEXDUMP("Mapping", &daddr, 16);
       HIP_HEXDUMP("Received", packet_ctx->src_addr, 16);
       hip_hadb_delete_peer_addrlist_one_old(packet_ctx->hadb_entry, &daddr);
       hip_hadb_add_peer_addr(packet_ctx->hadb_entry,
                              packet_ctx->src_addr,
                              0,
                              0,
                              PEER_ADDR_STATE_ACTIVE,
                              packet_ctx->msg_ports->src_port);
   }

   HIP_DEBUG("Received R1 in state %s\n", hip_state_str(ha_state));

   if (ha_state == HIP_STATE_I2_SENT) {
       HIP_DEBUG("Retransmission\n");
       retransmission = 1;
    } else {
        HIP_DEBUG("Not a retransmission\n");
    }

    hip_relay_add_rvs_to_ha(packet_ctx->input_msg, packet_ctx->hadb_entry);

#ifdef CONFIG_HIP_RVS
    hip_relay_handle_relay_to_in_client(packet_type, ha_state, packet_ctx);
#endif /* CONFIG_HIP_RVS */

    /* According to the section 8.6 of the base draft, we must first check
     * signature. */

    /* Blinded R1 packets do not contain HOST ID parameters, so the
     * verification must be delayed to the R2 */
    /* Store the peer's public key to HA and validate it */
    /** @todo Do not store the key if the verification fails. */
    HIP_IFEL(!(peer_host_id = hip_get_param(packet_ctx->input_msg, HIP_PARAM_HOST_ID)),
             -ENOENT, "No HOST_ID found in R1\n");
    //copy hostname to hadb entry if local copy is empty
    if (strlen((char *) (packet_ctx->hadb_entry->peer_hostname)) == 0) {
        memcpy(packet_ctx->hadb_entry->peer_hostname,
               hip_get_param_host_id_hostname(peer_host_id),
               HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
    }
    HIP_IFE(hip_init_peer(packet_ctx->hadb_entry, packet_ctx->input_msg, peer_host_id), -EINVAL);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(packet_ctx->hadb_entry->verify(packet_ctx->hadb_entry->peer_pub_key,
                                            packet_ctx->input_msg),
             -EINVAL,
             "Verification of R1 signature failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
#endif

    /* R1 packet had destination port hip_get_nat_udp_port(), which means that
     * the peer is behind NAT. We set NAT mode "on" and set the send function to
     * "hip_send_udp". The client UDP port is not stored until the handling
     * of R2 packet. Don't know if the entry is already locked... */
    if (packet_ctx->msg_ports->dst_port != 0) {
        HIP_LOCK_HA(packet_ctx->hadb_entry);
        if (packet_ctx->hadb_entry->nat_mode == HIP_NAT_MODE_NONE) {
            packet_ctx->hadb_entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
        }
        /* @todo Is this alternative xmit function necessary? */
        /* hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set); */
        HIP_UNLOCK_HA(packet_ctx->hadb_entry);
    }

    /***** LOCATOR PARAMETER ******/
    locator = (struct hip_locator *) hip_get_param(packet_ctx->input_msg, HIP_PARAM_LOCATOR);
    if (locator) {
        err = handle_locator(locator,
                             packet_ctx->src_addr,
                             packet_ctx->dst_addr,
                             packet_ctx->hadb_entry,
                             packet_ctx->msg_ports);
    } else {
        HIP_DEBUG("R1 did not have locator\n");
    }

    /* R1 generation check */

    /* We have problems with creating precreated R1s in reasonable
     * fashion... so we don't mind about generations. */
    r1cntr = hip_get_param(packet_ctx->input_msg, HIP_PARAM_R1_COUNTER);

    /* Do control bit stuff here... */

    /* We must store the R1 generation counter, _IF_ it exists. */
    if (r1cntr) {
        HIP_LOCK_HA(packet_ctx->hadb_entry);
        HIP_DEBUG("Storing R1 generation counter %d\n", r1cntr->generation);
        packet_ctx->hadb_entry->birthday = ntoh64(r1cntr->generation);
        HIP_UNLOCK_HA(packet_ctx->hadb_entry);
    }

    /* Solve puzzle: if this is a retransmission, we have to preserve
     * the old solution. */
    if (!retransmission) {
        struct hip_puzzle *pz = NULL;

        HIP_IFEL(!(pz = hip_get_param(packet_ctx->input_msg, HIP_PARAM_PUZZLE)), -EINVAL,
                 "Malformed R1 packet. PUZZLE parameter missing\n");
        HIP_IFEL((solved_puzzle = hip_solve_puzzle(pz,
                                                   packet_ctx->input_msg,
                                                   HIP_SOLVE_PUZZLE)) == 0,
                                                   -EINVAL, "Solving of puzzle failed\n");
        I = pz->I;
        packet_ctx->hadb_entry->puzzle_solution = solved_puzzle;
        packet_ctx->hadb_entry->puzzle_i        = pz->I;
    } else {
        I             = packet_ctx->hadb_entry->puzzle_i;
        solved_puzzle = packet_ctx->hadb_entry->puzzle_solution;
    }

    /* Allocate space for a new I2 message. */
    HIP_IFEL(!(packet_ctx->output_msg = hip_msg_alloc()),
             -ENOMEM,
             "Allocation of I2 failed\n");

    HIP_DEBUG("Build normal I2.\n");
    /* create I2 */
    hip_build_network_hdr(packet_ctx->output_msg,
                          HIP_I2,
                          i2_mask,
                          &packet_ctx->input_msg->hitr,
                          &packet_ctx->input_msg->hits);

    /* note: we could skip keying material generation in the case
     * of a retransmission but then we'd had to fill ctx->hmac etc */
    HIP_IFEL(hip_produce_keying_material(packet_ctx,
                                         I,
                                         solved_puzzle,
                                         &dhpv),
             -EINVAL,
             "Could not produce keying material\n");

    /********** ESP_INFO **********/
    /* SPI is set below */
    HIP_IFEL(hip_build_param_esp_info(packet_ctx->output_msg,
                                      packet_ctx->hadb_entry->esp_keymat_index,
                                      0,
                                      0),
             -1,
             "building of ESP_INFO failed.\n");

    /********** SOLUTION **********/
    HIP_IFEL(!(pz = hip_get_param(packet_ctx->input_msg, HIP_PARAM_PUZZLE)),
             -ENOENT,
             "Internal error: PUZZLE parameter mysteriously gone\n");
    HIP_IFEL(hip_build_param_solution(packet_ctx->output_msg, pz, ntoh64(solved_puzzle)),
             -1,
             "Building of solution failed\n");

    /********** Diffie-Hellman *********/
    /* calculate shared secret and create keying material */
    packet_ctx->hadb_entry->dh_shared_key = NULL;

    HIP_IFEL(!(dh_req = hip_get_param(packet_ctx->input_msg, HIP_PARAM_DIFFIE_HELLMAN)),
             -ENOENT,
             "Internal error\n");
    HIP_IFEL((written = hip_insert_dh(dhpv->public_value,
                                      ntohs(dhpv->pub_len),
                                      dhpv->group_id)) < 0,
                -1,
                "Could not extract the DH public key\n");

    HIP_IFEL(hip_build_param_diffie_hellman_contents(packet_ctx->output_msg,
                                                     dhpv->group_id,
                                                     dhpv->public_value,
                                                     written,
                                                     HIP_MAX_DH_GROUP_ID,
                                                     NULL,
                                                     0),
             -1,
             "Building of DH failed.\n");

    /* Everything ok, save host id to HA */
    HIP_IFE(hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0, -1);
    HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
              str,
              len,
              hip_get_param_host_id_hostname(peer_host_id));

    /********* ESP protection preferred transforms [OPTIONAL] *********/
    HIP_IFEL(esp_prot_r1_handle_transforms(packet_ctx),
             -1,
             "failed to handle preferred esp protection transforms\n");

    /******************************************************************/

    out_err:
    if (packet_ctx->hadb_entry->dh_shared_key) {
        HIP_FREE(packet_ctx->hadb_entry->dh_shared_key);
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_R1\n");
    hip_perf_stop_benchmark(perf_set, PERF_R1);
    hip_perf_write_benchmark(perf_set, PERF_R1);
#endif
    return err;
}
/**
 * hip_handle_i2_in_i2_sent
 *
 * Checks wether the received I2 packet in state I2-SENT should be droppped, or
 * not. If the packet should be dropped, the drop_packet flag is set to 1.
 *
 * @note See RFC5201, 4.4.2., Table 4 for details.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx The packet context containing a pointer to the received message,
 *             a pointer to the outgoing message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database.
 *
 * @return Success = 0,
 *         Error   = -1
 *
 */
int hip_handle_i2_in_i2_sent(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_IFEL(ctx->drop_packet,
             -1,
             "Abort packet processing.\n");

    if (hip_hit_is_bigger(&ctx->hadb_entry->hit_peer,
                          &ctx->hadb_entry->hit_our)) {
        ctx->drop_packet = 1;
    }
out_err:
    return err;
}

/**
 * Handles an incoming I2 packet.
 *
 * This function is the actual point from where the processing of I2 is started
 * and corresponding R2 is created. This function also creates a new host
 * association in the host association database if no previous association
 * matching the search key (source HIT XOR destination HIT) was found.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return         zero on success, or negative error value on error. Success
 *                 indicates that I2 payloads are checked and R2 is created and
 *                 sent.
 * @see            Section 6.9. "Processing Incoming I2 Packets" of
 *                 <a href="http://www.rfc-editor.org/rfc/rfc5201.txt">
 *                 RFC 5201</a>.
 */
int hip_handle_i2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx)
{
    int err = 0, retransmission = 0, host_id_found = 0, is_loopback = 0;
    uint16_t mask = HIP_PACKET_CTRL_ANON;
    uint16_t crypto_len                     = 0;
    uint32_t spi_in                         = 0, spi_out = 0;
    char *tmp_enc                           = NULL, *enc = NULL;
    unsigned char *iv                       = NULL;
    struct hip_hip_transform *hip_transform = NULL;
    struct hip_host_id *host_id_in_enc      = NULL;
    struct hip_r1_counter *r1cntr           = NULL;
    struct hip_esp_info *esp_info           = NULL;
    struct hip_dh_public_value *dhpv        = NULL;
    struct hip_solution *solution           = NULL;
    hip_transform_suite_t esp_tfm, hip_tfm;
    struct hip_spi_in_item spi_in_data;
    struct hip_locator *locator             = NULL;
    int do_transform                        = 0;
    int if_index                            = 0;
    struct sockaddr_storage ss_addr;
    struct sockaddr *addr                   = NULL;

    HIP_IFEL(ctx->drop_packet,
             -1,
             "Abort packet processing.\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I2\n");
    hip_perf_start_benchmark(perf_set, PERF_I2);
#endif

    HIP_IFEL(ipv6_addr_any(&(ctx->input_msg)->hitr),
             0,
             "Received NULL receiver HIT in I2. Dropping\n");

    HIP_IFEL(!hip_controls_sane(ntohs(ctx->input_msg->control), mask),
             0,
             "Received illegal controls in I2: 0x%x. Dropping\n",
             ntohs(ctx->input_msg->control));

    HIP_DEBUG("Received I2 in state %s\n", hip_state_str(ha_state));
    HIP_INFO("Received I2 from:\n");
    HIP_INFO_HIT("Source HIT:", &(ctx->input_msg)->hits);
    HIP_INFO_IN6ADDR("Source IP: ", ctx->src_addr);

    /* Check that the Responder's HIT is one of ours. According to RFC5201,
     * this MUST be done. This check was added by Lauri on 01.08.2008.
     * Note that this condition is not satisfied at the HIP relay server */
    if (!hip_hidb_hit_is_our(&(ctx->input_msg)->hitr)) {
        err = -EPROTO;
        HIP_ERROR("Responder's HIT in the received I2 packet does not" \
                  " correspond to one of our own HITs. Dropping I2" \
                  " packet.\n");
        goto out_err;
    }

    /* Fetch the R1_COUNTER parameter. */
    r1cntr = hip_get_param(ctx->input_msg, HIP_PARAM_R1_COUNTER);

    /* Here we should check the 'system boot counter' using the R1_COUNTER
     * parameter. However, our precreated R1 packets do not support system
     * boot counter so we do not check it. */

    /* Check solution for cookie */
    solution = hip_get_param(ctx->input_msg, HIP_PARAM_SOLUTION);
    if (solution == NULL) {
        err = -ENODATA;
        HIP_ERROR("SOLUTION parameter missing from I2 packet. " \
                  "Dropping the I2 packet.\n");
        goto out_err;
    }

    HIP_DEBUG_HIT("i2_saddr", ctx->src_addr);
    HIP_DEBUG_HIT("i2_daddr", ctx->dst_addr);

    HIP_IFEL(hip_verify_cookie(ctx->src_addr, ctx->dst_addr, ctx->input_msg, solution),
             -EPROTO,
             "Cookie solution rejected. Dropping the I2 packet.\n");

    if (ctx->hadb_entry != NULL) {
        spi_in = ctx->hadb_entry->spi_inbound_current;
        HIP_DEBUG("inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

        if (ctx->hadb_entry->state == HIP_STATE_R2_SENT) {
            retransmission = 1;
        } else if (ctx->hadb_entry->state == HIP_STATE_ESTABLISHED) {
            retransmission = 1;
        }
    } else {
         HIP_DEBUG("No HIP association found. Creating a new one.\n");

         if ((ctx->hadb_entry = hip_hadb_create_state(0)) == NULL) {
             err = -ENOMEM;
             HIP_ERROR("Out of memory when allocating memory for a new " \
                       "HIP association. Dropping the I2 packet.\n");
             goto out_err;
         }
     }

    /* Check HIP and ESP transforms, and produce keying material. */

    /* Note: we could skip keying material generation in the case of a
     * retransmission but then we'd had to fill i2_context.hmac etc.
     * TH: I'm not sure if this could be replaced with a function pointer
     * which is set from haDB. Usually you shouldn't have state here,
     * right? */

    HIP_IFEL(hip_produce_keying_material(ctx,
                                         solution->I,
                                         solution->J,
                                         &dhpv),
             -EPROTO,
             "Unable to produce keying material. Dropping the I2 packet.\n");

    /* Verify HMAC. */
    if (hip_hidb_hit_is_our(&(ctx->input_msg)->hits) &&
        hip_hidb_hit_is_our(&(ctx->input_msg)->hitr)) {

        is_loopback = 1;
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                        &ctx->hadb_entry->hip_hmac_out),
                 -EPROTO,
                 "HMAC loopback validation on I2 failed. " \
                 "Dropping the I2 packet.\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                        &ctx->hadb_entry->hip_hmac_in),
                 -EPROTO,
                 "HMAC validation on I2 failed. Dropping the" \
                 " I2 packet.\n");
    }

    hip_transform = hip_get_param(ctx->input_msg, HIP_PARAM_HIP_TRANSFORM);
    if (hip_transform == NULL) {
        err = -ENODATA;
        HIP_ERROR("HIP_TRANSFORM parameter missing from I2 packet. " \
                  "Dropping the I2 packet.\n");
        goto out_err;
    } else if ((hip_tfm =
                    hip_get_param_transform_suite_id(hip_transform, 0)) == 0) {
        err = -EPROTO;
        HIP_ERROR("Bad HIP transform. Dropping the I2 packet.\n");
        goto out_err;
    } else {
        do_transform = 1;
    }


    /* Decrypt the HOST_ID and verify it against the sender HIT. */
    /* @todo: the HOST_ID can be in the packet in plain text */
    enc = hip_get_param(ctx->input_msg, HIP_PARAM_ENCRYPTED);
    if (enc == NULL) {
        HIP_DEBUG("ENCRYPTED parameter missing from I2 packet\n");
        host_id_in_enc = hip_get_param(ctx->input_msg, HIP_PARAM_HOST_ID);
        HIP_IFEL(!host_id_in_enc, -1, "No host id in i2");
        host_id_found  = 1;
    } else {
        /* Little workaround...
         * We have a function that calculates SHA1 digest and then verifies the
         * signature. But since the SHA1 digest in I2 must be calculated over
         * the encrypted data, and the signature requires that the encrypted
         * data to be decrypted (it contains peer's host identity), we are
         * forced to do some temporary copying. If ultimate speed is required,
         * then calculate the digest here as usual and feed it to signature
         * verifier. */
        if ((tmp_enc = (char *) malloc(hip_get_param_total_len(enc))) == NULL) {
            err = -ENOMEM;
            HIP_ERROR("Out of memory when allocating memory for temporary " \
                      "ENCRYPTED parameter. Dropping the I2 packet.\n");
            goto out_err;
        }
        memcpy(tmp_enc, enc, hip_get_param_total_len(enc));


        if (do_transform) {
            /* Get pointers to:
             * 1) the encrypted HOST ID parameter inside the "Encrypted
             * data" field of the ENCRYPTED parameter.
             * 2) Initialization vector from the ENCRYPTED parameter.
             *
             * Get the length of the "Encrypted data" field in the ENCRYPTED
             * parameter. */

            switch (hip_tfm) {
            case HIP_HIP_RESERVED:
                HIP_ERROR("Found HIP suite ID 'RESERVED'. Dropping " \
                          "the I2 packet.\n");
                err            = -EOPNOTSUPP;
                goto out_err;
            case HIP_HIP_AES_SHA1:
                host_id_in_enc = (struct hip_host_id *)
                                 (tmp_enc +
                                  sizeof(struct hip_encrypted_aes_sha1));
                iv             = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
                /* 4 = reserved, 16 = IV */
                crypto_len     = hip_get_param_contents_len(enc) - 4 - 16;
                HIP_DEBUG("Found HIP suite ID " \
                          "'AES-CBC with HMAC-SHA1'.\n");
                break;
            case HIP_HIP_3DES_SHA1:
                host_id_in_enc = (struct hip_host_id *)
                                 (tmp_enc +
                                  sizeof(struct hip_encrypted_3des_sha1));
                iv             = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
                /* 4 = reserved, 8 = IV */
                crypto_len     = hip_get_param_contents_len(enc) - 4 - 8;
                HIP_DEBUG("Found HIP suite ID " \
                          "'3DES-CBC with HMAC-SHA1'.\n");
                break;
            case HIP_HIP_3DES_MD5:
                HIP_ERROR("Found HIP suite ID '3DES-CBC with " \
                          "HMAC-MD5'. Support for this suite ID is " \
                          "not implemented. Dropping the I2 packet.\n");
                err = -ENOSYS;
                goto out_err;
            case HIP_HIP_BLOWFISH_SHA1:
                HIP_ERROR("Found HIP suite ID 'BLOWFISH-CBC with " \
                          "HMAC-SHA1'. Support for this suite ID is " \
                          "not implemented. Dropping the I2 packet.\n");
                err            = -ENOSYS;
                goto out_err;
            case HIP_HIP_NULL_SHA1:
                host_id_in_enc = (struct hip_host_id *)
                                 (tmp_enc +
                                  sizeof(struct hip_encrypted_null_sha1));
                iv             = NULL;
                /* 4 = reserved */
                crypto_len     = hip_get_param_contents_len(enc) - 4;
                HIP_DEBUG("Found HIP suite ID " \
                          "'NULL-ENCRYPT with HMAC-SHA1'.\n");
                break;
            case HIP_HIP_NULL_MD5:
                HIP_ERROR("Found HIP suite ID 'NULL-ENCRYPT with " \
                          "HMAC-MD5'. Support for this suite ID is " \
                          "not implemented. Dropping the I2 packet.\n");
                err = -ENOSYS;
                goto out_err;
            default:
                HIP_ERROR("Found unknown HIP suite ID '%d'. Dropping " \
                          "the I2 packet.\n", hip_tfm);
                err = -EOPNOTSUPP;
                goto out_err;
            }
        }

        /* This far we have successfully produced the keying material (key),
         * identified which HIP transform is use (hip_tfm), retrieved pointers
         * both to the encrypted HOST_ID (host_id_in_enc) and initialization
         * vector (iv) and we know the length of the encrypted HOST_ID
         * parameter (crypto_len). We are ready to decrypt the actual host
         * identity. If the decryption succeeds, we have the decrypted HOST_ID
         * parameter in the 'host_id_in_enc' buffer.
         *
         * Note, that the original packet has the data still encrypted. */
        if (!host_id_found) {
            HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv, hip_tfm, crypto_len,
                                          (is_loopback ?
                                              &ctx->hadb_entry->hip_enc_out.key :
                                              &ctx->hadb_entry->hip_enc_in.key),
                                          HIP_DIRECTION_DECRYPT),
#ifdef CONFIG_HIP_OPENWRT
                     // workaround for non-included errno-base.h in openwrt
                     -EINVAL,
#else
                     -EKEYREJECTED,
#endif
                     "Failed to decrypt the HOST_ID parameter. Dropping the I2 " \
                     "packet.\n");
        }

        /* If the decrypted data is not a HOST_ID parameter, the I2 packet is
         * silently dropped. */
        if (hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID) {
            err = -EPROTO;
            HIP_ERROR("The decrypted data is not a HOST_ID parameter. " \
                      "Dropping the I2 packet.\n");
            goto out_err;
        }
    }
    HIP_HEXDUMP("Initiator host id", host_id_in_enc,
                hip_get_param_total_len(host_id_in_enc));

    if (spi_in == 0) {
        spi_in = ctx->hadb_entry->spi_inbound_current;
        HIP_DEBUG("inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
    }

    /* Next, we initialize the new HIP association. Peer HIT is the
     * source HIT of the received I2 packet. We can have many Host
     * Identities and using any of those Host Identities we can
     * calculate diverse HITs depending on the used algorithm. When
     * we sent one of our pre-created R1 packets, we have used one
     * of our Host Identities and thus of our HITs as source. We
     * must dig out the original Host Identity using the destination
     * HIT of the I2 packet as a key. The initialized HIP
     * association will not, however, have the I2 destination HIT as
     * source, but one that is calculated using the Host Identity
     * that we have dug out. */
    ipv6_addr_copy(&(ctx->hadb_entry)->hit_peer, &(ctx->input_msg)->hits);
    HIP_DEBUG("Initializing the HIP association.\n");
    hip_init_us(ctx->hadb_entry, &ctx->input_msg->hitr);
    HIP_DEBUG("Inserting the new HIP association in the HIP "       \
              "association database.\n");
    /* Should we handle the case where the insertion fails? */
    hip_hadb_insert_state(ctx->hadb_entry);

    ipv6_addr_copy(&(ctx->hadb_entry)->our_addr, ctx->dst_addr);

    /* Get the interface index of the network device which has our
     * local IP address. */
    if ((if_index =
             hip_devaddr2ifindex(&(ctx->hadb_entry)->our_addr)) < 0) {
        err = -ENXIO;
        HIP_ERROR("Interface index for local IPv6 address "     \
                  "could not be determined. Dropping the I2 "   \
                  "packet.\n");
        goto out_err;
    }

    /* We need our local IP address as a sockaddr because
     * hip_add_address_to_list() eats only sockaddr structures. */
    memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
    addr            = (struct sockaddr *) &ss_addr;
    addr->sa_family = AF_INET6;

    memcpy(hip_cast_sa_addr(addr), &(ctx->hadb_entry)->our_addr,
           hip_sa_addr_len(addr));
    hip_add_address_to_list(addr, if_index, 0);

    //hip_hadb_insert_state(ctx->hadb_entry);

    /* If there was already state, these may be uninitialized */
    ctx->hadb_entry->hip_transform = hip_tfm;
    if (!ctx->hadb_entry->our_pub) {
        hip_init_us(ctx->hadb_entry, &ctx->input_msg->hitr);
    }
    /* If the incoming I2 packet has hip_get_nat_udp_port() as destination port, NAT
     * mode is set on for the host association, I2 source port is
     * stored as the peer UDP port and send function is set to
     * "hip_send_pkt()". Note that we must store the port not until
     * here, since the source port can be different for I1 and I2. */
    if (ctx->msg_ports->dst_port != 0) {
        if (ctx->hadb_entry->nat_mode == 0) {
            ctx->hadb_entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
        }
        ctx->hadb_entry->local_udp_port = ctx->msg_ports->dst_port;
        ctx->hadb_entry->peer_udp_port  = ctx->msg_ports->src_port;
        HIP_DEBUG("Setting send func to UDP for entry %p from I2 info.\n",
                  ctx->hadb_entry);
        /* @todo Is this function set needed ? */
        //hip_hadb_set_xmit_function_set(ctx->hadb_entry, &nat_xmit_func_set);
    }

    ctx->hadb_entry->hip_transform = hip_tfm;

    /** @todo the above should not be done if signature fails...
     *  or it should be cancelled. */

    /* Store peer's public key and HIT to HA */
    HIP_IFE(hip_init_peer(ctx->hadb_entry, ctx->input_msg, host_id_in_enc), -EINVAL);

    /* Validate signature */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY(2)\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key,
                                     ctx->input_msg),
             -EINVAL,
             "Verification of I2 signature failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY(2)\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
#endif

    /* If we have old SAs with these HITs delete them */
    hip_delete_security_associations_and_sp(ctx->hadb_entry);
    {
        // 3.11.2009: 99999 Move this to a function and remove unused parts
        struct hip_esp_transform *esp_tf = NULL;
        struct hip_spi_out_item spi_out_data;

        HIP_IFEL(!(esp_tf = hip_get_param(ctx->input_msg,
                                          HIP_PARAM_ESP_TRANSFORM)),
                 -ENOENT, "Did not find ESP transform on i2\n");
        HIP_IFEL(!(esp_info = hip_get_param(ctx->input_msg,
                                            HIP_PARAM_ESP_INFO)),
                 -ENOENT, "Did not find SPI LSI on i2\n");

        if (r1cntr) {
            ctx->hadb_entry->birthday = r1cntr->generation;
        }
        ctx->hadb_entry->peer_controls |= ntohs(ctx->input_msg->control);

        /* move this below setup_sa */
        memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
        spi_out_data.spi            = ntohl(esp_info->new_spi);
        ctx->hadb_entry->spi_outbound_current = spi_out_data.spi;
        /* 99999
         * HIP_DEBUG("Adding spi 0x%x\n", spi_out_data.spi);
         * HIP_IFE(hip_hadb_add_spi_old(ctx->hadb_entry, HIP_SPI_DIRECTION_OUT,
         *                       &spi_out_data), -1);*/
        ctx->hadb_entry->esp_transform        = hip_select_esp_transform(esp_tf);
        HIP_IFEL((esp_tfm = ctx->hadb_entry->esp_transform) == 0, -1,
                 "Could not select proper ESP transform\n");
    }

    HIP_IFEL(hip_hadb_add_peer_addr(ctx->hadb_entry, ctx->src_addr,
                                    0,
                                    0,
                                    PEER_ADDR_STATE_ACTIVE,
                                    ctx->msg_ports->src_port),
             -1,
             "Error while adding the preferred peer address\n");

    HIP_DEBUG("retransmission: %s\n", (retransmission ? "yes" : "no"));
    HIP_DEBUG("src %d, dst %d\n",
              ctx->msg_ports->src_port,
              ctx->msg_ports->dst_port);

    /********** ESP-PROT anchor [OPTIONAL] **********/
    /** @todo Modularize esp_prot_* */
    HIP_IFEL(esp_prot_i2_handle_anchor(ctx), -1,
             "failed to handle esp prot anchor\n");

    /************************************************/

    /* Set up IPsec associations */
    err = hip_add_sa(ctx->src_addr,
                     ctx->dst_addr,
                     &ctx->input_msg->hits,
                     &ctx->input_msg->hitr,
                     spi_in,
                     esp_tfm,
                     &ctx->hadb_entry->esp_in,
                     &ctx->hadb_entry->auth_in,
                     retransmission,
                     HIP_SPI_DIRECTION_IN,
                     0,
                     ctx->hadb_entry);

    /* Remove the IPsec associations if there was an error when creating
     * them.
     */
    if (err) {
        err = -1;
        HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
        hip_delete_security_associations_and_sp(ctx->hadb_entry);
        goto out_err;
    }

    spi_out = ntohl(esp_info->new_spi);
    HIP_DEBUG("Setting up outbound IPsec SA, SPI=0x%x\n", spi_out);

    HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input_msg->hits,
                                   &ctx->input_msg->hitr,
                                   ctx->src_addr,
                                   ctx->dst_addr,
                                   IPPROTO_ESP,
                                   1,
                                   1),
             -1,
             "Failed to set up an SP pair.\n");

    memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
    spi_in_data.spi     = spi_in;
    spi_in_data.ifindex = hip_devaddr2ifindex(ctx->dst_addr);

    if (spi_in_data.ifindex) {
        HIP_DEBUG("spi_in_data.ifindex = %d.\n", spi_in_data.ifindex);
    } else {
        HIP_ERROR("Could not get device ifindex of address.\n");
    }

    /* 99999
     * err = hip_hadb_add_spi_old(ctx->hadb_entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
     * if (err) {
     *      HIP_UNLOCK_HA(ctx->hadb_entry);
     *      HIP_ERROR("Adding of SPI failed. Not creating an R2 packet.\n");
     *      goto out_err;
     * }
     * */

    ctx->hadb_entry->spi_outbound_new = spi_out;

#ifdef CONFIG_HIP_RVS
    {
        in6_addr_t dest;
        in_port_t dest_port = 0;

        ipv6_addr_copy(&dest, &in6addr_any);
        if (hip_relay_get_status() == HIP_RELAY_OFF) {
            ctx->hadb_entry->state = hip_relay_handle_relay_from(ctx->input_msg,
                                                                 ctx->src_addr,
                                                                 &dest,
                                                                 &dest_port);
            if (ctx->hadb_entry->state == -1) {
                HIP_DEBUG( "Handling RELAY_FROM of  I2 packet failed.\n");
                goto out_err;
            }
        }
    }
#endif

    /** @todo Should wait for ESP here or wait for implementation specific
     *  time. */
    /* As for the above todo item:
     *
     * Where is it said that we should wait for ESP or implementation
     * specific time here? This far we have successfully verified and
     * processed the I2 message (except the LOCATOR parameter) and sent an
     * R2 as an response. We are here at state UNASSOCIATED. From Section
     * 4.4.2. of RFC 5201 we learn that if I2 processing was successful, we
     * should "send R2 and go to R2-SENT" or if I2 processing failed, we
     * should "stay at UNASSOCIATED". -Lauri 29.04.2008 */
    ctx->hadb_entry->state = HIP_STATE_ESTABLISHED;

    /***** LOCATOR PARAMETER ******/
    /* Why do we process the LOCATOR parameter only after R2 has been sent?
     * -Lauri 29.04.2008.
     * We do not have valid spi_out to put the addresses into and NAT benefits
     * from the later handling ...
     * --samu
     */

    /***** LOCATOR PARAMETER *****/
    locator = (struct hip_locator *) hip_get_param(ctx->input_msg, HIP_PARAM_LOCATOR);
    if (locator) {
        HIP_DEBUG("Locator parameter support in BEX is not implemented!\n");
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_BASE\n");
    hip_perf_stop_benchmark(perf_set, PERF_BASE);
    hip_perf_write_benchmark(perf_set, PERF_BASE);
#endif

    HIP_INFO("Reached %s state\n", hip_state_str(ctx->hadb_entry->state));
    if (ctx->hadb_entry->hip_msg_retrans.buf) {
        ctx->hadb_entry->hip_msg_retrans.count = 0;
        memset(ctx->hadb_entry->hip_msg_retrans.buf, 0, HIP_MAX_NETWORK_PACKET);
    }
out_err:
    if (tmp_enc != NULL) {
        free(tmp_enc);
    }
    if (ctx->hadb_entry->dh_shared_key != NULL) {
        free(ctx->hadb_entry->dh_shared_key);
    }
    if (err) {
        ctx->drop_packet = 1;
    }
    return err;
}

/**
 * hip_handle_r2 - handle incoming R2 packet
 *
 * This function is the actual point from where the processing of R2
 * is started. On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return Success = 0,
 *         Error   = -1
 */
int hip_handle_r2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *packet_ctx)
{
    int err                         = 0, tfm = 0, retransmission = 0, idx = 0;
    uint16_t mask                   = 0;
    uint32_t spi_recvd              = 0, spi_in = 0;
    struct hip_esp_info *esp_info   = NULL;
    struct hip_locator *locator     = NULL;
    struct hip_spi_out_item spi_out_data;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R2\n");
    hip_perf_start_benchmark(perf_set, PERF_R2);
#endif

    HIP_IFEL(ipv6_addr_any(&(packet_ctx->input_msg)->hitr), -1,
             "Received NULL receiver HIT in R2. Dropping\n");

    HIP_IFEL(!hip_controls_sane(ntohs(packet_ctx->input_msg->control), mask),
             -1,
             "Received illegal controls in R2: 0x%x. Dropping\n",
             ntohs(packet_ctx->input_msg->control));

    HIP_IFEL(!packet_ctx->hadb_entry, -1,
             "No entry in host association database when receiving R2." \
             "Dropping.\n");

    /* if the NAT mode is used, update the port numbers of the host association */
    if (packet_ctx->msg_ports->dst_port == hip_get_local_nat_udp_port()) {
        packet_ctx->hadb_entry->local_udp_port = packet_ctx->msg_ports->dst_port;
        packet_ctx->hadb_entry->peer_udp_port  = packet_ctx->msg_ports->src_port;
    }

    HIP_DEBUG("Received R2 in state %s\n", hip_state_str(ha_state));

    if (ha_state == HIP_STATE_ESTABLISHED) {
        retransmission = 1;
        HIP_DEBUG("Retransmission\n");
    } else {
        HIP_DEBUG("Not a retransmission\n");
    }

    /* Verify HMAC */
    if (packet_ctx->hadb_entry->is_loopback) {
        HIP_IFEL(hip_verify_packet_hmac2(packet_ctx->input_msg,
                                         &packet_ctx->hadb_entry->hip_hmac_out,
                                         packet_ctx->hadb_entry->peer_pub),
                 -1,
                 "HMAC validation on R2 failed.\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac2(packet_ctx->input_msg,
                                         &packet_ctx->hadb_entry->hip_hmac_in,
                                         packet_ctx->hadb_entry->peer_pub),
                 -1,
                 "HMAC validation on R2 failed.\n");
    }

    /* Signature validation */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY(3)\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(packet_ctx->hadb_entry->verify(packet_ctx->hadb_entry->peer_pub_key,
                                            packet_ctx->input_msg),
             -EINVAL,
             "R2 signature verification failed.\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY(3)\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
#endif

    /* The rest */
    HIP_IFEL(!(esp_info = hip_get_param(packet_ctx->input_msg, HIP_PARAM_ESP_INFO)),
             -EINVAL,
             "Parameter SPI not found.\n");

    spi_recvd = ntohl(esp_info->new_spi);
    memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
    spi_out_data.spi = spi_recvd;

    packet_ctx->hadb_entry->spi_outbound_current = spi_recvd;
    HIP_DEBUG("Set SPI out = 0x%x\n", spi_recvd);

    /* Copy SPI out value here or otherwise ICE code has zero SPI */
    packet_ctx->hadb_entry->spi_outbound_new = spi_recvd;
    HIP_DEBUG("Set default SPI out = 0x%x\n", spi_recvd);

    HIP_DEBUG("entry should have only one spi_in now, test\n");

    spi_in = packet_ctx->hadb_entry->spi_inbound_current;
    HIP_DEBUG("spi_in: 0x%x\n", spi_in);

    tfm    = packet_ctx->hadb_entry->esp_transform;
    HIP_DEBUG("esp_transform: %i\n", tfm);

    HIP_DEBUG("R2 packet source port: %d, destination port %d.\n",
              packet_ctx->msg_ports->src_port, packet_ctx->msg_ports->dst_port);

    /********** ESP-PROT anchor [OPTIONAL] **********/
    HIP_IFEL(esp_prot_r2_handle_anchor(packet_ctx->hadb_entry,
                                       packet_ctx->input_msg),
             -1,
             "failed to handle esp prot anchor\n");

    /***** LOCATOR PARAMETER *****/
    locator = (struct hip_locator *) hip_get_param(packet_ctx->input_msg, HIP_PARAM_LOCATOR);
    if (locator) {
        HIP_DEBUG("Locator parameter support in BEX is not implemented!\n");
    }
    //end add

    // moved from hip_send_i2
    HIP_DEBUG_HIT("hit our", &(packet_ctx->hadb_entry)->hit_our);
    HIP_DEBUG_HIT("hit peer", &(packet_ctx->hadb_entry)->hit_peer);
    HIP_IFEL(hip_add_sa(packet_ctx->src_addr,
                        packet_ctx->dst_addr,
                        &packet_ctx->input_msg->hits,
                        &packet_ctx->input_msg->hitr,
                        spi_in,
                        tfm,
                        &(packet_ctx->hadb_entry)->esp_in,
                        &(packet_ctx->hadb_entry)->auth_in,
                        0,
                        HIP_SPI_DIRECTION_IN,
                        0,
                        packet_ctx->hadb_entry),
            -1,
            "Failed to setup IPsec SPD/SA entries, peer:src\n");

    HIP_IFEL(hip_add_sa(packet_ctx->dst_addr,
                        packet_ctx->src_addr,
                        &packet_ctx->input_msg->hitr,
                        &packet_ctx->input_msg->hits,
                        spi_recvd,
                        tfm,
                        &packet_ctx->hadb_entry->esp_out,
                        &packet_ctx->hadb_entry->auth_out,
                        0,
                        HIP_SPI_DIRECTION_OUT,
                        0,
                        packet_ctx->hadb_entry),
             -1,
             "Failed to setup IPsec SPD/SA entries, peer:dst\n");

    /** @todo Check for -EAGAIN */
    HIP_DEBUG("Set up outbound IPsec SA, SPI = 0x%x (host).\n", spi_recvd);

    /* Source IPv6 address is implicitly the preferred address after the
     * base exchange. */

    idx = hip_devaddr2ifindex(packet_ctx->dst_addr);

    if (idx != 0) {
        HIP_DEBUG("ifindex = %d\n", idx);
        // hip_hadb_set_spi_ifindex_deprecated(packet_ctx->hadb_entry, spi_in, idx);
    } else {
        HIP_ERROR("Couldn't get device ifindex of address\n");
    }

#ifdef CONFIG_HIP_RVS
        hip_relay_handle_relay_to_in_client(packet_type, ha_state, packet_ctx);
#endif /* CONFIG_HIP_RVS */

    /* Copying address list from temp location in entry
     * "entry->peer_addr_list_to_be_added" */
    hip_copy_peer_addrlist_changed(packet_ctx->hadb_entry);

    /* Handle REG_RESPONSE and REG_FAILED parameters. */
    hip_handle_param_reg_response(packet_ctx->hadb_entry, packet_ctx->input_msg);
    hip_handle_param_reg_failed(packet_ctx->hadb_entry, packet_ctx->input_msg);

    hip_handle_reg_from(packet_ctx->hadb_entry, packet_ctx->input_msg);

    /* These will change SAs' state from ACQUIRE to VALID, and wake up any
     * transport sockets waiting for a SA. */
    // hip_finalize_sa(&entry->hit_peer, spi_recvd);
    // hip_finalize_sa(&entry->hit_our, spi_in);

    packet_ctx->hadb_entry->state = HIP_STATE_ESTABLISHED;
    hip_hadb_insert_state(packet_ctx->hadb_entry);

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
    hip_oppipdb_delentry(&(packet_ctx->hadb_entry->peer_addr));
#endif
    HIP_INFO("Reached ESTABLISHED state\n");
    HIP_INFO("Handshake completed\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_BASE\n");
    hip_perf_stop_benchmark(perf_set, PERF_BASE);
    hip_perf_write_benchmark(perf_set, PERF_BASE);
#endif
    if (packet_ctx->hadb_entry->hip_msg_retrans.buf) {
        packet_ctx->hadb_entry->hip_msg_retrans.count = 0;
        memset(packet_ctx->hadb_entry->hip_msg_retrans.buf,
               0,
               HIP_MAX_NETWORK_PACKET);
    }

out_err:
    if (packet_ctx->hadb_entry->state == HIP_STATE_ESTABLISHED) {
        HIP_DEBUG("Send response to firewall.\n");
        hip_firewall_set_bex_data(HIP_MSG_FW_BEX_DONE,
                                  packet_ctx->hadb_entry,
                                  &(packet_ctx->hadb_entry)->hit_our,
                                  &(packet_ctx->hadb_entry)->hit_peer);
    } else {
        hip_firewall_set_bex_data(HIP_MSG_FW_BEX_DONE,
                                  packet_ctx->hadb_entry,
                                  NULL,
                                  NULL);
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_R2\n");
    hip_perf_stop_benchmark(perf_set, PERF_R2);
    hip_perf_write_benchmark(perf_set, PERF_R2);
#endif
    return err;
}

/**
 * Handles an incoming I1 packet.
 *
 * Handles an incoming I1 packet and parses @c FROM or @c RELAY_FROM parameter
 * from the packet. If a @c FROM or a @c RELAY_FROM parameter is found, there must
 * also be a @c RVS_HMAC parameter present. This hmac is first verified. If the
 * verification fails, a negative error value is returned and hip_send_r1() is
 * not invoked. If verification succeeds,
 * <ol>
 * <li>and a @c FROM parameter is found, the IP address obtained from the
 * parameter is passed to hip_send_r1() as the destination IP address. The
 * source IP address of the received I1 packet is passed to hip_send_r1() as
 * the IP of RVS.</li>
 * <li>and a @c RELAY_FROM parameter is found, the IP address and
 * port number obtained from the parameter is passed to hip_send_r1() as the
 * destination IP address and destination port. The source IP address and source
 * port of the received I1 packet is passed to hip_send_r1() as the IP and port
 * of RVS.</li>
 * <li>If no @c FROM or @c RELAY_FROM parameters are found, this function does
 * nothing else but calls hip_send_r1().</li>
 * </ol>
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return         zero on success, or negative error value on error.
 * @warning        This code only handles a single @c FROM or @c RELAY_FROM
 *                 parameter. If there is a mix of @c FROM and @c RELAY_FROM
 *                 parameters, only the first @c FROM parameter is parsed. Also,
 *                 if there are multiple @c FROM or @c RELAY_FROM parameters
 *                 present in the incoming I1 packet, only the first of a kind
 *                 is parsed.
 */
int hip_handle_i1(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *packet_ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_BASE\n");
    hip_perf_start_benchmark(perf_set, PERF_BASE);
    HIP_DEBUG("Start PERF_I1\n");
    hip_perf_start_benchmark(perf_set, PERF_I1);
#endif
    int err = 0, mask = 0, src_hit_is_our;

    HIP_ASSERT(!ipv6_addr_any(&(packet_ctx->input_msg)->hitr));

    /* In some environments, a copy of broadcast our own I1 packets
     * arrive at the local host too. The following variable handles
     * that special case. Since we are using source HIT (and not
     * destination) it should handle also opportunistic I1 broadcast */
    src_hit_is_our = hip_hidb_hit_is_our(&(packet_ctx->input_msg)->hits);

    /* check i1 for broadcast/multicast addresses */
    if (IN6_IS_ADDR_V4MAPPED(packet_ctx->dst_addr)) {
        struct in_addr addr4;

        IPV6_TO_IPV4_MAP(packet_ctx->dst_addr, &addr4);

        if (addr4.s_addr == INADDR_BROADCAST) {
            HIP_DEBUG("Received I1 broadcast\n");
            HIP_IFF(src_hit_is_our,
                    -1,
                    packet_ctx->drop_packet = 1,
                    "Received a copy of own broadcast, dropping\n");

            HIP_IFF(hip_select_source_address(packet_ctx->dst_addr, packet_ctx->src_addr),
                    -1,
                    packet_ctx->drop_packet = 1,
                    "Could not find source address\n");
        }
    } else if (IN6_IS_ADDR_MULTICAST(packet_ctx->dst_addr)) {
        HIP_IFF(src_hit_is_our,
                -1,
                packet_ctx->drop_packet = 1,
                "Received a copy of own broadcast, dropping\n");
        HIP_IFF(hip_select_source_address(packet_ctx->dst_addr, packet_ctx->src_addr),
                -1,
                packet_ctx->drop_packet = 1,
                "Could not find source address\n");
    }

    HIP_IFF(!hip_controls_sane(ntohs(packet_ctx->input_msg->control), mask),
            -1,
            packet_ctx->drop_packet = 1,
            "Received illegal controls in I1: 0x%x. Dropping\n",
            ntohs(packet_ctx->input_msg->control));

    HIP_INFO_HIT("I1 Source HIT:", &(packet_ctx->input_msg)->hits);
    HIP_INFO_IN6ADDR("I1 Source IP :", packet_ctx->src_addr);

out_err:
    return err;
}

/**
 * Handles an incoming NOTIFY packet.
 *
 * Handles an incoming NOTIFY packet and parses @c NOTIFICATION parameters and
 * @c VIA_RVS parameter from the packet.
 *
 * @note draft-ietf-hip-base-06, Section 6.13: Processing NOTIFY packets is
 * OPTIONAL. If processed, any errors in a received NOTIFICATION parameter
 * SHOULD be logged.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *packet_ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return         zero on success, or negative error value on error.
 */
int hip_handle_notify(const uint8_t packet_type,
                      const uint32_t ha_state,
                      struct hip_packet_context *ctx)
{
    int err       = 0;
    uint16_t mask = HIP_PACKET_CTRL_ANON, notify_controls = 0;
    struct hip_common i1;
    struct hip_tlv_common *current_param  = NULL;
    struct hip_notification *notification = NULL;
    struct in6_addr responder_ip, responder_hit;
    hip_tlv_type_t param_type             = 0, response;
    hip_tlv_len_t param_len               = 0;
    uint16_t msgtype                      = 0;
    in_port_t port                        = 0;


    HIP_IFEL(ctx->hadb_entry == NULL, -EFAULT,
             "Received a NOTIFY packet from an unknown sender, ignoring " \
             "the packet.\n");

    notify_controls = ntohs(ctx->input_msg->control);

    HIP_IFEL(!hip_controls_sane(notify_controls, mask), -EPROTO,
           "Received a NOTIFY packet with illegal controls: 0x%x, ignoring " \
           "the packet.\n", notify_controls);

    /* Loop through all the parameters in the received packet. */
    while ((current_param =
                hip_get_next_param(ctx->input_msg, current_param)) != NULL) {
        param_type = hip_get_param_type(current_param);

        if (param_type == HIP_PARAM_NOTIFICATION) {
            HIP_INFO("Found NOTIFICATION parameter in NOTIFY " \
                     "packet.\n");
            notification = (struct hip_notification *) current_param;

            param_len    = hip_get_param_contents_len(current_param);
            msgtype      = ntohs(notification->msgtype);

            switch (msgtype) {
            case HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "UNSUPPORTED_CRITICAL_PARAMETER_" \
                         "TYPE.\n");
                break;
            case HIP_NTF_INVALID_SYNTAX:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "INVALID_SYNTAX.\n");
                break;
            case HIP_NTF_NO_DH_PROPOSAL_CHOSEN:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "NO_DH_PROPOSAL_CHOSEN.\n");
                break;
            case HIP_NTF_INVALID_DH_CHOSEN:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "INVALID_DH_CHOSEN.\n");
                break;
            case HIP_NTF_NO_HIP_PROPOSAL_CHOSEN:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "NO_HIP_PROPOSAL_CHOSEN.\n");
                break;
            case HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "INVALID_HIP_TRANSFORM_CHOSEN.\n");
                break;
            case HIP_NTF_AUTHENTICATION_FAILED:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "AUTHENTICATION_FAILED.\n");
                break;
            case HIP_NTF_CHECKSUM_FAILED:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "CHECKSUM_FAILED.\n");
                break;
            case HIP_NTF_HMAC_FAILED:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "HMAC_FAILED.\n");
                break;
            case HIP_NTF_ENCRYPTION_FAILED:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "ENCRYPTION_FAILED.\n");
                break;
            case HIP_NTF_INVALID_HIT:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "INVALID_HIT.\n");
                break;
            case HIP_NTF_BLOCKED_BY_POLICY:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "BLOCKED_BY_POLICY.\n");
                break;
            case HIP_NTF_SERVER_BUSY_PLEASE_RETRY:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "SERVER_BUSY_PLEASE_RETRY.\n");
                break;
            case HIP_NTF_I2_ACKNOWLEDGEMENT:
                HIP_INFO("NOTIFICATION parameter type is " \
                         "I2_ACKNOWLEDGEMENT.\n");
                break;
            case HIP_PARAM_RELAY_TO:
            case HIP_PARAM_RELAY_FROM:
                response = ((msgtype == HIP_PARAM_RELAY_TO) ? HIP_I1 : HIP_NOTIFY);
                HIP_INFO("NOTIFICATION parameter type is " \
                         "RVS_NAT.\n");

                /* responder_hit is not currently used. */
                ipv6_addr_copy(&responder_hit, (struct in6_addr *) (void *)
                               notification->data);
                ipv6_addr_copy(&responder_ip, (struct in6_addr *) (void *)
                               &(notification->
                                 data[sizeof(struct in6_addr)]));
                memcpy(&port, &(notification->
                                data[2 * sizeof(struct in6_addr)]),
                       sizeof(in_port_t));

                /* If port is zero (the responder is not behind
                 * a NAT) we use hip_get_nat_udp_port() as the destination
                 * port. */
                if (port == 0) {
                    port = hip_get_peer_nat_udp_port();
                }

                /* We don't need to use hip_msg_alloc(), since
                 * the I1 packet is just the size of struct
                 * hip_common. */
                memset(&i1, 0, sizeof(i1));

                hip_build_network_hdr(&i1,
                                      response,
                                      ctx->hadb_entry->local_controls,
                                      &(ctx->hadb_entry)->hit_our,
                                      &(ctx->hadb_entry)->hit_peer);

                /* Calculate the HIP header length */
                hip_calc_hdr_len(&i1);

                /* This I1 packet must be send only once, which
                 * is why we use NULL entry for sending. */
                err = hip_send_pkt(&(ctx->hadb_entry)->our_addr,
                                   &responder_ip,
                                   (ctx->hadb_entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                                   port,
                                   &i1, NULL, 0);

                break;
            default:
                HIP_INFO("Unrecognized NOTIFICATION parameter " \
                         "type.\n");
                break;
            }
            HIP_HEXDUMP("NOTIFICATION parameter notification data:",
                        notification->data,
                        param_len
                        - sizeof(notification->reserved)
                        - sizeof(notification->msgtype)
                        );
            msgtype = 0;
        } else {
            HIP_INFO("Found unsupported parameter in NOTIFY " \
                     "packet.\n");
        }
    }

out_err:
    return err;
}

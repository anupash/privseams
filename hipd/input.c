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
 * @author  Laura Takkinen (blind code)
 * @author  Rene Hummen
 * @author  Samu Varjonen
 * @author  Tim Just
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "input.h"
#include "hadb.h"
#include "oppdb.h"
#include "user.h"
#include "keymat.h"
#include "lib/core/crypto.h"
#include "lib/core/builder.h"
#include "dh.h"
#include "lib/core/misc.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "lib/tool/pk.h"
#include "netdev.h"
#include "lib/tool/lutil.h"
#include "lib/core/state.h"
#include "oppdb.h"
#include "registration.h"
#include "esp_prot_hipd_msg.h"
#include "esp_prot_light_update.h"
#include "hipd.h"

#include "oppipdb.h"

/* TODO Remove this include, when modularization is finished */
#include "modules/update/hipd/update.h"

#ifdef CONFIG_HIP_MIDAUTH
#include "pisa.h"
#endif

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
                           u8 *hmac, void *hmac_key, int hmac_type)
{
    int err = 0;
    u8 hmac_res[HIP_AH_SHA_LEN];

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
    u8 orig_checksum      = 0;

    HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");

    HIP_IFEL(!(hmac = hip_get_param(msg, parameter_type)),
             -ENOMSG, "No HMAC parameter\n");

    /* hmac verification modifies the msg length temporarily, so we have
     * to restore the length */
    orig_len      = hip_get_msg_total_len(msg);

    /* hmac verification assumes that checksum is zero */
    orig_checksum = hip_get_msg_checksum(msg);
    hip_zero_msg_checksum(msg);

    len           = (u8 *) hmac - (u8 *) msg;
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
int hip_produce_keying_material(struct hip_common *msg, struct hip_context *ctx,
                                uint64_t I, uint64_t J,
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
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM)),
             -EINVAL,
             "Could not find HIP transform\n");
    HIP_IFEL((hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
             -EINVAL, "Could not select HIP transform\n");
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM)),
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
    esp_info                 = hip_get_param(msg, HIP_PARAM_ESP_INFO);

    if (esp_info != NULL) {
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

    HIP_IFEL(!(keymat = HIP_MALLOC(keymat_len, GFP_KERNEL)), -ENOMEM,
             "Error on allocating memory for keying material.\n");

    /* 1024 should be enough for shared secret. The length of the shared
     * secret actually depends on the DH Group. */
    /** @todo 1024 -> hip_get_dh_size ? */
    HIP_IFEL(!(dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_KERNEL)),
             -ENOMEM,
             "Error on allocating memory for Diffie-Hellman shared key.\n");

    memset(dh_shared_key, 0, dh_shared_len);

    HIP_IFEL(!(dhf = (struct hip_diffie_hellman *) hip_get_param(
                   msg, HIP_PARAM_DIFFIE_HELLMAN)),
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


    hip_make_keymat(dh_shared_key, dh_shared_len,
                    &km, keymat, keymat_len,
                    &msg->hits, &msg->hitr, &ctx->keymat_calc_index, I, J);

    /* draw from km to keymat, copy keymat to dst, length of
     * keymat is len */

    we_are_HITg = hip_hit_is_bigger(&msg->hitr, &msg->hits);
    HIP_DEBUG("We are %s HIT.\n", we_are_HITg ? "greater" : "lesser");

    if (we_are_HITg) {
        hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_hmac_out.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_enc_in.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(ctx->esp_out.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(ctx->auth_out.key, &km,
                                 auth_transf_length);
        hip_keymat_draw_and_copy(ctx->esp_in.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(ctx->auth_in.key, &km,
                                 auth_transf_length);
    } else {
        hip_keymat_draw_and_copy(ctx->hip_enc_in.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,
                                 hip_transf_length);
        hip_keymat_draw_and_copy(ctx->hip_hmac_out.key, &km,
                                 hmac_transf_length);
        hip_keymat_draw_and_copy(ctx->esp_in.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(ctx->auth_in.key, &km,
                                 auth_transf_length);
        hip_keymat_draw_and_copy(ctx->esp_out.key, &km,
                                 esp_transf_length);
        hip_keymat_draw_and_copy(ctx->auth_out.key, &km,
                                 auth_transf_length);
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_DH_CREATE\n");
    hip_perf_stop_benchmark(perf_set, PERF_DH_CREATE);
#endif
    HIP_HEXDUMP("HIP-gl encryption:", &ctx->hip_enc_out.key,
                hip_transf_length);
    HIP_HEXDUMP("HIP-gl integrity (HMAC) key:", &ctx->hip_hmac_out.key,
                hmac_transf_length);
    _HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n",
               hip_transf_length);
    HIP_HEXDUMP("HIP-lg encryption:", &ctx->hip_enc_in.key,
                hip_transf_length);
    HIP_HEXDUMP("HIP-lg integrity (HMAC) key:", &ctx->hip_hmac_in.key,
                hmac_transf_length);
    HIP_HEXDUMP("SA-gl ESP encryption key:", &ctx->esp_out.key,
                esp_transf_length);
    HIP_HEXDUMP("SA-gl ESP authentication key:", &ctx->auth_out.key,
                auth_transf_length);
    HIP_HEXDUMP("SA-lg ESP encryption key:", &ctx->esp_in.key,
                esp_transf_length);
    HIP_HEXDUMP("SA-lg ESP authentication key:", &ctx->auth_in.key,
                auth_transf_length);

    /* the next byte when creating new keymat */
    ctx->current_keymat_index = keymat_len_min;     /* offset value, so no +1 ? */
    ctx->keymat_calc_index    = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;
    ctx->esp_keymat_index     = esp_keymat_index;

    memcpy(ctx->current_keymat_K,
           keymat + (ctx->keymat_calc_index - 1) * HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

    _HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
               ctx->keymat_calc_index, ctx->current_keymat_index);
    _HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K,
                 HIP_AH_SHA_LEN);

    /* store DH shared key */
    ctx->dh_shared_key     = dh_shared_key;
    ctx->dh_shared_key_len = dh_shared_len;

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
        if (hip_shotgun_status == SO_HIP_SHOTGUN_ON
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
 * @param msg   a pointer to the received HIP control packet common header with
 *              source and destination HITs.
 * @param saddr a pointer to the source address from where the packet was
 *              received.
 * @param daddr a pointer to the destination address where to the packet was
 *              sent to (own address).
 * @param info  a pointer to the source and destination ports.
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_control_packet(struct hip_common *msg,
                               struct in6_addr *src_addr,
                               struct in6_addr *dst_addr,
                               hip_portpair_t *msg_info)
{
    hip_ha_t tmp, *entry = NULL;
    int err = 0, skip_sync = 0;
    struct in6_addr ipv6_any_addr = IN6ADDR_ANY_INIT;
    struct hip_packet_context ctx = {0};
    uint32_t type, state;

    /* Debug printing of received packet information. All received HIP
     * control packets are first passed to this function. Therefore
     * printing packet data here works for all packets. To avoid excessive
     * debug printing do not print this information inside the individual
     * receive or handle functions. */
    HIP_DEBUG_HIT("HIT Sender  ", &msg->hits);
    HIP_DEBUG_HIT("HIT Receiver", &msg->hitr);
    HIP_DEBUG("source port: %u, destination port: %u\n",
              msg_info->src_port, msg_info->dst_port);
    HIP_DUMP_MSG(msg);

    if (hip_hidb_hit_is_our(&msg->hits) &&
        (IN6_ARE_ADDR_EQUAL(&msg->hitr, &msg->hits) ||
         IN6_ARE_ADDR_EQUAL(&msg->hitr, &ipv6_any_addr)) &&
        !hip_addr_is_loopback(dst_addr) &&
        !hip_addr_is_loopback(src_addr) &&
        !IN6_ARE_ADDR_EQUAL(src_addr, dst_addr)) {
        HIP_DEBUG("Invalid loopback packet. Dropping.\n");
        goto out_err;
    }

    HIP_IFEL(hip_check_network_msg(msg),
             -1,
             "checking control message failed\n",
             -1);

    type  = hip_get_msg_type(msg);

    /** @todo Check packet csum.*/

    entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

    // Check if we need to drop the packet
    if (entry && hip_packet_to_drop(entry, type, &msg->hitr) == 1) {
        HIP_DEBUG("Ignoring the packet sent \n");
        err = -1;
        goto out_err;
    }

    ctx.msg        = msg;
    ctx.src_addr   = src_addr;
    ctx.dst_addr   = dst_addr;
    ctx.hadb_entry = entry;
    ctx.msg_info   = msg_info;

    if (entry) {
        state = entry->state;
    } else {
        state = HIP_STATE_NONE;
    }

#ifdef CONFIG_HIP_OPPORTUNISTIC
    if (!entry && opportunistic_mode &&
        (type == HIP_I1 || type == HIP_R1)) {
        entry = hip_oppdb_get_hadb_entry_i1_r1(msg, src_addr,
                                               dst_addr,
                                               msg_info);
    }
#endif

#ifdef CONFIG_HIP_RVS
    /* check if it a relaying msg */
    if (hip_relay_handle_relay_to(msg, type, src_addr, dst_addr, msg_info)) {
        err = -ECANCELED;
        goto out_err;
    } else {
        HIP_DEBUG("handle relay to failed, continue the bex handler\n");
    }
#endif

    switch (type) {
    case HIP_DATA:
    case HIP_I1:
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I1\n");
        hip_perf_start_benchmark(perf_set, PERF_I1);
#endif
        err = hip_handle_i1(type, state, &ctx);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_I1\n");
        hip_perf_stop_benchmark(perf_set, PERF_I1);
        hip_perf_write_benchmark(perf_set, PERF_I1);
#endif
        break;

    case HIP_I2:
        /* Possibly state. */
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2\n");
        hip_perf_start_benchmark(perf_set, PERF_I2);
#endif
        err = hip_receive_i2(&ctx);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_I2\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2);
        hip_perf_write_benchmark(perf_set, PERF_I2);
#endif
        break;
    case HIP_LUPDATE:
        HIP_IFCS(entry, err = esp_prot_receive_light_update(msg,
                                                            src_addr,
                                                            dst_addr,
                                                            entry));
        break;

    case HIP_R1:
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R1\n");
        hip_perf_start_benchmark(perf_set, PERF_R1);
#endif
        /* State. */
        HIP_IFEL(!entry, -1, "No entry when receiving R1\n");
        HIP_IFCS(entry, err = hip_receive_r1(msg, src_addr, dst_addr, entry, msg_info));
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_R1\n");
        hip_perf_stop_benchmark(perf_set, PERF_R1);
        hip_perf_write_benchmark(perf_set, PERF_R1);
#endif
        break;

    case HIP_R2:
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2\n");
        hip_perf_start_benchmark(perf_set, PERF_R2);
#endif
        HIP_IFCS(entry, err = hip_receive_r2(msg, src_addr, dst_addr, entry, msg_info));
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_R2\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2);
        hip_perf_write_benchmark(perf_set, PERF_R2);
#endif
        break;

    case HIP_UPDATE:
        HIP_DEBUG_HIT("received an UPDATE:  ", src_addr );
        HIP_IFCS(entry, err = hip_receive_update(&ctx));
        break;

    case HIP_NOTIFY:
        HIP_IFCS(entry, err = hip_receive_notify(msg, src_addr, dst_addr, entry));
        break;

    case HIP_BOS:
        err = hip_receive_bos(msg, src_addr, dst_addr, entry, msg_info);

        /*In case of BOS the msg->hitr is null, therefore it is replaced
         * with our own HIT, so that the beet state can also be
         * synchronized. */
        ipv6_addr_copy(&tmp.hit_peer, &msg->hits);
        hip_init_us(&tmp, NULL);
        ipv6_addr_copy(&msg->hitr, &tmp.hit_our);
        skip_sync = 0;
        break;

    case HIP_CLOSE:
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_HANDLE_CLOSE\n");
        hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
        HIP_IFCS(entry, err = hip_receive_close(msg, entry));
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE");
        hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE);
        hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
        break;

    case HIP_CLOSE_ACK:
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_HANDLE_CLOSE_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
        HIP_IFCS(entry, err = hip_receive_close_ack(msg, entry));
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
        hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
        break;

    default:
        HIP_ERROR("Unknown packet %d\n", type);
        err = -ENOSYS;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_SIGN, PERF_DSA_SIGN_IMPL, PERF_RSA_SIGN_IMPL, PERF_VERIFY, PERF_DSA_VERIFY_IMPL, PERF_RSA_VERIFY_IMPL, PERF_DH_CREATE\n");
    hip_perf_write_benchmark(perf_set, PERF_SIGN);
    hip_perf_write_benchmark(perf_set, PERF_DSA_SIGN_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_RSA_SIGN_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_VERIFY);
    hip_perf_write_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_RSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_DH_CREATE);
#endif
    HIP_DEBUG("Done with control packet, err is %d.\n", err);

    if (err) {
        goto out_err;
    }

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
 * @param msg   a pointer to the received HIP control packet common header with
 *              source and destination HITs.
 * @param saddr a pointer to the source address from where the packet was
 *              received.
 * @param daddr a pointer to the destination address where to the packet was
 *              sent to (own address).
 * @param info  a pointer to the source and destination ports.
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_udp_control_packet(struct hip_common *msg,
                                   struct in6_addr *saddr,
                                   struct in6_addr *daddr,
                                   hip_portpair_t *info)
{
    hip_ha_t *entry;
    int err                       = 0, type;
    struct in6_addr *saddr_public = saddr;

    _HIP_DEBUG("hip_nat_receive_udp_control_packet() invoked.\n");

    type  = hip_get_msg_type(msg);
    entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

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
        saddr_public = &entry->peer_addr;
    }
#endif
    HIP_IFEL(hip_receive_control_packet(msg, saddr_public, daddr, info), -1,
             "receiving of control packet failed\n");
out_err:
    return err;
}

/**
 * @brief Creates an I2 packet and sends it.
 *
 * @param ctx           context that includes the incoming R1 packet
 * @param solved_puzzle a value that solves the puzzle
 * @param r1_saddr      a pointer to R1 packet source IP address
 * @param r1_daddr      a pointer to R1 packet destination IP address
 * @param entry         a pointer to a host association
 * @param r1_info       a pointer to R1 packet source and destination ports
 * @param dhpv          a pointer to the DH public value chosen
 *
 * @return zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle,
                  in6_addr_t *r1_saddr, in6_addr_t *r1_daddr, hip_ha_t *entry,
                  hip_portpair_t *r1_info, struct hip_dh_public_value *dhpv)
{
    hip_transform_suite_t transform_hip_suite, transform_esp_suite;
    struct hip_spi_in_item spi_in_data;
    in6_addr_t daddr;
    struct hip_param *param                 = NULL;
    struct hip_diffie_hellman *dh_req       = NULL;
    struct hip_esp_info *esp_info           = NULL;
    struct hip_host_id_entry *host_id_entry = NULL;
    hip_common_t *i2                        = NULL;
    char *enc_in_msg                        = NULL, *host_id_in_enc = NULL;
    unsigned char *iv                       = NULL;
    int err = 0, host_id_in_enc_len = 0, written = 0;
    uint16_t mask = 0;
    uint32_t spi_in = 0;

    _HIP_DEBUG("hip_create_i2() invoked.\n");

    HIP_DEBUG("R1 source port %u, destination port %d\n",
              r1_info->src_port, r1_info->dst_port);

    HIP_ASSERT(entry);

    spi_in = entry->spi_inbound_current;

    /* Allocate space for a new I2 message. */
    HIP_IFEL(!(i2 = hip_msg_alloc()), -ENOMEM, "Allocation of I2 failed\n");

    /* TLV sanity checks are are already done by the caller of this
     * function. Now, begin to build I2 piece by piece. */

    /* Delete old SPDs and SAs, if present */
    hip_delete_security_associations_and_sp(entry);

    HIP_DEBUG("Build normal I2.\n");
    /* create I2 */
    hip_build_network_hdr(i2, HIP_I2, mask, &(ctx->input->hitr), &(ctx->input->hits));

    /********** ESP_INFO **********/
    /* SPI is set below */
    HIP_IFEL(hip_build_param_esp_info(i2, ctx->esp_keymat_index, 0, 0),
             -1, "building of ESP_INFO failed.\n");

    /********** R1 COUNTER (OPTIONAL) ********/
    /* we build this, if we have recorded some value (from previous R1s) */
    {
        uint64_t rtmp;

        HIP_LOCK_HA(entry);
        rtmp = entry->birthday;
        HIP_UNLOCK_HA(entry);

        HIP_IFEL(rtmp && hip_build_param_r1_counter(i2, rtmp), -1,
                 "Could not build R1 GENERATION parameter\n");
    }

    /********** SOLUTION **********/
    {
        struct hip_puzzle *pz;

        HIP_IFEL(!(pz = hip_get_param(ctx->input, HIP_PARAM_PUZZLE)), -ENOENT,
                 "Internal error: PUZZLE parameter mysteriously gone\n");
        HIP_IFEL(hip_build_param_solution(i2, pz, ntoh64(solved_puzzle)), -1,
                 "Building of solution failed\n");
    }

    /********** Diffie-Hellman *********/
    HIP_IFEL(!(dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN)),
             -ENOENT, "Internal error\n");
    HIP_IFEL((written = hip_insert_dh(dhpv->public_value,
                                      ntohs(dhpv->pub_len), dhpv->group_id)) < 0,
             -1, "Could not extract the DH public key\n");

    HIP_IFEL(hip_build_param_diffie_hellman_contents(i2,
                                                     dhpv->group_id,
                                                     dhpv->public_value,
                                                     written,
                                                     HIP_MAX_DH_GROUP_ID,
                                                     NULL,
                                                     0),
             -1,
             "Building of DH failed.\n");

    /********** HIP transform. **********/
    HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), -ENOENT);
    HIP_IFEL((transform_hip_suite =
                  hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
             -EINVAL, "Could not find acceptable hip transform suite\n");

    /* Select only one transform */
    HIP_IFEL(hip_build_param_hip_transform(i2,
                                           &transform_hip_suite, 1), -1,
             "Building of HIP transform failed\n");

    HIP_DEBUG("HIP transform: %d\n", transform_hip_suite);

    /************ Encrypted ***********/
    if (hip_encrypt_i2_hi) {
        switch (transform_hip_suite) {
        case HIP_HIP_AES_SHA1:
            HIP_IFEL(hip_build_param_encrypted_aes_sha1(i2,
                                                        (struct hip_tlv_common *) entry->our_pub),
                     -1,
                     "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
            get_random_bytes(iv, 16);
            host_id_in_enc = enc_in_msg +
                             sizeof(struct hip_encrypted_aes_sha1);
            break;
        case HIP_HIP_3DES_SHA1:
            HIP_IFEL(hip_build_param_encrypted_3des_sha1(i2, (struct hip_tlv_common *) entry->our_pub),
                     -1, "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
            get_random_bytes(iv, 8);
            host_id_in_enc = enc_in_msg +
                             sizeof(struct hip_encrypted_3des_sha1);
            break;
        case HIP_HIP_NULL_SHA1:
            HIP_IFEL(hip_build_param_encrypted_null_sha1(i2, (struct hip_tlv_common *) entry->our_pub),
                     -1, "Building of param encrypted failed.\n");
            enc_in_msg     = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
            HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
            iv             = NULL;
            host_id_in_enc = enc_in_msg +
                             sizeof(struct hip_encrypted_null_sha1);
            break;
        default:
            HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
                     transform_hip_suite);
        }
    } else {   /* add host id in plaintext without encrypted wrapper */
               /* Parameter HOST_ID. Notice that hip_get_public_key overwrites
                * the argument pointer, so we have to allocate some extra memory */

        HIP_IFEL(!(host_id_entry = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID,
                                                                        &(ctx->input->hitr),
                                                                        HIP_ANY_ALGO,
                                                                        -1)),
                   -1,
                   "Unknown HIT\n");

        _HIP_DEBUG("This HOST ID belongs to: %s\n",
                   hip_get_param_host_id_hostname(host_id_entry->host_id));

        HIP_IFEL(hip_build_param(i2, host_id_entry->host_id),
                 -1,
                 "Building of host id failed\n");
    }

    /* REG_INFO parameter. This builds a REG_REQUEST parameter in the I2
     * packet. */
    hip_handle_param_reg_info(entry, ctx->input, i2);

    /********** ESP-ENC transform. **********/
    HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM)), -ENOENT);

    /* Select only one transform */
    HIP_IFEL((transform_esp_suite =
                  hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
             -1, "Could not find acceptable hip transform suite\n");
    HIP_IFEL(hip_build_param_esp_transform(i2,
                                           &transform_esp_suite, 1), -1,
             "Building of ESP transform failed\n");

    /********** ESP-PROT anchor [OPTIONAL] **********/

    HIP_IFEL(esp_prot_i2_add_anchor(i2, entry, ctx), -1,
             "failed to add esp protection anchor\n");

    /************************************************/

    if (hip_encrypt_i2_hi) {
        HIP_HEXDUMP("enc(host_id)", host_id_in_enc,
                    hip_get_param_total_len(host_id_in_enc));

        /* Calculate the length of the host id inside the encrypted param */
        host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

        /* Adjust the host id length for AES (block size 16).
         * build_param_encrypted_aes has already taken care that there is
         * enough padding */
        if (transform_hip_suite == HIP_HIP_AES_SHA1) {
            int remainder = host_id_in_enc_len % 16;
            if (remainder) {
                HIP_DEBUG("Remainder %d (for AES)\n", remainder);
                host_id_in_enc_len += remainder;
            }
        }

        _HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
                     hip_get_param_total_len(host_id_in_enc));
        _HIP_HEXDUMP("encinmsg", enc_in_msg,
                     hip_get_param_total_len(enc_in_msg));
        HIP_HEXDUMP("enc key", &ctx->hip_enc_out.key, HIP_MAX_KEY_LEN);
        _HIP_HEXDUMP("IV", iv, 16);         // or 8
        HIP_DEBUG("host id type: %d\n",
                  hip_get_host_id_algo((struct hip_host_id *) host_id_in_enc));
        _HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);


        HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
                                      transform_hip_suite,
                                      host_id_in_enc_len,
                                      &ctx->hip_enc_out.key,
                                      HIP_DIRECTION_ENCRYPT), -1,
                 "Building of param encrypted failed\n");

        _HIP_HEXDUMP("encinmsg 2", enc_in_msg,
                     hip_get_param_total_len(enc_in_msg));
        _HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);
    }

    /* Now that almost everything is set up except the signature, we can
     * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

    HIP_DEBUG("src %d, dst %d\n", r1_info->src_port, r1_info->dst_port);

    entry->local_udp_port = r1_info->src_port;
    entry->peer_udp_port  = r1_info->dst_port;

    entry->hip_transform  = transform_hip_suite;

    /* XXX: -EAGAIN */
    HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

    HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input->hits,
                                   &ctx->input->hitr,
                                   r1_saddr, r1_daddr,
                                   IPPROTO_ESP, 1, 1),
             -1,
             "Setting up SP pair failed\n");

    esp_info          = hip_get_param(i2, HIP_PARAM_ESP_INFO);
    HIP_ASSERT(esp_info);     /* Builder internal error */
    esp_info->new_spi = htonl(spi_in);
    /* LSI not created, as it is local, and we do not support IPv4 */

    /********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
    /* must reply... */
    {
        struct hip_echo_request *ping;

        ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST_SIGN);
        if (ping) {
            int ln = hip_get_param_contents_len(ping);
            HIP_IFEL(hip_build_param_echo(i2, ping + 1, ln, 1, 0), -1,
                     "Error while creating echo reply parameter\n");
        }
    }

    /************* HMAC ************/
    HIP_IFEL(hip_build_param_hmac_contents(i2, &ctx->hip_hmac_out),
             -1, "Building of HMAC failed\n");

    /********** Signature **********/
    /* Build a digest of the packet built so far. Signature will
     * be calculated over the digest. */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_SIGN\n");
    hip_perf_start_benchmark(perf_set, PERF_SIGN);
#endif
    HIP_IFEL(entry->sign(entry->our_priv_key, i2), -EINVAL, "Could not create signature\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_SIGN\n");
    hip_perf_stop_benchmark(perf_set, PERF_SIGN);
#endif

    /********** ECHO_RESPONSE (OPTIONAL) ************/
    /* must reply */
    {
        struct hip_echo_request *ping;

        ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST);
        if (ping) {
            int ln = hip_get_param_contents_len(ping);
            HIP_IFEL(hip_build_param_echo(i2, (ping + 1), ln, 0, 0), -1,
                     "Error while creating echo reply parameter\n");
        }
    }

    /********** I2 packet complete **********/
    memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
    spi_in_data.spi     = spi_in;
    spi_in_data.ifindex = hip_devaddr2ifindex(r1_daddr);
    HIP_LOCK_HA(entry);

    // 99999 HIP_IFEB(hip_hadb_add_spi_old(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1, HIP_UNLOCK_HA(entry));

    entry->esp_transform = transform_esp_suite;
    HIP_DEBUG("Saving base exchange encryption data to entry \n");
    HIP_DEBUG_HIT("Our HIT: ", &entry->hit_our);
    HIP_DEBUG_HIT("Peer HIT: ", &entry->hit_peer);
    /* Store the keys until we receive R2 */
    HIP_IFEB(hip_store_base_exchange_keys(entry, ctx, 1), -1, HIP_UNLOCK_HA(entry));

    /** @todo Also store the keys that will be given to ESP later */
    HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);

    /* R1 packet source port becomes the I2 packet destination port. */
    err = hip_send_pkt(r1_daddr, &daddr,
                       (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       r1_info->src_port, i2, entry, 1);
    HIP_IFEL(err < 0, -ECOMM, "Sending I2 packet failed.\n");

out_err:
    if (i2) {
        HIP_FREE(i2);
    }

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
 * Handles an incoming R1 packet and calls hip_create_i2() if the R1 packet
 * passes all tests.
 *
 * @param r1       a pointer to the received R1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet was
 *                 received.
 * @param r1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @todo           When rendezvous service is used, the I1 packet is relayed
 *                 to the responder via the rendezvous server. Responder then
 *                 replies directly to the initiator with an R1 packet that has
 *                 a @c VIA_RVS parameter. This parameter contains the IP
 *                 addresses of the travesed RVSes (usually just one). The
 *                 initiator should store these addresses to cope with the
 *                 double jump problem.
 */
int hip_handle_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
                  hip_ha_t *entry, hip_portpair_t *r1_info)
{
    int err                          = 0, retransmission = 0, len;
    uint64_t solved_puzzle           = 0, I = 0;
    struct hip_context *ctx          = NULL;
    struct hip_host_id *peer_host_id = NULL;
    struct hip_r1_counter *r1cntr    = NULL;
    struct hip_dh_public_value *dhpv = NULL;
    struct hip_locator *locator      = NULL;
    char *str                        = NULL;

    /** A function set for NAT travelsal. */

    _HIP_DEBUG("hip_handle_r1() invoked.\n");

    if (entry->state == HIP_STATE_I2_SENT) {
        HIP_DEBUG("Retransmission\n");
        retransmission = 1;
    } else {
        HIP_DEBUG("Not a retransmission\n");
    }

    HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL)),
             -ENOMEM, "Could not allocate memory for context\n");
    memset(ctx, 0, sizeof(struct hip_context));
    ctx->input = r1;

    hip_relay_add_rvs_to_ha(r1, entry);

    /* According to the section 8.6 of the base draft, we must first check
     * signature. */

    /* Blinded R1 packets do not contain HOST ID parameters, so the
     * verification must be delayed to the R2 */
    /* Store the peer's public key to HA and validate it */
    /** @todo Do not store the key if the verification fails. */
    HIP_IFEL(!(peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID)),
             -ENOENT, "No HOST_ID found in R1\n");
    //copy hostname to hadb entry if local copy is empty
    if (strlen((char *) (entry->peer_hostname)) == 0) {
        memcpy(entry->peer_hostname,
               hip_get_param_host_id_hostname(peer_host_id),
               HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
    }
    HIP_IFE(hip_init_peer(entry, r1, peer_host_id), -EINVAL);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(entry->verify(entry->peer_pub_key, r1), -EINVAL,
                 "Verification of R1 signature failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
#endif

    /* R1 packet had destination port hip_get_nat_udp_port(), which means that the peer is
     * behind NAT. We set NAT mode "on" and set the send funtion to
     * "hip_send_udp". The client UDP port is not stored until the handling
     * of R2 packet. Don't know if the entry is already locked... */
    if (r1_info->dst_port != 0) {
        HIP_LOCK_HA(entry);
        if (entry->nat_mode == HIP_NAT_MODE_NONE) {
            entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
        }
        //hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
        HIP_UNLOCK_HA(entry);
    }

    /***** LOCATOR PARAMETER ******/
    locator = (struct hip_locator *) hip_get_param(r1, HIP_PARAM_LOCATOR);
    if (locator) {
        err = handle_locator(locator, r1_saddr, r1_daddr, entry, r1_info);
    } else {
        HIP_DEBUG("R1 did not have locator\n");
    }

    /* R1 generation check */

    /* We have problems with creating precreated R1s in reasonable
     * fashion... so we don't mind about generations. */
    r1cntr = hip_get_param(r1, HIP_PARAM_R1_COUNTER);

    /* Do control bit stuff here... */

    /* We must store the R1 generation counter, _IF_ it exists. */
    if (r1cntr) {
        HIP_LOCK_HA(entry);
        HIP_DEBUG("Storing R1 generation counter %d\n", r1cntr->generation);
        entry->birthday = ntoh64(r1cntr->generation);
        HIP_UNLOCK_HA(entry);
    }

    /* Solve puzzle: if this is a retransmission, we have to preserve
     * the old solution. */
    if (!retransmission) {
        struct hip_puzzle *pz = NULL;

        HIP_IFEL(!(pz = hip_get_param(r1, HIP_PARAM_PUZZLE)), -EINVAL,
                 "Malformed R1 packet. PUZZLE parameter missing\n");
        HIP_IFEL((solved_puzzle = hip_solve_puzzle(pz, r1, HIP_SOLVE_PUZZLE)) == 0,
                 -EINVAL, "Solving of puzzle failed\n");
        I                      = pz->I;
        entry->puzzle_solution = solved_puzzle;
        entry->puzzle_i        = pz->I;
    } else {
        I             = entry->puzzle_i;
        solved_puzzle = entry->puzzle_solution;
    }

    /* calculate shared secret and create keying material */
    ctx->dh_shared_key = NULL;
    /* note: we could skip keying material generation in the case
     * of a retransmission but then we'd had to fill ctx->hmac etc */
    HIP_IFEL(hip_produce_keying_material(r1,
                                         ctx,
                                         I,
                                         solved_puzzle,
                                         &dhpv),
            -EINVAL, "Could not produce keying material\n");

    /* Everything ok, save host id to HA */
    HIP_IFE(hip_get_param_host_id_di_type_len(
            peer_host_id, &str, &len) < 0, -1);
    HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n", str,
              len, hip_get_param_host_id_hostname(peer_host_id));

    /********* ESP protection preferred transforms [OPTIONAL] *********/

    HIP_IFEL(esp_prot_r1_handle_transforms(entry, ctx), -1,
             "failed to handle preferred esp protection transforms\n");

    /******************************************************************/

    /* We haven't handled REG_INFO parameter. We do that in hip_create_i2()
     * because we must create an REG_REQUEST parameter based on the data
     * of the REG_INFO parameter. */

    err = hip_create_i2(ctx,
                        solved_puzzle,
                        r1_saddr,
                        r1_daddr,
                        entry,
                        r1_info,
                        dhpv);

    HIP_IFEL(err < 0, -1, "Creation of I2 failed\n");

    if (entry->state == HIP_STATE_I1_SENT) {
        entry->state = HIP_STATE_I2_SENT;
    }

out_err:
    if (ctx->dh_shared_key) {
        HIP_FREE(ctx->dh_shared_key);
    }
    if (ctx) {
        HIP_FREE(ctx);
    }

    return err;
}

/**
 * Determines the action to be executed for an incoming R1 packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * a R1 packet. First it is checked, if the corresponding I1 packet has
 * been sent. If yes, then the received R1 packet is handled in
 * hip_handle_r1(). The R1 packet is handled also in @c HIP_STATE_ESTABLISHED.
 * Otherwise the packet is dropped and not handled in any way.
 *
 * @param r1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet
 *                 was received.
 * @param i1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 */
int hip_receive_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
                   hip_ha_t *entry, hip_portpair_t *r1_info)
{
    int state, mask = HIP_PACKET_CTRL_ANON, err = 0;

    HIP_DEBUG("hip_receive_r1() invoked.\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
    hip_oppipdb_delentry(&(entry->peer_addr));
#endif

    if (ipv6_addr_any(&r1->hitr)) {
        HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
    }

    HIP_IFEL(!hip_controls_sane(ntohs(r1->control), mask), 0,
             "Received illegal controls in R1: 0x%x Dropping\n",
             ntohs(r1->control));
    HIP_IFEL(!entry, -EFAULT,
             "Received R1 with no local state. Dropping\n");

    /* An implicit and insecure REA. If sender's address is different than
     * the one that was mapped, then we will overwrite the mapping with the
     * newer address. This enables us to use the rendezvous server, while
     * not supporting the REA TLV. */
    {
        struct in6_addr daddr;

        hip_hadb_get_peer_addr(entry, &daddr);
        if (ipv6_addr_cmp(&daddr, r1_saddr) != 0) {
            HIP_DEBUG("Mapped address didn't match received address\n");
            HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
            HIP_HEXDUMP("Mapping", &daddr, 16);
            HIP_HEXDUMP("Received", r1_saddr, 16);
            hip_hadb_delete_peer_addrlist_one_old(entry, &daddr);
            hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
                                   PEER_ADDR_STATE_ACTIVE,
                                   r1_info->src_port);
        }
    }

    state = entry->state;

    HIP_DEBUG("Received R1 in state %s\n", hip_state_str(state));
    switch (state) {
    case HIP_STATE_I1_SENT:
    case HIP_STATE_I2_SENT:
    case HIP_STATE_CLOSING:
    case HIP_STATE_CLOSED:
        /* E1. The normal case. Process, send I2, goto E2. */
        err = hip_handle_r1(r1, r1_saddr, r1_daddr, entry, r1_info);
        HIP_LOCK_HA(entry);
        if (err < 0) {
            HIP_ERROR("Handling of R1 failed\n");
        }
        HIP_UNLOCK_HA(entry);
        break;
    case HIP_STATE_R2_SENT:
        break;
    case HIP_STATE_ESTABLISHED:
        break;
    case HIP_STATE_NONE:
    case HIP_STATE_UNASSOCIATED:
    default:
        /* Can't happen. */
        err = -EFAULT;
        HIP_ERROR("R1 received in odd state: %d. Dropping.\n", state);
        break;
    }

    /* hip_put_ha(entry); */

out_err:
    return err;
}

/**
 * Creates and transmits an R2 packet.
 *
 * @param  ctx      a pointer to the context of processed I2 packet.
 * @param  i2_saddr a pointer to I2 packet source IP address.
 * @param  i2_daddr a pointer to I2 packet destination IP address.
 * @param  entry    a pointer to the current host association database state.
 * @param  i2_info  a pointer to the source and destination ports (when NAT is
 *                  in use).
 * @return zero on success, negative otherwise.
 */
int hip_create_r2(struct hip_context *ctx, in6_addr_t *i2_saddr,
                  in6_addr_t *i2_daddr, hip_ha_t *entry,
                  hip_portpair_t *i2_info,
                  in6_addr_t *dest,
                  const in_port_t dest_port)
{
    hip_common_t *r2 = NULL, *i2 = NULL;
    struct hip_crypto_key hmac;
    int err          = 0;
    uint16_t mask    = 0;
    uint32_t spi_in  = 0;

    _HIP_DEBUG("hip_create_r2() invoked.\n");
    /* Assume already locked entry */
    i2 = ctx->input;

    /* Build and send R2: IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
    HIP_IFEL(!(r2 = hip_msg_alloc()), -ENOMEM, "No memory for R2\n");

    /* Just swap the addresses to use the I2's destination HIT as the R2's
     * source HIT. */
    hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our, &entry->hit_peer);

    HIP_DUMP_MSG(r2);

    /* ESP_INFO */
    spi_in = entry->spi_inbound_current;
    HIP_IFEL(hip_build_param_esp_info(r2, ctx->esp_keymat_index, 0, spi_in),
             -1, "building of ESP_INFO failed.\n");

    /********** CHALLENGE_RESPONSE **********/
#ifdef CONFIG_HIP_MIDAUTH
    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    HIP_IFEL(hip_solve_puzzle_m(r2, ctx->input, entry), -1,
             "Building of Challenge_Response failed\n");
    char *midauth_cert = hip_pisa_get_certificate();

    HIP_IFEL(hip_build_param(r2, entry->our_pub), -1,
             "Building of host id failed\n");

    /* For now we just add some random data to see if it works */
    HIP_IFEL(hip_build_param_cert(r2, 1, 1, 1, 1, midauth_cert, strlen(midauth_cert)),
             -1,
             "Building of cert failed\n");

#endif

    /********** ESP-PROT anchor [OPTIONAL] **********/

    HIP_IFEL(esp_prot_r2_add_anchor(r2, entry), -1,
             "failed to add esp protection anchor\n");

    /************************************************/

#if defined(CONFIG_HIP_RVS)
    /********** REG_REQUEST **********/
    /* This part should only be executed at server offering rvs or relay
     * services.
     */

    /* Handle REG_REQUEST parameter. */
    hip_handle_param_reg_request(entry, i2, r2);

#endif

#if defined(CONFIG_HIP_RVS)
    if (hip_relay_get_status() != HIP_RELAY_OFF) {
        hip_build_param_reg_from(r2, i2_saddr, i2_info->src_port);
    }

#endif


    /* Create HMAC2 parameter. */
    if (entry->our_pub == NULL) {
        HIP_DEBUG("entry->our_pub is NULL.\n");
    } else {
        _HIP_HEXDUMP("Host ID for HMAC2", entry->our_pub,
                     hip_get_param_total_len(entry->our_pub));
    }

    memcpy(&hmac, &entry->hip_hmac_out, sizeof(hmac));
    HIP_IFEL(hip_build_param_hmac2_contents(r2, &hmac, entry->our_pub), -1,
             "Failed to build parameter HMAC2 contents.\n");

    /* Why is err reset to zero? -Lauri 11.06.2008 */
    if (err == 1) {
        err = 0;
    }

    HIP_IFEL(entry->sign(entry->our_priv_key, r2), -EINVAL, "Could not sign R2. Failing\n");

#ifdef CONFIG_HIP_RVS
    if (!ipv6_addr_any(dest)) {
        //if(hip_relay_get_status() == HIP_RELAY_ON) {

        HIP_INFO("create replay_to parameter in R2\n");
        hip_build_param_relay_to(
            r2, dest, dest_port);
        //}
    }

#endif

    err = hip_add_sa(i2_daddr, i2_saddr,
                     &ctx->input->hitr, &ctx->input->hits,
                     entry->spi_outbound_current,
                     entry->esp_transform,
                     &ctx->esp_out, &ctx->auth_out,
                     1, HIP_SPI_DIRECTION_OUT, 0, entry);
    if (err) {
        HIP_ERROR("Failed to setup outbound SA with SPI = %d.\n",
                  entry->spi_outbound_current);

        /* delete all IPsec related SPD/SA for this entry*/
        hip_delete_security_associations_and_sp(entry);
        goto out_err;
    }

    //end modify
    /* @todo Check if err = -EAGAIN... */
    HIP_DEBUG("Set up outbound IPsec SA, SPI=0x%x\n", entry->spi_outbound_new);
// end move

    err = hip_send_pkt(i2_daddr,
                       i2_saddr,
                       (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       entry->peer_udp_port,
                       r2,
                       entry,
                       1);

    if (err == 1) {
        err = 0;
    }

    HIP_IFEL(err, -ECOMM, "Sending R2 packet failed.\n");

    /* Send the first heartbeat. Notice that error value is ignored
     * because we want to to complete the base exchange successfully */
    /* for ICE , we do not need it*/
    if (hip_icmp_interval > 0) {
        _HIP_DEBUG("icmp sock %d\n", hip_icmp_sock);
        hip_send_icmp(hip_icmp_sock, entry);
    }

out_err:
    if (r2 != NULL) {
        free(r2);
    }

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
 * @param i2       a pointer to the I2 HIP packet common header with source and
 *                 destination HITs.
 * @param i2_saddr a pointer to the source address from where the I2 packet was
 *                 received.
 * @param i2_daddr a pointer to the destination address where the I2 packet was
 *                 sent to (own address).
 * @param ha       host association corresponding to the peer.
 * @param i2_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error. Success
 *                 indicates that I2 payloads are checked and R2 is created and
 *                 sent.
 * @see            Section 6.9. "Processing Incoming I2 Packets" of
 *                 <a href="http://www.rfc-editor.org/rfc/rfc5201.txt">
 *                 RFC 5201</a>.
 */
int hip_handle_i2(struct hip_packet_context *ctx)
{
    /* Primitive data types. */
    int err = 0, retransmission = 0, state = 0, host_id_found = 0, is_loopback = 0;
    uint16_t crypto_len                     = 0;
    uint32_t spi_in                         = 0, spi_out = 0;
    in_port_t dest_port                     = 0; // For the port in RELAY_FROM
    /* Pointers */
    char *tmp_enc                           = NULL, *enc = NULL;
    unsigned char *iv                       = NULL;
    struct hip_hip_transform *hip_transform = NULL;
    struct hip_host_id *host_id_in_enc      = NULL;
    struct hip_r1_counter *r1cntr           = NULL;
    struct hip_esp_info *esp_info           = NULL;
    struct hip_dh_public_value *dhpv        = NULL;
    struct hip_solution *solution           = NULL;
    /* Data structures. */
    in6_addr_t dest;     // dest for the IP address in RELAY_FROM
    hip_transform_suite_t esp_tfm, hip_tfm;
    struct hip_spi_in_item spi_in_data;
    struct hip_context i2_context;
    struct hip_locator *locator             = NULL;
    int do_transform                        = 0;
    int if_index                            = 0;
    struct sockaddr_storage ss_addr;
    struct sockaddr *addr                   = NULL;
    struct update_state *localstate         = NULL;
    /** A function set for NAT travelsal. */

    HIP_INFO("\n\nReceived I2 from:");
    HIP_INFO_HIT("Source HIT:", &(ctx->msg)->hits);
    HIP_INFO_IN6ADDR("Source IP :", ctx->src_addr);

    _HIP_DEBUG("hip_handle_i2() invoked.\n");

    /* The context structure is used to gather the context created from
     * processing the I2 packet, as well as storing the original packet.
     * From the context struct we can then access the I2 in hip_create_r2()
     * later. */
    i2_context.input         = NULL;
    i2_context.output        = NULL;
    i2_context.dh_shared_key = NULL;

    /* Store a pointer to the incoming i2 message in the context just
     * allocted. From the context struct we can then access the I2 in
     * hip_create_r2() later. */
    i2_context.input         = ctx->msg;

    /* Check that the Responder's HIT is one of ours. According to RFC5201,
     * this MUST be done. This check was added by Lauri on 01.08.2008.
     * Note that this condition is not satisfied at the HIP relay server */
    if (!hip_hidb_hit_is_our(&(ctx->msg)->hitr)) {
        err = -EPROTO;
        HIP_ERROR("Responder's HIT in the received I2 packet does not" \
                  " correspond to one of our own HITs. Dropping I2" \
                  " packet.\n");
        goto out_err;
    }

    /* Fetch the R1_COUNTER parameter. */
    r1cntr = hip_get_param(ctx->msg, HIP_PARAM_R1_COUNTER);

    /* Here we should check the 'system boot counter' using the R1_COUNTER
     * parameter. However, our precreated R1 packets do not support system
     * boot counter so we do not check it. */

    /* Check solution for cookie */
    solution = hip_get_param(i2_context.input, HIP_PARAM_SOLUTION);
    if (solution == NULL) {
        err = -ENODATA;
        HIP_ERROR("SOLUTION parameter missing from I2 packet. " \
                  "Dropping the I2 packet.\n");
        goto out_err;
    }

    HIP_DEBUG_HIT("i2_saddr", ctx->src_addr);
    HIP_DEBUG_HIT("i2_daddr", ctx->dst_addr);

    HIP_IFEL(hip_verify_cookie(ctx->src_addr, ctx->dst_addr, ctx->msg, solution),
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
    }

    /* Check HIP and ESP transforms, and produce keying material. */

    /* Note: we could skip keying material generation in the case of a
     * retransmission but then we'd had to fill i2_context.hmac etc.
     * TH: I'm not sure if this could be replaced with a function pointer
     * which is set from haDB. Usually you shouldn't have state here,
     * right? */

    HIP_IFEL(hip_produce_keying_material(i2_context.input, &i2_context,
                                         solution->I, solution->J, &dhpv),
             -EPROTO, "Unable to produce keying material. Dropping the I2" \
                      " packet.\n");


    /* Verify HMAC. */
    if (hip_hidb_hit_is_our(&(ctx->msg)->hits) &&
        hip_hidb_hit_is_our(&(ctx->msg)->hitr))
    {
        is_loopback = 1;
        HIP_IFEL(hip_verify_packet_hmac(ctx->msg, &i2_context.hip_hmac_out),
                 -EPROTO, "HMAC loopback validation on I2 failed. " \
                          "Dropping the I2 packet.\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac(ctx->msg, &i2_context.hip_hmac_in),
                 -EPROTO, "HMAC validation on I2 failed. Dropping the" \
                          " I2 packet.\n");
    }

    hip_transform = hip_get_param(ctx->msg, HIP_PARAM_HIP_TRANSFORM);
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
    enc = hip_get_param(ctx->msg, HIP_PARAM_ENCRYPTED);
    if (enc == NULL) {
        HIP_DEBUG("ENCRYPTED parameter missing from I2 packet\n");
        host_id_in_enc = hip_get_param(ctx->msg, HIP_PARAM_HOST_ID);
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

        /* This far we have succesfully produced the keying material (key),
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
                                          (is_loopback ? &i2_context.hip_enc_out.key :
                                           &i2_context.hip_enc_in.key),
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

    /* If there is no HIP association, we must create one now. */
    if (ctx->hadb_entry == NULL) {
        HIP_DEBUG("No HIP association found. Creating a new one.\n");

        if ((ctx->hadb_entry = hip_hadb_create_state(GFP_KERNEL)) == NULL) {
            err = -ENOMEM;
            HIP_ERROR("Out of memory when allocating memory for a new " \
                      "HIP association. Dropping the I2 packet.\n");
            goto out_err;
        }
    }

    //ctx->hadb_entry->hip_nat_key = i2_context.hip_nat_key;
    //HIP_DEBUG("hip nat key from context %s", i2_context.hip_nat_key);
    memcpy(ctx->hadb_entry->hip_nat_key, i2_context.hip_nat_key, HIP_MAX_KEY_LEN);
    //HIP_DEBUG("hip nat key in entry %s", ctx->hadb_entry->hip_nat_key);

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
    ipv6_addr_copy(&(ctx->hadb_entry)->hit_peer, &(ctx->msg)->hits);
    HIP_DEBUG("Initializing the HIP association.\n");
    hip_init_us(ctx->hadb_entry, &ctx->msg->hitr);
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
        hip_init_us(ctx->hadb_entry, &ctx->msg->hitr);
    }
    /* If the incoming I2 packet has hip_get_nat_udp_port() as destination port, NAT
     * mode is set on for the host association, I2 source port is
     * stored as the peer UDP port and send function is set to
     * "hip_send_pkt()". Note that we must store the port not until
     * here, since the source port can be different for I1 and I2. */
    if (ctx->msg_info->dst_port != 0) {
        if (ctx->hadb_entry->nat_mode == 0) {
            ctx->hadb_entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
        }
        ctx->hadb_entry->local_udp_port = ctx->msg_info->dst_port;
        ctx->hadb_entry->peer_udp_port  = ctx->msg_info->src_port;
        HIP_DEBUG("Setting send func to UDP for entry %p from I2 info.\n",
                  ctx->hadb_entry);
        /* @todo Is this function set needed ? */
        //hip_hadb_set_xmit_function_set(ctx->hadb_entry, &nat_xmit_func_set);
    }

    ctx->hadb_entry->hip_transform = hip_tfm;

    /** @todo the above should not be done if signature fails...
     *  or it should be cancelled. */

    /* Store peer's public key and HIT to HA */
    HIP_IFE(hip_init_peer(ctx->hadb_entry, ctx->msg, host_id_in_enc), -EINVAL);

    /* Validate signature */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY(2)\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key, i2_context.input), -EINVAL,
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

        HIP_IFEL(!(esp_tf = hip_get_param(i2_context.input,
                                          HIP_PARAM_ESP_TRANSFORM)),
                 -ENOENT, "Did not find ESP transform on i2\n");
        HIP_IFEL(!(esp_info = hip_get_param(i2_context.input,
                                            HIP_PARAM_ESP_INFO)),
                 -ENOENT, "Did not find SPI LSI on i2\n");

        if (r1cntr) {
            ctx->hadb_entry->birthday = r1cntr->generation;
        }
        ctx->hadb_entry->peer_controls |= ntohs(ctx->msg->control);

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
                                    ctx->msg_info->src_port),
             -1,
             "Error while adding the preferred peer address\n");

    HIP_DEBUG("retransmission: %s\n", (retransmission ? "yes" : "no"));
    HIP_DEBUG("src %d, dst %d\n",
              ctx->msg_info->src_port,
              ctx->msg_info->dst_port);

    /********** ESP-PROT anchor [OPTIONAL] **********/

    HIP_IFEL(esp_prot_i2_handle_anchor(ctx->hadb_entry, &i2_context), -1,
             "failed to handle esp prot anchor\n");

    /************************************************/

    /* Set up IPsec associations */
    err = hip_add_sa(ctx->src_addr,
                     ctx->dst_addr,
                     &i2_context.input->hits,
                     &i2_context.input->hitr,
                     spi_in,
                     esp_tfm,
                     &i2_context.esp_in,
                     &i2_context.auth_in,
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

    HIP_IFEL(hip_setup_hit_sp_pair(&i2_context.input->hits,
                                   &i2_context.input->hitr,
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
    HIP_IFE(hip_store_base_exchange_keys(ctx->hadb_entry, &i2_context, 0), -1);
    //hip_hadb_insert_state(ctx->hadb_entry);

    HIP_DEBUG("\nInserted a new host association state.\n"
              "\tHIP state: %s\n" \
              "\tDefault outgoing SPI 0x%x.\n"
              "\tCreating an R2 packet in response next.\n",
              hip_state_str(ctx->hadb_entry->state), ctx->hadb_entry->spi_outbound_new);


#ifdef CONFIG_HIP_RVS
    ipv6_addr_copy(&dest, &in6addr_any);
    if (hip_relay_get_status() == HIP_RELAY_OFF) {
        state = hip_relay_handle_relay_from(ctx->msg, ctx->src_addr, &dest, &dest_port);
        if (state == -1) {
            HIP_DEBUG( "Handling RELAY_FROM of  I2 packet failed.\n");
            goto out_err;
        }
    }
#endif

    /* Note that we haven't handled the REG_REQUEST yet. This is because we
     * must create an REG_RESPONSE parameter into the R2 packet based on the
     * REG_REQUEST parameter. We handle the REG_REQUEST parameter in
     * hip_create_r2() - although that is somewhat illogical.
     * -Lauri 06.05.2008 */

    /* Create an R2 packet in response. */
    HIP_IFEL(hip_create_r2(&i2_context,
                           ctx->src_addr,
                           ctx->dst_addr,
                           ctx->hadb_entry,
                           ctx->msg_info,
                           &dest,
                           dest_port),
             -1,
             "Creation of R2 failed\n");


    /** @todo Should wait for ESP here or wait for implementation specific
     *  time. */

    /* As for the above todo item:
     *
     * Where is it said that we should wait for ESP or implementation
     * specific time here? This far we have succesfully verified and
     * processed the I2 message (except the LOCATOR parameter) and sent an
     * R2 as an response. We are here at state UNASSOCIATED. From Section
     * 4.4.2. of RFC 5201 we learn that if I2 processing was successful, we
     * should "send R2 and go to R2-SENT" or if I2 processing failed, we
     * should "stay at UNASSOCIATED". -Lauri 29.04.2008 */

    /** RFC 5201 Section 5.2.13:
     *   Notice that the section says "The Update ID is an unsigned quantity,
     *   initialized by a host to zero upon moving to ESTABLISHED state" and
     *   "The Update ID is incremented by one before each new UPDATE that is
     *   sent by the host; the first UPDATE packet originated by a host has
     *   an Update ID of 0". All of these requirements can not be achieved
     *   at the same time so we initialize the id to -1.
     */

    /* @todo Need hook for modularization */
    //ctx->hadb_entry->update_id_out = -1; TODO why -1?
    localstate = hip_get_state_item(ctx->hadb_entry->hip_modular_state, "update");
    localstate->update_id_out = 0;

    ctx->hadb_entry->state = HIP_STATE_ESTABLISHED;

    /***** LOCATOR PARAMETER ******/
    /* Why do we process the LOCATOR parameter only after R2 has been sent?
     * -Lauri 29.04.2008.
     * We do not have valid spi_out to put the addresses into and NAT benefits
     * from the later handling ...
     * --samu
     */

    /***** LOCATOR PARAMETER *****/
    locator = (struct hip_locator *) hip_get_param(ctx->msg, HIP_PARAM_LOCATOR);
    if (locator) {
        HIP_DEBUG("Locator parameter support in BEX is not implemented!\n");
    }

//end add
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
    /* 'ha' is not NULL if hip_receive_i2() fetched the HA for us. In that
     * case we must not release our reference to it. Otherwise, if 'ha' is
     * NULL, then we created the HIP HA in this function and we should free
     * the reference. */
    /* 'ctx->hadb_entry' cannot be NULL here anymore since it has been used in this
     * function directly without NULL check. -Lauri. */

    /* hip_put_ha(ctx->hadb_entry); */

    if (tmp_enc != NULL) {
        free(tmp_enc);
    }
    if (i2_context.dh_shared_key != NULL) {
        free(i2_context.dh_shared_key);
    }

    return err;
}

/**
 * Receive I2 packet.
 *
 * This is the initial function which is called when an I2 packet is received.
 * If we are in correct state, the packet is handled to hip_handle_i2() for
 * further processing.
 *
 * @param i2       a pointer to...
 * @param i2_saddr a pointer to...
 * @param i2_daddr a pointer to...
 * @param entry    a pointer to...
 * @param i2_info  a pointer to...
 * @return         always zero
 * @todo   Check if it is correct to return always 0
 */
int hip_receive_i2(struct hip_packet_context *ctx)
{
    int state     = 0, err = 0;
    uint16_t mask = HIP_PACKET_CTRL_ANON;
    _HIP_DEBUG("hip_receive_i2() invoked.\n");

    HIP_IFEL(ipv6_addr_any(&(ctx->msg)->hitr), 0,
             "Received NULL receiver HIT in I2. Dropping\n");

    HIP_IFEL(!hip_controls_sane(ntohs(ctx->msg->control), mask), 0,
             "Received illegal controls in I2: 0x%x. Dropping\n",
             ntohs(ctx->msg->control));

    if (ctx->hadb_entry == NULL) {
#ifdef CONFIG_HIP_RVS
        if (hip_relay_get_status() != HIP_RELAY_OFF) {
            hip_relrec_t *rec = NULL, dummy;

            /* Check if we have a relay record in our database matching the
             * Responder's HIT. We should find one, if the Responder is
             * registered to relay.*/
            HIP_DEBUG_HIT("Searching relay record on HIT ", &(ctx->msg)->hitr);
            memcpy(&(dummy.hit_r), &(ctx->msg)->hitr, sizeof(ctx->msg->hitr));
            rec = hip_relht_get(&dummy);
            if (rec == NULL) {
                HIP_INFO("No matching relay record found.\n");
            } else if (rec->type != HIP_RVSRELAY) {
                HIP_INFO("Matching relay record found:Full-Relay.\n");
                hip_relay_forward(ctx->msg,
                                  ctx->src_addr,
                                  ctx->dst_addr,
                                  rec,
                                  ctx->msg_info,
                                  HIP_I2,
                                  rec->type);
                state = HIP_STATE_NONE;
                err   = -ECANCELED;
                goto out_err;
            }
        }
#endif
//end
        state = HIP_STATE_UNASSOCIATED;
    } else {
        HIP_LOCK_HA(ctx->hadb_entry);
        state = ctx->hadb_entry->state;
    }

    HIP_DEBUG("Received I2 in state %s\n", hip_state_str(state));

    switch (state) {
    case HIP_STATE_UNASSOCIATED:
        /* Possibly no state created yet, thus function pointers can't
         * be used here. */
        err = hip_handle_i2(ctx);

        break;
    case HIP_STATE_I2_SENT:
        if (ctx->hadb_entry->is_loopback) {
            err = hip_handle_i2(ctx);
        } else if (hip_hit_is_bigger(&(ctx->hadb_entry)->hit_our,
                                     &(ctx->hadb_entry)->hit_peer)) {
            HIP_IFEL(hip_receive_i2(ctx),
                     -ENOSYS,
                     "Dropping HIP packet.\n");
        }
        break;
    case HIP_STATE_I1_SENT:
    case HIP_STATE_R2_SENT:
        err = hip_handle_i2(ctx);
        break;
    case HIP_STATE_ESTABLISHED:
        err = hip_handle_i2(ctx);

        break;
    case HIP_STATE_CLOSING:
    case HIP_STATE_CLOSED:
        err = hip_handle_i2(ctx);
        break;
    default:
        HIP_ERROR("Internal state (%d) is incorrect\n", state);
        break;
    }

    /* hip_put_ha(entry); */

out_err:
    if (err) {
        HIP_ERROR("Error (%d) occurred\n", err);
    }

    return err;
}

/**
 * hip_handle_r2 - handle incoming R2 packet
 * @param skb sk_buff where the HIP packet is in
 * @param entry HA
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(hip_common_t *r2, in6_addr_t *r2_saddr, in6_addr_t *r2_daddr,
                  hip_ha_t *entry, hip_portpair_t *r2_info)
{
    struct hip_context *ctx         = NULL;
    struct hip_esp_info *esp_info   = NULL;
    struct hip_spi_out_item spi_out_data;
    int err                         = 0, tfm = 0, retransmission = 0, idx = 0;
    uint32_t spi_recvd              = 0, spi_in = 0;
    struct hip_locator *locator     = NULL;
    struct update_state *localstate = NULL;

    if (entry->state == HIP_STATE_ESTABLISHED) {
        retransmission = 1;
        HIP_DEBUG("Retransmission\n");
    } else {
        HIP_DEBUG("Not a retransmission\n");
    }

    /* assume already locked entry */
    HIP_IFE(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_ATOMIC)), -ENOMEM);
    memset(ctx, 0, sizeof(struct hip_context));
    ctx->input = r2;

    /* Verify HMAC */
    if (entry->is_loopback) {
        HIP_IFEL(hip_verify_packet_hmac2(
                     r2, &entry->hip_hmac_out, entry->peer_pub), -1,
                 "HMAC validation on R2 failed.\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac2(
                     r2, &entry->hip_hmac_in, entry->peer_pub), -1,
                 "HMAC validation on R2 failed.\n");
    }

    /* Signature validation */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_VERIFY(3)\n");
    hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
    HIP_IFEL(entry->verify(entry->peer_pub_key, r2), -EINVAL,
             "R2 signature verification failed.\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY(3)\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
#endif

    /* The rest */
    HIP_IFEL(!(esp_info = hip_get_param(r2, HIP_PARAM_ESP_INFO)), -EINVAL,
             "Parameter SPI not found.\n");

    spi_recvd                   = ntohl(esp_info->new_spi);
    memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
    spi_out_data.spi            = spi_recvd;
    // 99999 HIP_IFE(hip_hadb_add_spi_old(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data), -1);

    entry->spi_outbound_current =  spi_recvd;
    HIP_DEBUG("Set SPI out = 0x%x\n", spi_recvd);

    /* Copy SPI out value here or otherwise ICE code has zero SPI */
    entry->spi_outbound_new     = spi_recvd;
    HIP_DEBUG("Set default SPI out = 0x%x\n", spi_recvd);

    memcpy(&ctx->esp_out, &entry->esp_out, sizeof(ctx->esp_out));
    memcpy(&ctx->auth_out, &entry->auth_out, sizeof(ctx->auth_out));
    HIP_DEBUG("entry should have only one spi_in now, test\n");

    spi_in = entry->spi_inbound_current;
    HIP_DEBUG("spi_in: 0x%x\n", spi_in);

    tfm    = entry->esp_transform;
    HIP_DEBUG("esp_transform: %i\n", tfm);

    HIP_DEBUG("R2 packet source port: %d, destination port %d.\n",
              r2_info->src_port, r2_info->dst_port);

    /********** ESP-PROT anchor [OPTIONAL] **********/

    HIP_IFEL(esp_prot_r2_handle_anchor(entry, ctx), -1,
             "failed to handle esp prot anchor\n");

    /************************************************/

    /*comment out for draft v6
     *      hip_nat_handle_pacing(r2, entry);
     */

    /***** LOCATOR PARAMETER *****/
    locator = (struct hip_locator *) hip_get_param(r2, HIP_PARAM_LOCATOR);
    if (locator) {
        HIP_DEBUG("Locator parameter support in BEX is not implemented!\n");
    }
    //end add

    // moved from hip_create_i2
    HIP_DEBUG_HIT("hit our", &entry->hit_our);
    HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
    HIP_IFEL(hip_add_sa(r2_saddr,
                        r2_daddr,
                        &ctx->input->hits,
                        &ctx->input->hitr,
                        spi_in,
                        tfm,
                        &entry->esp_in,
                        &entry->auth_in,
                        0,
                        HIP_SPI_DIRECTION_IN,
                        0,
                        entry),
            -1,
            "Failed to setup IPsec SPD/SA entries, peer:src\n");

    err = hip_add_sa(r2_daddr,
                     r2_saddr,
                     &ctx->input->hitr,
                     &ctx->input->hits,
                     spi_recvd,
                     tfm,
                     &ctx->esp_out,
                     &ctx->auth_out,
                     0,
                     HIP_SPI_DIRECTION_OUT,
                     0,
                     entry);

        if (err) {
            /** @todo Remove inbound IPsec SA. */
            HIP_ERROR("hip_add_sa() failed, peer:dst (err = %d).\n", err);
            err = -1;
            goto out_err;
        }

    /** @todo Check for -EAGAIN */
    HIP_DEBUG("Set up outbound IPsec SA, SPI = 0x%x (host).\n", spi_recvd);

    /* Source IPv6 address is implicitly the preferred address after the
     * base exchange. */

    idx = hip_devaddr2ifindex(r2_daddr);

    if (idx != 0) {
        HIP_DEBUG("ifindex = %d\n", idx);
        // hip_hadb_set_spi_ifindex_deprecated(entry, spi_in, idx);
    } else {
        HIP_ERROR("Couldn't get device ifindex of address\n");
    }

    /* Copying address list from temp location in entry
     * "entry->peer_addr_list_to_be_added" */
    hip_copy_peer_addrlist_changed(entry);

    /* Handle REG_RESPONSE and REG_FAILED parameters. */
    hip_handle_param_reg_response(entry, r2);
    hip_handle_param_reg_failed(entry, r2);

    hip_handle_reg_from(entry, r2);

    /* These will change SAs' state from ACQUIRE to VALID, and wake up any
     * transport sockets waiting for a SA. */
    // hip_finalize_sa(&entry->hit_peer, spi_recvd);
    // hip_finalize_sa(&entry->hit_our, spi_in);

    /** RFC 5201 Section 5.2.13:
     *   Notice that the section says "The Update ID is an unsigned quantity,
     *   initialized by a host to zero upon moving to ESTABLISHED state" and
     *   "The Update ID is incremented by one before each new UPDATE that is
     *   sent by the host; the first UPDATE packet originated by a host has
     *   an Update ID of 0". All of these requirements can not be achieved
     *   at the same time so we initialize the id to -1.
     */
    /* @todo Need hook for modularization */
    //entry->update_id_out = -1; TODO why -1?
    localstate = hip_get_state_item(entry->hip_modular_state, "update");
    localstate->update_id_out  = 0;

    entry->state         = HIP_STATE_ESTABLISHED;
    hip_hadb_insert_state(entry);

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
    hip_oppipdb_delentry(&(entry->peer_addr));
#endif
    HIP_INFO("Reached ESTABLISHED state\n");
    HIP_INFO("Handshake completed\n");




#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_BASE\n");
    hip_perf_stop_benchmark(perf_set, PERF_BASE);
    hip_perf_write_benchmark(perf_set, PERF_BASE);
#endif
    if (entry->hip_msg_retrans.buf) {
        entry->hip_msg_retrans.count = 0;
        memset(entry->hip_msg_retrans.buf, 0, HIP_MAX_NETWORK_PACKET);
    }

    /* Send the first heartbeat. Notice that the error is ignored to complete
     * the base exchange successfully. */

    if (hip_icmp_interval > 0) {
        hip_send_icmp(hip_icmp_sock, entry);
    }

    //TODO Send the R2 Response to Firewall

out_err:
    if (entry->state == HIP_STATE_ESTABLISHED) {
        HIP_DEBUG("Send response to firewall \n");
        hip_firewall_set_bex_data(SO_HIP_FW_BEX_DONE, entry, &entry->hit_our, &entry->hit_peer);
    } else {
        hip_firewall_set_bex_data(SO_HIP_FW_BEX_DONE, entry, NULL, NULL);
    }

    if (ctx) {
        HIP_FREE(ctx);
    }
    return err;
}

/**
 * Handles an incoming I1 packet.
 *
 * Handles an incoming I1 packet and parses @c FROM or @c RELAY_FROM parameter
 * from the packet. If a @c FROM or a @c RELAY_FROM parameter is found, there must
 * also be a @c RVS_HMAC parameter present. This hmac is first verified. If the
 * verification fails, a negative error value is returned and hip_xmit_r1() is
 * not invoked. If verification succeeds,
 * <ol>
 * <li>and a @c FROM parameter is found, the IP address obtained from the
 * parameter is passed to hip_xmit_r1() as the destination IP address. The
 * source IP address of the received I1 packet is passed to hip_xmit_r1() as
 * the IP of RVS.</li>
 * <li>and a @c RELAY_FROM parameter is found, the IP address and
 * port number obtained from the parameter is passed to hip_xmit_r1() as the
 * destination IP address and destination port. The source IP address and source
 * port of the received I1 packet is passed to hip_xmit_r1() as the IP and port
 * of RVS.</li>
 * <li>If no @c FROM or @c RELAY_FROM parameters are found, this function does
 * nothing else but calls hip_xmit_r1().</li>
 * </ol>
 *
 * @param i1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where to the I1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @warning        This code only handles a single @c FROM or @c RELAY_FROM
 *                 parameter. If there is a mix of @c FROM and @c RELAY_FROM
 *                 parameters, only the first @c FROM parameter is parsed. Also,
 *                 if there are multiple @c FROM or @c RELAY_FROM parameters
 *                 present in the incoming I1 packet, only the first of a kind
 *                 is parsed.
 */
int hip_handle_i1(const uint32_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_BASE\n");
    hip_perf_start_benchmark(perf_set, PERF_BASE);
#endif
    int err = 0, mask = 0, src_hit_is_our;
    hip_tlv_type_t relay_para_type = 0;
    in6_addr_t dest;    /* For the IP address in FROM/RELAY_FROM */
    in_port_t dest_port = 0; /* For the port in RELAY_FROM */

    HIP_ASSERT(!ipv6_addr_any(&(ctx->msg)->hitr));

    /* In some environments, a copy of broadcast our own I1 packets
     * arrive at the local host too. The following variable handles
     * that special case. Since we are using source HIT (and not
     * destination) it should handle also opportunistic I1 broadcast */
    src_hit_is_our = hip_hidb_hit_is_our(&(ctx->msg)->hits);

    /* check i1 for broadcast/multicast addresses */
    if (IN6_IS_ADDR_V4MAPPED(ctx->dst_addr)) {
        struct in_addr addr4;

        IPV6_TO_IPV4_MAP(ctx->dst_addr, &addr4);

        if (addr4.s_addr == INADDR_BROADCAST) {
            HIP_DEBUG("Received I1 broadcast\n");
            HIP_IFEL(src_hit_is_our, -1,
                     "Received a copy of own broadcast, dropping\n");
            HIP_IFEL(hip_select_source_address(ctx->dst_addr, ctx->src_addr), -1,
                     "Could not find source address\n");
        }
    } else if (IN6_IS_ADDR_MULTICAST(ctx->dst_addr)) {
        HIP_IFEL(src_hit_is_our, -1,
                 "Received a copy of own broadcast, dropping\n");
        HIP_IFEL(hip_select_source_address(ctx->dst_addr, ctx->src_addr), -1,
                 "Could not find source address\n");
    }

    HIP_IFEL(!hip_controls_sane(ntohs(ctx->msg->control), mask), -1,
             "Received illegal controls in I1: 0x%x. Dropping\n", ntohs(ctx->msg->control));

    HIP_INFO_HIT("I1 Source HIT:", &(ctx->msg)->hits);
    HIP_INFO_IN6ADDR("I1 Source IP :", ctx->src_addr);

    ipv6_addr_copy(&dest, &in6addr_any);

    err = hip_xmit_r1(ctx->msg,
                      ctx->src_addr,
                      ctx->dst_addr,
                      &dest,
                      dest_port,
                      ctx->msg_info,
                      relay_para_type);
out_err:
    return err;
}

/**
 * @addtogroup receive_functions
 * @{
 */

/**
 * hip_receive_r2 - receive R2 packet
 * @param skb sk_buff where the HIP packet is in
 * TODO doxygen header incomplete
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * @return 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_r2(struct hip_common *hip_common,
                   struct in6_addr *r2_saddr,
                   struct in6_addr *r2_daddr,
                   hip_ha_t *entry,
                   hip_portpair_t *r2_info)
{
    int err       = 0, state;
    uint16_t mask = 0;

    _HIP_DEBUG("hip_receive_r2() invoked.\n");

    HIP_IFEL(ipv6_addr_any(&hip_common->hitr), -1,
             "Received NULL receiver HIT in R2. Dropping\n");

    HIP_IFEL(!hip_controls_sane(ntohs(hip_common->control), mask), -1,
             "Received illegal controls in R2: 0x%x. Dropping\n", ntohs(hip_common->control));
    //HIP_IFEL(!(entry = hip_hadb_find_byhits(&hip_common->hits,
    //              &hip_common->hitr)), -EFAULT,
    //          "Received R2 by unknown sender\n");

    HIP_IFEL(!entry, -EFAULT,
             "Received R2 by unknown sender\n");

    HIP_LOCK_HA(entry);
    state = entry->state;

    // if the NAT mode is used, update the port numbers of the host association
    if (r2_info->dst_port == hip_get_local_nat_udp_port()) {
        entry->local_udp_port = r2_info->dst_port;
        entry->peer_udp_port  = r2_info->src_port;
    }

    HIP_DEBUG("Received R2 in state %s\n", hip_state_str(state));
    switch (state) {
    case HIP_STATE_I2_SENT:
        /* The usual case. */
        err = hip_handle_r2(hip_common, r2_saddr, r2_daddr, entry, r2_info);
        if (err) {
            HIP_ERROR("hip_handle_r2 failed (err=%d)\n", err);
            goto out_err;
        }
        break;

    case HIP_STATE_ESTABLISHED:
        if (entry->is_loopback) {
            err = hip_handle_r2(hip_common, r2_saddr, r2_daddr, entry, r2_info);
        }
        break;
    case HIP_STATE_R2_SENT:
    case HIP_STATE_UNASSOCIATED:
    case HIP_STATE_I1_SENT:
    default:
        HIP_IFEL(1, -EFAULT, "Dropping\n");
    }

out_err:

    /* hip_put_ha(entry); */

    return err;
}

/**
 * Handles an incoming NOTIFY packet.
 *
 * Handles an incoming NOTIFY packet and parses @c NOTIFICATION parameters and
 * @c VIA_RVS parameter from the packet.
 *
 * @param notify       a pointer to the received NOTIFY HIP packet common header
 *                     with source and destination HITs.
 * @param notify_saddr a pointer to the source address from where the NOTIFY
 *                     packet was received.
 * @param notify_daddr a pointer to the destination address where to the NOTIFY
 *                     packet was sent to (own address).
 * @param entry        a pointer to a host association
 */
static inline int hip_handle_notify(const struct hip_common *notify,
                                    const struct in6_addr *notify_saddr,
                                    const struct in6_addr *notify_daddr, hip_ha_t *entry)
{
    int err                               = 0;
    struct hip_common i1;
    struct hip_tlv_common *current_param  = NULL;
    struct hip_notification *notification = NULL;
    struct in6_addr responder_ip, responder_hit;
    hip_tlv_type_t param_type             = 0, response;
    hip_tlv_len_t param_len               = 0;
    uint16_t msgtype                      = 0;
    in_port_t port                        = 0;

    /* draft-ietf-hip-base-06, Section 6.13: Processing NOTIFY packets is
     * OPTIONAL. If processed, any errors in a received NOTIFICATION parameter
     * SHOULD be logged. */

    _HIP_DEBUG("hip_receive_notify() invoked.\n");

    /* Loop through all the parameters in the received I1 packet. */
    while ((current_param =
                hip_get_next_param(notify, current_param)) != NULL) {
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
                                      entry->local_controls,
                                      &entry->hit_our,
                                      &entry->hit_peer);

                /* Calculate the HIP header length */
                hip_calc_hdr_len(&i1);

                //sleep(3);

                /* This I1 packet must be send only once, which
                 * is why we use NULL entry for sending. */
                err = hip_send_pkt(&entry->our_addr, &responder_ip,
                                   (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
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

    return err;
}

/**
 * Determines the action to be executed for an incoming NOTIFY packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * a NOTIFY packet.
 *
 * @param notify       a pointer to the received NOTIFY HIP packet common header
 *                     with source and destination HITs.
 * @param notify_saddr a pointer to the source address from where the NOTIFY
 *                     packet was received.
 * @param notify_daddr a pointer to the destination address where to the NOTIFY
 *                     packet was sent to (own address).
 * @param entry        a pointer to the current host association database state.
 */
int hip_receive_notify(const struct hip_common *notify,
                       const struct in6_addr *notify_saddr,
                       const struct in6_addr *notify_daddr, hip_ha_t *entry)
{
    int err       = 0;
    uint16_t mask = HIP_PACKET_CTRL_ANON, notify_controls = 0;

    _HIP_DEBUG("hip_receive_notify() invoked.\n");

    HIP_IFEL(entry == NULL, -EFAULT,
             "Received a NOTIFY packet from an unknown sender, ignoring " \
             "the packet.\n");

    notify_controls = ntohs(notify->control);

    HIP_IFEL(!hip_controls_sane(notify_controls, mask), -EPROTO,
             "Received a NOTIFY packet with illegal controls: 0x%x, ignoring " \
             "the packet.\n", notify_controls);

    err = hip_handle_notify(notify, notify_saddr, notify_daddr, entry);

out_err:

    /* hip_put_ha(entry); */

    return err;
}

/**
 * Receive BOS packet.
 *
 * This function is called when a BOS packet is received. We add the
 * received HIT and HOST_ID to the database.
 *
 * @param bos       a pointer to...
 * @param bos_saddr a pointer to...
 * @param bos_daddr a pointer to...
 * @param entry     a pointer to...
 * @param bos_info  a pointer to...
 * @return          always zero.
 * @todo Check if it is correct to return always zero.
 */
int hip_receive_bos(struct hip_common *bos,
                    struct in6_addr *bos_saddr,
                    struct in6_addr *bos_daddr,
                    hip_ha_t *entry,
                    hip_portpair_t *bos_info)
{
    int err = 0, state = 0;

    _HIP_DEBUG("hip_receive_bos() invoked.\n");

    HIP_IFEL(ipv6_addr_any(&bos->hits), 0,
             "Received NULL sender HIT in BOS.\n");
    HIP_IFEL(!ipv6_addr_any(&bos->hitr), 0,
             "Received non-NULL receiver HIT in BOS.\n");
    HIP_DEBUG("Entered in hip_receive_bos...\n");
    state = entry ? entry->state : HIP_STATE_UNASSOCIATED;

    /** @todo If received BOS packet from already known sender should return
     *  right now */
    HIP_DEBUG("Received BOS packet in state %s\n", hip_state_str(state));
    switch (state) {
    case HIP_STATE_UNASSOCIATED:
    case HIP_STATE_I1_SENT:
    case HIP_STATE_I2_SENT:
        /* Possibly no state created yet */
        err = hip_handle_bos(bos, bos_saddr, bos_daddr, entry, bos_info);
        break;
    case HIP_STATE_R2_SENT:
    case HIP_STATE_ESTABLISHED:
        HIP_DEBUG("BOS not handled in state %s\n", hip_state_str(state));
        break;
    default:
        HIP_IFEL(1, 0, "Internal state (%d) is incorrect\n", state);
    }

    /* hip_put_ha(entry); */
out_err:
    return err;
}

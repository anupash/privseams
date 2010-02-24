/**
 * @file firewall/esp_prot_light_update.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Provides messaging functionality required for HHL-based anchor
 * element updates.
 *
 * @brief Messaging required for HHL-based anchor element updates
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "esp_prot_light_update.h"
#include "esp_prot_anchordb.h"
#include "lib/core/builder.h"

/**
 * sends an ack for a received HHL-based update message
 *
 * @param entry host association for which the ack should be send
 * @param src_addr src ip address
 * @param dst_addr dst ip address
 * @param spi IPsec spi of the direction
 * @return 0 in case of succcess, -1 otherwise
 */
static int esp_prot_send_light_ack(hip_ha_t *entry, const in6_addr_t *src_addr,
                                   const in6_addr_t *dst_addr, const uint32_t spi)
{
    hip_common_t *light_ack = NULL;
    uint16_t mask           = 0;
    int err                 = 0;

    HIP_IFEL(!(light_ack = hip_msg_alloc()), -ENOMEM,
             "failed to allocate memory\n");

    hip_build_network_hdr(light_ack,
                          HIP_LUPDATE,
                          mask,
                          &entry->hit_our,
                          &entry->hit_peer);

    /* Add ESP_INFO */
    HIP_IFEL(hip_build_param_esp_info(light_ack, entry->current_keymat_index,
                                      spi, spi), -1, "Building of ESP_INFO failed\n");

    /* Add ACK */
    HIP_IFEL(hip_build_param_ack(light_ack, entry->light_update_id_in), -1,
             "Building of ACK failed\n");

    /* Add HMAC */
    HIP_IFEL(hip_build_param_hmac_contents(light_ack, &entry->hip_hmac_out), -1,
             "Building of HMAC failed\n");

    HIP_IFEL(hip_send_pkt(src_addr,
                          dst_addr,
                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                          entry->peer_udp_port,
                          light_ack,
                          entry,
                          0),
             -1,
             "failed to send ANCHOR-UPDATE\n");

out_err:
    return err;
}

/**
 * sends an HHL-based update message
 *
 * @param entry             host association for this connection
 * @param anchor_offset     offset of the anchor in the link tree
 * @param secret            secrets for anchor elements to be sent
 * @param secret_length     length of each secret
 * @param branch_nodes      branch nodes for anchor elements to be sent
 * @param branch_length     length of each branch
 * @return                  0 in case of succcess, -1 otherwise
 */
int esp_prot_send_light_update(hip_ha_t *entry,
                               const int anchor_offset[],
                               unsigned char *secret[MAX_NUM_PARALLEL_HCHAINS],
                               const int secret_length[],
                               unsigned char *branch_nodes[MAX_NUM_PARALLEL_HCHAINS],
                               const int branch_length[])
{
    hip_common_t *light_update = NULL;
    int hash_length            = 0;
    uint16_t mask              = 0;
    int err                    = 0, i;

    HIP_IFEL(!(light_update = hip_msg_alloc()), -ENOMEM,
             "failed to allocate memory\n");

    hip_build_network_hdr(light_update,
                          HIP_LUPDATE,
                          mask,
                          &entry->hit_our,
                          &entry->hit_peer);

    /********************* add SEQ *********************/

    entry->light_update_id_out++;
    HIP_DEBUG("outgoing light UPDATE ID=%u\n", entry->light_update_id_out);

    HIP_IFEL(hip_build_param_seq(light_update, entry->light_update_id_out), -1,
             "building of SEQ param failed\n");

    /********** add ESP-PROT anchor, branch, secret, root **********/

    hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

    for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
        HIP_IFEL(hip_build_param_esp_prot_anchor(light_update,
                                                 entry->esp_prot_transform, &entry->esp_local_anchors[i][0],
                                                 &entry->esp_local_update_anchors[i][0], hash_length, entry->hash_item_length),
                 -1, "building of ESP protection ANCHOR failed\n");
    }

    for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
        HIP_IFEL(hip_build_param_esp_prot_branch(light_update,
                                                 anchor_offset[i], branch_length[i], branch_nodes[i]), -1,
                 "building of ESP BRANCH failed\n");
    }

    for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
        HIP_IFEL(hip_build_param_esp_prot_secret(light_update, secret_length[i], secret[i]),
                 -1, "building of ESP SECRET failed\n");
    }

    for (i = 0; i < esp_prot_num_parallel_hchains; i++) {
        // only send root if the update hchain has got a link_tree
        if (entry->esp_root_length > 0) {
            HIP_IFEL(hip_build_param_esp_prot_root(light_update,
                                                   entry->esp_root_length,
                                                   entry->esp_root[i]),
                     -1,
                     "building of ESP ROOT failed\n");
        }
    }

    /******************** add HMAC **********************/
    HIP_IFEL(hip_build_param_hmac_contents(light_update, &entry->hip_hmac_out), -1,
             "building of HMAC failed\n");

    /* send the packet with retransmission enabled */
    entry->light_update_retrans = 1;

    HIP_IFEL(hip_send_pkt(&entry->our_addr,
                          &entry->peer_addr,
                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                          entry->peer_udp_port,
                          light_update,
                          entry,
                          entry->light_update_retrans),
             -1,
             "failed to send light anchor update\n");

out_err:
    if (err) {
        entry->light_update_retrans = 1;
    }

    if (light_update) {
        free(light_update);
    }

    return err;
}

/**
 * esp_prot_handle_light_update
 *
 * Handles an HHL-based update message
 *
 * @param msg       received hip message
 * @param src_addr  src ip address
 * @param dst_addr  dst ip address
 * @param entry     host association for this connection
 * @return          0 in case of succcess, -1 otherwise
 */
int esp_prot_handle_light_update(const uint32_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx)
{
    struct hip_seq *seq = NULL;
    struct hip_ack *ack = NULL;
    uint32_t seq_no     = 0;
    uint32_t ack_no     = 0;
    uint32_t spi        = 0;
    int err             = 0;

    HIP_IFEL(hip_verify_packet_hmac(ctx->msg, &(ctx->hadb_entry)->hip_hmac_in),
             -1,
             "HMAC validation on UPDATE failed.\n");

    ack = hip_get_param(ctx->msg, HIP_PARAM_ACK);
    seq = hip_get_param(ctx->msg, HIP_PARAM_SEQ);

    if (seq != NULL) {
        /********** SEQ ***********/
        seq_no = ntohl(seq->update_id);

        HIP_DEBUG("SEQ parameter found with update ID: %u\n", seq_no);
        HIP_DEBUG("previous incoming update id=%u\n", ctx->hadb_entry->light_update_id_in);

        if (seq_no < ctx->hadb_entry->light_update_id_in) {
            HIP_DEBUG("old SEQ, dropping...\n");

            err = -EINVAL;
            goto out_err;
        } else if (seq_no == ctx->hadb_entry->light_update_id_in) {
            HIP_DEBUG("retransmitted UPDATE packet (?), continuing\n");
        } else {
            HIP_DEBUG("new SEQ, storing...\n");
            ctx->hadb_entry->light_update_id_in = seq_no;
        }

        /********** ANCHOR ***********/
        HIP_IFEL(esp_prot_update_handle_anchor(ctx->msg,
                                               ctx->hadb_entry,
                                               ctx->src_addr,
                                               ctx->dst_addr,
                                               &spi),
                 -1, "failed to handle anchors\n");

        // send ACK
        esp_prot_send_light_ack(ctx->hadb_entry,
                                ctx->dst_addr,
                                ctx->src_addr,
                                spi);
    } else if (ack != NULL) {
        /********** ACK ***********/
        ack_no = ntohl(ack->peer_update_id);

        HIP_DEBUG("ACK found with peer update ID: %u\n", ack_no);

        HIP_IFEL(ack_no != ctx->hadb_entry->light_update_id_out, -1,
                 "received non-matching ACK\n");

        // stop retransmission
        ctx->hadb_entry->light_update_retrans = 0;

        // notify sadb about next anchor
        HIP_IFEL(hip_add_sa(ctx->dst_addr,
                            ctx->src_addr,
                            &(ctx->hadb_entry)->hit_our,
                            &(ctx->hadb_entry)->hit_peer,
                            ctx->hadb_entry->spi_outbound_new,
                            ctx->hadb_entry->esp_transform,
                            &(ctx->hadb_entry)->esp_out,
                            &(ctx->hadb_entry)->auth_out,
                            0,
                            HIP_SPI_DIRECTION_OUT,
                            1,
                            ctx->hadb_entry),
                 -1,
                 "failed to notify sadb about next anchor\n");
    } else {
        HIP_ERROR("light update message received, but no SEQ or ACK found\n");

        err = -1;
    }

out_err:
    return err;
}

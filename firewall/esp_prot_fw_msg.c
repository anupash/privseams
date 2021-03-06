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
 * This implements the communication with the hipd.
 *
 * @brief TPA and HHL-specific inter-process communication with the hipd
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hashchain.h"
#include "lib/core/hashchain_store.h"
#include "lib/core/hashtree.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/linkedlist.h"
#include "lib/core/message.h"
#include "lib/core/protodefs.h"
#include "esp_prot_api.h"
#include "user_ipsec_sadb.h"
#include "esp_prot_fw_msg.h"

#include <netinet/udp.h>

#include "firewall.h"


/** creates the anchor element message
 *
 * @param   hcstore the BEX store
 * @param   use_hash_trees indicates whether hash chains or hash trees are stored
 * @return  the message on success, NULL on error
 *
 * @note this will only consider the first hchain item in each shelf, as only
 *       this should be set up for the store containing the hchains for the BEX
 * @note the created message contains hash_length and anchors for each transform
 */
static struct hip_common *create_bex_store_update_msg(struct hchain_store *hcstore,
                                                      const int use_hash_trees)
{
    struct hip_common   *msg         = NULL;
    struct esp_prot_tfm *transform   = NULL;
    struct hash_chain   *hchain      = NULL;
    struct hash_tree    *htree       = NULL;
    unsigned char       *anchor      = NULL;
    unsigned             j           = 0;
    uint8_t              i           = 0;
    int                  hash_length = 0, num_hchains = 0, err = 0, hash_item_length = 0;

    HIP_ASSERT(hcstore != NULL);

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "failed to allocate memory\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_BEX_STORE_UPDATE, 0), -1,
             "build hdr failed\n");

    // first add hash_length and num_hchain for each transform
    for (i = 1; i <= NUM_TRANSFORMS; i++) {
        HIP_IFEL(!(transform = esp_prot_resolve_transform(token_transform)), -1,
                 "failed to resolve transform\n");

        HIP_IFEL((hash_length = esp_prot_get_hash_length(token_transform)) <= 0,
                 -1, "hash_length <= 0, expecting something bigger\n");

        HIP_IFEL((num_hchains = hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
                                                [transform->hash_length_id].
                                                hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1])) <= 0, -1,
                 "num_hchains <= 0, expecting something higher\n");

        // tell hipd about transform
        HIP_IFEL(hip_build_param_contents(msg, &token_transform,
                                          HIP_PARAM_UINT, sizeof(uint8_t)), -1,
                 "build param contents failed\n");
        HIP_DEBUG("added esp_transform: %u\n", token_transform);

        // add num_hchains for this transform, needed on receiver side
        HIP_IFEL(hip_build_param_contents(msg, &num_hchains,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");
        HIP_DEBUG("added num_hchains: %i\n", num_hchains);

        // add the hash_length for this transform, needed on receiver side
        HIP_IFEL(hip_build_param_contents(msg, &hash_length,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");
        HIP_DEBUG("added hash_length: %i\n", hash_length);
    }

    // now add the hchain anchors
    for (i = 1; i <= NUM_TRANSFORMS; i++) {
        HIP_IFEL(!(transform = esp_prot_resolve_transform(token_transform)), -1,
                 "failed to resolve transform\n");

        HIP_IFEL((hash_length = esp_prot_get_hash_length(token_transform)) <= 0,
                 -1, "hash_length <= 0, expecting something bigger\n");

        // ensure correct boundaries
        HIP_ASSERT(transform->hash_func_id >= 0
                   && transform->hash_func_id < NUM_HASH_FUNCTIONS);
        HIP_ASSERT(transform->hash_length_id >= 0
                   && transform->hash_length_id < NUM_HASH_LENGTHS);

        // add anchor with this transform
        for (j = 0; j < hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
                                        [transform->hash_length_id].
                                        hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1]); j++) {
            if (use_hash_trees) {
                HIP_IFEL(!(htree = hip_ll_get(&hcstore->hchain_shelves[transform->hash_func_id]
                                              [transform->hash_length_id].hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1],
                                              j)),
                         -1, "failed to retrieve htree\n");

                anchor           = htree->root;
                hash_item_length = htree->num_data_blocks;
            } else {
                HIP_IFEL(!(hchain = hip_ll_get(&hcstore->hchain_shelves[transform->hash_func_id]
                                               [transform->hash_length_id].hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1], j)),
                         -1, "failed to retrieve hchain\n");

                anchor           = hchain_get_anchor(hchain);
                hash_item_length = hchain->hchain_length;
            }

            HIP_IFEL(hip_build_param_contents(msg, anchor,
                                              HIP_PARAM_HCHAIN_ANCHOR, hash_length),
                     -1, "build param contents failed\n");
            HIP_HEXDUMP("added anchor: ", anchor, hash_length);

            // also send the hchain/htree length for each item
            HIP_IFEL(hip_build_param_contents(msg, &hash_item_length,
                                              HIP_PARAM_INT, sizeof(int)),
                     -1, "build param contents failed\n");
            HIP_DEBUG("added hash_item_length: %i\n", hash_item_length);
        }
    }

out_err:
    if (err) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

/**
 * Sends the preferred transform to hipd implicitely turning on
 * the esp protection extension there
 *
 * @param   activate 1 to activate, 0 to deactivate the extension in the hipd
 * @return  0 on success, -1 on error
 */
int send_esp_prot_to_hipd(const int activate)
{
    struct hip_common *msg            = NULL;
    int                num_transforms = 0;
    int                err            = 0, i;
    uint8_t            transform      = 0;

    HIP_ASSERT(activate >= 0);

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "failed to allocate memory\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_ESP_PROT_TFM, 0), -1,
             "build hdr failed\n");

    if (activate > 0) {
        /*** activation case ***/
        HIP_DEBUG("sending preferred esp prot transforms to hipd...\n");

        // all "in use" transforms + UNUSED
        num_transforms = NUM_TRANSFORMS + 1;

        HIP_DEBUG("adding activate: %i\n", activate);
        HIP_IFEL(hip_build_param_contents(msg, &activate,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
        HIP_IFEL(hip_build_param_contents(msg, &num_transforms,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("adding num_parallel_hchains: %i\n", num_parallel_hchains);
        HIP_IFEL(hip_build_param_contents(msg, &num_parallel_hchains,
                                          HIP_PARAM_INT, sizeof(long)), -1,
                 "build param contents failed\n");

        for (i = 0; i < num_transforms; i++) {
            HIP_DEBUG("adding transform %i: %u\n", i + 1, token_transform);
            HIP_IFEL(hip_build_param_contents(msg, &token_transform,
                                              HIP_PARAM_ESP_PROT_TFM,
                                              sizeof(uint8_t)), -1,
                     "build param contents failed\n");
        }
    } else {
        /*** deactivation case ***/
        HIP_DEBUG("sending esp prot transform ESP_PROT_TFM_UNUSED to hipd...\n");

        // we are only sending ESP_PROT_TFM_UNUSED
        num_transforms = 1;
        transform      = ESP_PROT_TFM_UNUSED;

        HIP_DEBUG("adding activate: %i\n", activate);
        HIP_IFEL(hip_build_param_contents(msg, &activate,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
        HIP_IFEL(hip_build_param_contents(msg, &num_transforms,
                                          HIP_PARAM_INT, sizeof(int)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("adding num_parallel_hchains: %i\n", num_parallel_hchains);
        HIP_IFEL(hip_build_param_contents(msg, &num_parallel_hchains,
                                          HIP_PARAM_INT, sizeof(long)), -1,
                 "build param contents failed\n");

        HIP_DEBUG("adding transform ESP_PROT_TFM_UNUSED: %u\n", transform);
        HIP_IFEL(hip_build_param_contents(msg, &transform,
                                          HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
                 "build param contents failed\n");
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
             "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

    HIP_DEBUG("send_recv msg succeeded\n");

out_err:
    free(msg);
    return err;
}

/** sends a list of all available anchor elements in the BEX store
 * to the hipd
 *
 * @param   hcstore the BEX store
 * @param   use_hash_trees indicates whether hash chains or hash trees are stored
 * @return  0 on success, -1 on error
 */
int send_bex_store_update_to_hipd(struct hchain_store *hcstore,
                                  const int use_hash_trees)
{
    struct hip_common *msg = NULL;
    int                err = 0;

    HIP_ASSERT(hcstore != NULL);

    HIP_DEBUG("sending bex-store update to hipd...\n");

    HIP_IFEL(!(msg = create_bex_store_update_msg(hcstore, use_hash_trees)),
             -1, "failed to create bex store anchors update message\n");

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1, "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

    HIP_DEBUG("send_recv msg succeeded\n");

out_err:
    free(msg);
    return err;
}

/**
 * Invokes an UPDATE message containing an anchor element as a hook to
 * next hash structure to be used when the active one depletes
 *
 * @param   entry the sadb entry for the outbound direction
 * @param   anchors the anchor elements to be sent
 * @param   hash_item_length length of the respective hash item
 * @param   soft_update indicates if HHL-based updates should be used
 * @param   anchor_offset the offset of the anchor element in the link tree
 * @param   link_trees the link trees for the anchor elements, in case of HHL
 * @return  0 on success, -1 on error
 */
int send_trigger_update_to_hipd(const struct hip_sa_entry *entry,
                                const unsigned char *anchors[MAX_NUM_PARALLEL_HCHAINS],
                                const int hash_item_length,
                                const int soft_update,
                                const int *anchor_offset,
                                struct hash_tree *link_trees[MAX_NUM_PARALLEL_HCHAINS])
{
    int                  err           = 0;
    int                  i             = 0;
    struct hip_common   *msg           = NULL;
    int                  hash_length   = 0;
    struct hash_chain   *hchain        = NULL;
    struct hash_tree    *htree         = NULL;
    struct hash_tree    *link_tree     = NULL;
    int                  secret_length = 0;
    int                  branch_length = 0;
    int                  root_length   = 0;
    const unsigned char *secret        = NULL;
    unsigned char       *branch_nodes  = NULL;
    const unsigned char *root          = NULL;

    HIP_ASSERT(entry != NULL);

    HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
             -1, "error or tried to resolve UNUSED transform\n");

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "failed to allocate memory\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_TRIGGER_UPDATE, 0), -1,
             "build hdr failed\n");

    HIP_DEBUG_HIT("src_hit", &entry->inner_src_addr);
    HIP_IFEL(hip_build_param_contents(msg, &entry->inner_src_addr,
                                      HIP_PARAM_HIT, sizeof(struct in6_addr)),
             -1, "build param contents failed\n");

    HIP_DEBUG_HIT("dst_hit", &entry->inner_dst_addr);
    HIP_IFEL(hip_build_param_contents(msg, &entry->inner_dst_addr,
                                      HIP_PARAM_HIT, sizeof(struct in6_addr)),
             -1, "build param contents failed\n");

    HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
    HIP_IFEL(hip_build_param_contents(msg, &entry->esp_prot_transform,
                                      HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)),
             -1, "build param contents failed\n");

    // also send the hchain/htree length for all update items
    HIP_IFEL(hip_build_param_contents(msg, &hash_item_length, HIP_PARAM_INT,
                                      sizeof(int)), -1, "build param contents failed\n");
    HIP_DEBUG("added hash_item_length: %i\n", hash_item_length);

    HIP_DEBUG("num_parallel_hchains: %u\n", num_parallel_hchains);
    HIP_IFEL(hip_build_param_contents(msg, &num_parallel_hchains,
                                      HIP_PARAM_INT, sizeof(long)), -1,
             "build param contents failed\n");

    // add update anchors
    for (i = 0; i < num_parallel_hchains; i++) {
        HIP_HEXDUMP("anchor: ", anchors[i], hash_length);
        HIP_IFEL(hip_build_param_contents(msg, anchors[i],
                                          HIP_PARAM_HCHAIN_ANCHOR,
                                          hash_length), -1,
                 "build param contents failed\n");
    }

    // now transmit root for each next hash item for tree-based updates, if available
    for (i = 0; i < num_parallel_hchains; i++) {
        if (entry->esp_prot_transform == ESP_PROT_TFM_TREE) {
            htree     = entry->next_hash_items[i];
            link_tree = htree->link_tree;
        } else {
            hchain    = entry->next_hash_items[i];
            link_tree = hchain->link_tree;
        }

        if (link_tree) {
            /* if the next_hchain has got a link_tree, we need its root for
             * the verification of the next_hchain's elements */
            root = htree_get_root(link_tree, &root_length);
        }

        // only transmit root length once
        if (i == 0) {
            HIP_DEBUG("root_length: %i\n", root_length);
            HIP_IFEL(hip_build_param_contents(msg, &root_length,
                                              HIP_PARAM_INT,
                                              sizeof(int)), -1,
                     "build param contents failed\n");
        }

        if (root) {
            HIP_HEXDUMP("root: ", root, root_length);
            HIP_IFEL(hip_build_param_contents(msg, root,
                                              HIP_PARAM_ROOT, root_length), -1,
                     "build param contents failed\n");
        }
    }

    HIP_DEBUG("soft_update: %i\n", soft_update);
    HIP_IFEL(hip_build_param_contents(msg, &soft_update, HIP_PARAM_INT,
                                      sizeof(int)), -1,
             "build param contents failed\n");

    if (soft_update) {
        for (i = 0; i < num_parallel_hchains; i++) {
            secret = htree_get_secret(link_trees[i],
                                      anchor_offset[i], &secret_length);
            HIP_IFEL(!(branch_nodes = htree_get_branch(link_trees[i],
                                                       anchor_offset[i], NULL,
                                                       &branch_length)), -1,
                     "failed to get branch nodes\n");

            HIP_DEBUG("anchor_offset: %i\n", anchor_offset[i]);
            HIP_IFEL(hip_build_param_contents(msg, &anchor_offset[i],
                                              HIP_PARAM_INT,
                                              sizeof(int)), -1,
                     "build param contents failed\n");

            HIP_DEBUG("secret_length: %i\n", secret_length);
            HIP_IFEL(hip_build_param_contents(msg, &secret_length,
                                              HIP_PARAM_INT,
                                              sizeof(int)), -1,
                     "build param contents failed\n");

            HIP_DEBUG("branch_length: %i\n", branch_length);
            HIP_IFEL(hip_build_param_contents(msg, &branch_length,
                                              HIP_PARAM_INT,
                                              sizeof(int)), -1,
                     "build param contents failed\n");

            HIP_HEXDUMP("secret: ", secret, secret_length);
            HIP_IFEL(hip_build_param_contents(msg, secret,
                                              HIP_PARAM_SECRET,
                                              secret_length), -1,
                     "build param contents failed\n");

            HIP_HEXDUMP("branch_nodes: ", branch_nodes, branch_length);
            HIP_IFEL(hip_build_param_contents(msg, branch_nodes,
                                              HIP_PARAM_BRANCH_NODES,
                                              branch_length), -1,
                     "build param contents failed\n");
        }
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
             "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

    HIP_DEBUG("send_recv msg succeeded\n");

out_err:
    free(msg);
    free(branch_nodes);
    return err;
}

/**
 * Notifies the hipd about an anchor change in the hipfw
 *
 * @param   entry the sadb entry for the outbound direction
 * @return  0 on success, -1 on error, 1 for inbound sadb entry
 */
int send_anchor_change_to_hipd(const struct hip_sa_entry *entry)
{
    int                err         = 0;
    int                hash_length = 0;
    long               i           = 0;
    unsigned char     *anchor      = NULL;
    struct hip_common *msg         = NULL;
    struct hash_chain *hchain      = NULL;
    struct hash_tree  *htree       = NULL;

    HIP_ASSERT(entry != NULL);
    HIP_ASSERT(entry->direction == HIP_SPI_DIRECTION_OUT);

    HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
             -1, "error or tried to resolve UNUSED transform\n");

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "failed to allocate memory\n");

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_ANCHOR_CHANGE, 0), -1,
             "build hdr failed\n");

    HIP_DEBUG_HIT("src_hit", &entry->inner_src_addr);
    HIP_IFEL(hip_build_param_contents(msg, &entry->inner_src_addr,
                                      HIP_PARAM_HIT, sizeof(struct in6_addr)),
             -1, "build param contents failed\n");

    HIP_DEBUG_HIT("dst_hit", &entry->inner_dst_addr);
    HIP_IFEL(hip_build_param_contents(msg, &entry->inner_dst_addr,
                                      HIP_PARAM_HIT, sizeof(struct in6_addr)),
             -1, "build param contents failed\n");

    HIP_DEBUG("direction: %i\n", entry->direction);
    HIP_IFEL(hip_build_param_contents(msg, &entry->direction,
                                      HIP_PARAM_INT, sizeof(int)), -1,
             "build param contents failed\n");

    HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
    HIP_IFEL(hip_build_param_contents(msg, &entry->esp_prot_transform,
                                      HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)),
             -1, "build param contents failed\n");

    HIP_DEBUG("esp_prot_num_parallel_hchains: %i\n", num_parallel_hchains);
    HIP_IFEL(hip_build_param_contents(msg, &num_parallel_hchains,
                                      HIP_PARAM_INT, sizeof(int)), -1,
             "build param contents failed\n");

    for (i = 0; i < num_parallel_hchains; i++) {
        // the anchor change has already occurred on fw-side
        if (entry->esp_prot_transform == ESP_PROT_TFM_TREE) {
            htree  = entry->active_hash_items[i];
            anchor = htree->root;
        } else {
            hchain = entry->active_hash_items[i];
            anchor = hchain_get_anchor(hchain);
        }

        HIP_HEXDUMP("anchor: ", anchor, hash_length);
        HIP_IFEL(hip_build_param_contents(msg, anchor,
                                          HIP_PARAM_HCHAIN_ANCHOR, hash_length),
                 -1, "build param contents failed\n");
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
             "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

    HIP_DEBUG("send_recv msg succeeded\n");

out_err:
    free(msg);
    return err;
}

/** handles the TPA specific parts in the setup of new IPsec SAs
 *
 * @param   msg the HIP message
 * @param   esp_prot_transform the TPA transform (return value)
 * @param   num_anchors number of anchor in the array
 * @param   esp_prot_anchors array storing the anchors
 * @param   hash_item_length length of the employed hash structure at the peer (return value)
 * @return  0 on success, -1 on error
 */
int esp_prot_handle_sa_add_request(const struct hip_common *msg,
                                   uint8_t *esp_prot_transform,
                                   uint16_t *num_anchors,
                                   unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                                   uint32_t *hash_item_length)
{
    const struct hip_tlv_common *param       = NULL;
    int                          hash_length = 0, err = 0;
    const unsigned char         *anchor      = NULL;
    uint16_t                     i;
    *num_anchors        = 0;
    *esp_prot_transform = 0;

    HIP_ASSERT(msg != NULL);
    HIP_ASSERT(esp_prot_transform != NULL);
    HIP_ASSERT(num_anchors != NULL);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM)),
             -1, "esp prot transform missing\n");
    *esp_prot_transform = *((const uint8_t *) hip_get_param_contents_direct(param));
    HIP_DEBUG("esp protection transform is %u\n", *esp_prot_transform);

    // this parameter is only included, if the esp extension is used
    if (*esp_prot_transform > ESP_PROT_TFM_UNUSED) {
        // retrieve hash length for the received transform
        HIP_IFEL((hash_length = esp_prot_get_hash_length(*esp_prot_transform)) <= 0,
                 -1, "error or tried to resolve UNUSED transform\n");

        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ITEM_LENGTH)),
                 -1, "transform suggests hash_item_length, but it is NOT included in msg\n");
        *hash_item_length = *((const uint32_t *) hip_get_param_contents_direct(param));
        HIP_DEBUG("esp protection item length: %u\n", *hash_item_length);

        HIP_IFEL(!(param = hip_get_next_param(msg, param)),
                 -1, "transform suggests num_anchors, but it is NOT included in msg\n");
        *num_anchors = *((const uint16_t *) hip_get_param_contents_direct(param));
        HIP_DEBUG("esp protection number of transferred anchors: %u\n", *num_anchors);

        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR)),
                 -1, "transform suggests anchor, but it is NOT included in msg\n");

        if (*num_anchors <= num_parallel_hchains) {
            for (i = 0; i < *num_anchors; i++) {
                anchor = hip_get_param_contents_direct(param);

                // store the current anchor
                memcpy(&esp_prot_anchors[i][0], anchor, hash_length);
                HIP_HEXDUMP("esp protection anchor is ", &esp_prot_anchors[i][0], hash_length);

                HIP_IFEL(!(param = hip_get_next_param(msg, param)),
                         -1, "awaiting further anchor, but it is NOT included in msg\n");
            }
        }
    }

out_err:
    if (err) {
        *esp_prot_transform = 0;
        *num_anchors        = 0;
    }

    return err;
}

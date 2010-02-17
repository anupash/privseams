/**
 * @file firewall/esp_prot_conntrack.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * API for the connection tracking for the ESP protection extension.
 *
 * @brief Connection tracking extension needed for the ESP protection extension
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef ESP_PROT_CONNTRACK_H_
#define ESP_PROT_CONNTRACK_H_

#include "lib/core/protodefs.h"
#include "conntrack.h"

typedef struct esp_prot_conntrack_tfm {
    hash_function_t hash_function;     /* pointer to the hash function */
    int             hash_length; /* hash length for this transform */
    int             is_used; /* needed as complete transform array is initialized */
} esp_prot_conntrack_tfm_t;

extern int window_size;

int esp_prot_conntrack_init(void);
int esp_prot_conntrack_uninit(void);
int esp_prot_conntrack_R1_tfms(const struct hip_common *common,
                               const struct tuple *tuple);
int esp_prot_conntrack_I2_anchor(const struct hip_common *common,
                                 struct tuple *tuple);
struct esp_tuple *esp_prot_conntrack_R2_esp_tuple(const SList *other_dir_esps);
int esp_prot_conntrack_R2_anchor(const struct hip_common *common,
                                 const struct tuple *tuple);
int esp_prot_conntrack_update(const hip_common_t *update,
                              const struct tuple *tuple);
int esp_prot_conntrack_remove_state(struct esp_tuple *esp_tuple);
int esp_prot_conntrack_lupdate(const struct in6_addr *ip6_src,
                               const struct in6_addr *ip6_dst,
                               const struct hip_common *common,
                               struct tuple *tuple);
int esp_prot_conntrack_verify(const hip_fw_context_t *ctx,
                              struct esp_tuple *esp_tuple);

#endif /* ESP_PROT_CONNTRACK_H_ */

/**
 * @file
 *
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
 *
 * API for the connection tracking for the ESP protection extension.
 *
 * @brief Connection tracking extension needed for the ESP protection extension
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_FIREWALL_ESP_PROT_CONNTRACK_H
#define HIP_FIREWALL_ESP_PROT_CONNTRACK_H

#define _BSD_SOURCE

#include "lib/core/protodefs.h"
#include "firewall_defines.h"

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
int esp_prot_conntrack_lupdate(const struct hip_common *common,
                               struct tuple *tuple,
                               const hip_fw_context_t *ctx);
int esp_prot_conntrack_verify(const hip_fw_context_t *ctx,
                              struct esp_tuple *esp_tuple);

#endif /* HIP_FIREWALL_ESP_PROT_CONNTRACK_H */

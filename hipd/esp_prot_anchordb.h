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
 * API to store anchor elements to be used as references to
 * the hash structures stored in the BEX store of the hipfw. The elements
 * maintained here should be used for the insertion of new anchor elements
 * during HIP BEX.
 *
 * @brief Stores anchor elements to be used for the esp protection
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPD_ESP_PROT_ANCHORDB_H
#define HIP_HIPD_ESP_PROT_ANCHORDB_H

#include <stdint.h>

#include "lib/core/protodefs.h"

void anchor_db_init(void);
void anchor_db_uninit(void);
int anchor_db_update(const struct hip_common *msg);
int anchor_db_get_num_anchors(const uint8_t transform);
unsigned char *anchor_db_get_anchor(const uint8_t transform);
int anchor_db_get_anchor_length(const uint8_t transform);
int anchor_db_get_hash_item_length(const uint8_t transform);

#endif /*HIP_HIPD_ESP_PROT_ANCHORDB_H*/

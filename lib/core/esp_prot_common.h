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
 * API for the  functionality for the ESP protection in
 * hipd and hipfw. It also defines necessary TPA parameters used by both
 * hipfw and hipd.
 *
 * @brief Provides common functionality for the ESP protection in hipd and hipfw
 */

#ifndef HIP_LIB_CORE_ESP_PROT_COMMON_H
#define HIP_LIB_CORE_ESP_PROT_COMMON_H

#include <stdint.h>

/* the maximum numbers for arrays used for the different modes */
#define MAX_NUM_TRANSFORMS                      10
#define MAX_NUM_PARALLEL_HCHAINS                10
#define MAX_HTREE_DEPTH                         20
#define MAX_RING_BUFFER_SIZE                    128

/* this is a special purpose transform representing no hash token to be used */
#define ESP_PROT_TFM_UNUSED                     0
#define ESP_PROT_TFM_PLAIN                      1
#define ESP_PROT_TFM_PARALLEL                   2
#define ESP_PROT_TFM_CUMULATIVE                 3
#define ESP_PROT_TFM_PARA_CUMUL                 4
#define ESP_PROT_TFM_TREE                       5
#define ESP_PROT_TFM_TREE_CHAIN                 6

int esp_prot_check_transform(const int num_transforms,
                             const uint8_t *preferred_transforms,
                             const uint8_t transform);

#endif /* HIP_LIB_CORE_ESP_PROT_COMMON_H */

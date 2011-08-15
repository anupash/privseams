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
 * This implementation provides functionality for the ESP protection in
 * hipd and hipfw. It also defines necessary TPA parameters used by both
 * hipfw and hipd.
 *
 * @brief Provides common functionality for the ESP protection in hipd and hipfw
 */

#include "esp_prot_common.h"
#include "debug.h"

/**
 * Checks if the passed transform is one of our locally preferred transforms
 *
 * @param       num_transforms amount of transforms contained in the array
 * @param       preferred_transforms the transforms against which should be checked
 * @param       transform the ESP protection extension transform to be checked
 * @return      index in the preferred_transforms array, -1 if no match found
 */
int esp_prot_check_transform(const int num_transforms,
                             const uint8_t *preferred_transforms,
                             const uint8_t transform)
{
    int err = -1, i;

    // check if local preferred transforms contain passed transform
    for (i = 0; i < num_transforms; i++) {
        if (preferred_transforms[i] == transform) {
            HIP_DEBUG("transform found in preferred transforms\n");

            err = i;
            goto out_err;
        }
    }

    HIP_DEBUG("transform NOT found in local preferred transforms\n");

out_err:
    return err;
}

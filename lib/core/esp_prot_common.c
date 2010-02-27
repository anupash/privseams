/**
 * @file firewall/esp_prot_common.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This implementation provides functionality for the ESP protection in
 * hipd and hipfw. It also defines necessary TPA parameters used by both
 * hipfw and hipd.
 *
 * @brief Provides common functionality for the ESP protection in hipd and hipfw
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
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

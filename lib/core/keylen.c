/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Various key length calculation functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include "keylen.h"
#include "protodefs.h"
#include "debug.h"

/**
 * get encryption key length for a transform
 *
 * @param tid transform
 * @return the encryption key length of the chosen transform,
 *         or negative  on error.
 */
int hip_enc_key_length(int tid)
{
    int ret = -1;

    switch (tid) {
    case HIP_ESP_AES_SHA1:
        ret = 16;
        break;
    case HIP_ESP_3DES_SHA1:
        ret = 24;
        break;
    case HIP_ESP_NULL_SHA1:
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}

/**
 * get hmac key length of a transform
 *
 * @param tid transform
 * @return the encryption key length based of the chosen transform,
 *         or negative  on error.
 */
int hip_hmac_key_length(int tid)
{
    int ret = -1;
    switch (tid) {
    case HIP_ESP_AES_SHA1:
    case HIP_ESP_3DES_SHA1:
    case HIP_ESP_NULL_SHA1:
        ret = 20;
        break;
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}


/**
 * get authentication key length for an ESP transform
 *
 * @param tid transform
 * @return the authentication key length for the chosen transform.
 * or negative on error
 */
int hip_auth_key_length_esp(int tid)
{
    int ret = -1;

    switch (tid) {
    case HIP_ESP_AES_SHA1:
    case HIP_ESP_NULL_SHA1:
    case HIP_ESP_3DES_SHA1:
        ret = 20;
        break;
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}


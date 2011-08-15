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
 * @brief Various key length calculation functions
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

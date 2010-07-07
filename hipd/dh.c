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
 * @brief Diffie-Hellman wrappers for HIP
 *
 * @author Mika Kousa <mkousa@iki.fi>
 * @author Kristian Slavov <ksl@iki.fi>
 * @author Tobias Heer <heer@tobibox.de>
 */

#include <stdint.h>
#include <sys/types.h>
#include <openssl/ossl_typ.h>

#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "dh.h"

DH *dh_table[HIP_MAX_DH_GROUP_ID] = {0};

/**
 * insert the current DH-key into the buffer
 *
 * If a DH-key does not exist, we will create one.
 * @return >0 if ok, -1 if errors
 */
int hip_insert_dh(uint8_t *buffer, int bufsize, int group_id)
{
    int res;
    DH *tmp;

    /*
     * First check that we have the key available.
     * Then encode it into the buffer
     */

    if (dh_table[group_id] == NULL) {
        tmp                = hip_generate_dh_key(group_id);

        dh_table[group_id] = tmp;

        if (dh_table[group_id] == NULL) {
            HIP_ERROR("DH key %d not found and could not create it\n",
                      group_id);
            return -1;
        }
    }

    tmp = dh_table[group_id];

    res = hip_encode_dh_publickey(tmp, buffer, bufsize);
    if (res < 0) {
        HIP_ERROR("Encoding error\n");
        res = -3;
        goto err_free;
    }

err_free:
    return res;
}

/**
 * create a shared secret based on the public key of the peer
 * (passed as an argument) and own DH private key (created beforehand).
 *
 * @param public_value Peer's Diffie-Hellman public key
 * @param group_id the Diffie-Hellman group ID
 * @param len the length of the public value
 * @param buffer Buffer that holds enough space for the shared secret.
 * @param bufsize size of the buffer
 *
 * @return the length of the shared secret in octets if successful,
 * or -1 if an error occured.
 */
int hip_calculate_shared_secret(uint8_t *public_value,
                                uint8_t group_id,
                                signed int len,
                                unsigned char *buffer,
                                int bufsize)
{
    int err = 0;
    DH *tmp;

    /*
     * First check that we have the key available.
     * Then encode it into the buffer
     */

    if (dh_table[group_id] == NULL) {
        tmp                = hip_generate_dh_key(group_id);
        dh_table[group_id] = tmp;

        if (dh_table[group_id] == NULL) {
            HIP_ERROR("Unsupported DH group: %d\n", group_id);
            return -1;
        }
    }

    err = hip_gen_dh_shared_key(dh_table[group_id], public_value,
                                len, buffer, bufsize);
    if (err < 0) {
        HIP_ERROR("Could not create shared secret\n");
        return -1;
    }

    return err;
}

/**
 * regenerate Diffie-Hellman keys for HIP
 * @param bitmask Mask of groups to generate.
 *
 * @note Use only this function to generate DH keys.
 */
static void hip_regen_dh_keys(uint32_t bitmask)
{
    DH *tmp, *okey;
    int maxmask, i;
    int cnt = 0;

    /* if MAX_DH_GROUP_ID = 4 --> maxmask = 0...01111 */
    maxmask  = (1 << (HIP_MAX_DH_GROUP_ID + 1)) - 1;
    bitmask &= maxmask;

    for (i = 1; i <= HIP_MAX_DH_GROUP_ID; i++) {
        if (bitmask & (1 << i)) {
            tmp = hip_generate_dh_key(i);
            if (!tmp) {
                HIP_INFO("Error while generating group: %d\n", i);
                continue;
            }

            okey        = dh_table[i];
            dh_table[i] = tmp;

            hip_free_dh(okey);

            cnt++;

            HIP_DEBUG("DH key for group %d generated\n", i);
        }
    }
    HIP_DEBUG("%d keys generated\n", cnt);
}

/**
 * uninitialize precreated DH structures
 */
void hip_dh_uninit(void)
{
    int i;
    for (i = 1; i < HIP_MAX_DH_GROUP_ID; i++) {
        if (dh_table[i] != NULL) {
            hip_free_dh(dh_table[i]);
            dh_table[i] = NULL;
        }
    }
}

/**
 * initialize D-H cipher structures
 */
int hip_init_cipher(void)
{
    uint32_t supported_groups;

    supported_groups = (1 << HIP_DH_OAKLEY_1 |
                        1 << HIP_DH_OAKLEY_5 |
                        1 << HIP_DH_384);

    HIP_DEBUG("Generating DH keys\n");
    hip_regen_dh_keys(supported_groups);

    return 1;
}

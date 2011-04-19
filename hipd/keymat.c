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
 * This file contains KEYMAT handling functions for HIPL
 *
 * @author Mika Kousa <mkousa#iki.fi>
 * @author Kristian Slavov <ksl#iki.fi>
 * @author Tobias Heer <heer#tobibox.de>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hit.h"
#include "lib/core/ife.h"
#include "keymat.h"

/**
 * allocate and initialize a big enough key material buffer for
 * drawing symmetric keys for HIP and ESP
 *
 * @param kij the diffie hellman session key
 * @param kij_len the length of kij in bytes
 * @param hash_len the length of the used hash
 * @param smaller_hit smaller HIT
 * @param bigger_hit bigger HIT
 * @param I the I value from the puzzle
 * @param J the J value from the puzzle
 * @return the allocated buffer (caller deallocates) or NULL on failure
 */
static uint8_t *hip_create_keymat_buffer(char *kij, size_t kij_len, size_t hash_len,
                                         struct in6_addr *smaller_hit,
                                         struct in6_addr *bigger_hit,
                                         const uint8_t I[PUZZLE_LENGTH],
                                         const uint8_t J[PUZZLE_LENGTH])

{
    uint8_t *buffer = NULL, *cur = NULL;
    size_t   requiredmem;

    if (2 * sizeof(struct in6_addr) < hash_len) {
        requiredmem = kij_len + hash_len + sizeof(uint8_t) + 2 * PUZZLE_LENGTH;
    } else {
        requiredmem = kij_len + 2 * sizeof(struct in6_addr) +
                      sizeof(uint8_t) + 2 * PUZZLE_LENGTH;
    }
    buffer = malloc(requiredmem);
    if (!buffer) {
        HIP_ERROR("Out of memory\n");
        return buffer;
    }

    cur = buffer;
    memcpy(cur, kij, kij_len);
    cur += kij_len;
    memcpy(cur, (uint8_t *) smaller_hit, sizeof(struct in6_addr));
    cur += sizeof(struct in6_addr);
    memcpy(cur, (uint8_t *) bigger_hit, sizeof(struct in6_addr));
    cur += sizeof(struct in6_addr);
    memcpy(cur, I, PUZZLE_LENGTH);
    cur += PUZZLE_LENGTH;
    memcpy(cur, J, PUZZLE_LENGTH);
    cur   += PUZZLE_LENGTH;
    *(cur) = 1;
    cur   += sizeof(uint8_t);

    return buffer;
}

/**
 * update keymat buffer and index after writing material to it
 *
 * @param keybuf a pointer to the key material
 * @param Kold a the seed
 * @param Kold_len length of Kold
 * @param Kij_len length of the Kij
 * @param cnt index value
 */
static void hip_update_keymat_buffer(uint8_t *keybuf, uint8_t *Kold, size_t Kold_len,
                                     size_t Kij_len, uint8_t cnt)
{
    HIP_ASSERT(keybuf);

    memcpy(keybuf + Kij_len, Kold, Kold_len);
    *(keybuf + Kij_len + Kold_len) = cnt;

    return;
}

/**
 * generate HIP keying material
 * @param kij Diffie-Hellman Kij (as in the HIP drafts)
 * @param kij_len the length of the Kij material
 * @param keymat pointer to a keymat structure which will be updated according
 *           to the generated keymaterial
 * @param dstbuf the generated keymaterial will be written here
 * @param dstbuflen the length of the buffer to which to write to
 * @param hit1 source HIT
 * @param hit2 destination HIT
 * @param calc_index where the one byte index is stored (n of Kn)
 * @param I the I value
 * @param J the J value
 *
 */
void hip_make_keymat(char *kij,
                     size_t kij_len,
                     struct hip_keymat_keymat *keymat,
                     void *dstbuf,
                     size_t dstbuflen,
                     struct in6_addr *hit1,
                     struct in6_addr *hit2,
                     uint8_t *calc_index,
                     const uint8_t I[PUZZLE_LENGTH],
                     const uint8_t J[PUZZLE_LENGTH])
{
    int              bufsize;
    uint8_t          index_nbr = 1;
    size_t           dstoffset = 0;
    void            *seedkey;
    struct in6_addr *smaller_hit, *bigger_hit;
    int              hit1_is_bigger;
    uint8_t         *shabuffer = NULL;

    HIP_DEBUG("\n");
    if (dstbuflen < HIP_AH_SHA_LEN) {
        HIP_ERROR("dstbuf is too short (%d)\n", dstbuflen);
        return;
    }

    HIP_ASSERT(sizeof(index_nbr) == HIP_KEYMAT_INDEX_NBR_SIZE);

    hit1_is_bigger = hip_hit_is_bigger(hit1, hit2);

    bigger_hit  =  hit1_is_bigger ? hit1 : hit2;
    smaller_hit = hit1_is_bigger ? hit2 : hit1;

    shabuffer = hip_create_keymat_buffer(kij, kij_len, HIP_AH_SHA_LEN,
                                         smaller_hit, bigger_hit, I, J);
    if (!shabuffer) {
        HIP_ERROR("No memory for keymat\n");
        return;
    }

    bufsize = kij_len + 2 * sizeof(struct in6_addr) +
              2 * sizeof(uint64_t) + 1;

    // XX FIXME: is this correct
    hip_build_digest(HIP_DIGEST_SHA1, shabuffer, bufsize, dstbuf);

    dstoffset = HIP_AH_SHA_LEN;
    index_nbr++;

    /*
     * K2 = SHA1(Kij | K1 | 2)
     * K3 = SHA1(Kij | K2 | 3)
     * ...
     */
    seedkey = dstbuf;
    hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
                             kij_len, index_nbr);

    while (dstoffset < dstbuflen) {
        hip_build_digest(HIP_DIGEST_SHA1, shabuffer,
                         kij_len + HIP_AH_SHA_LEN + 1,
                         (uint8_t *) dstbuf + dstoffset);
        seedkey    = (uint8_t *) dstbuf + dstoffset;
        dstoffset += HIP_AH_SHA_LEN;
        index_nbr++;
        hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
                                 kij_len, index_nbr);
    }

    keymat->offset    = 0;
    keymat->keymatlen = dstoffset;
    keymat->keymatdst = dstbuf;

    if (calc_index) {
        *calc_index = index_nbr;
    } else {
        HIP_ERROR("NULL calc_index\n");
    }

    free(shabuffer);

    return;
}

/**
 * draw keying material
 * @param keymat pointer to the keymat structure which contains information
 *          about the actual
 * @param len size of keymat structure
 *
 * @return pointer the next point where one can draw the next keymaterial
 */
static void *hip_keymat_draw(struct hip_keymat_keymat *keymat, int len)
{
    /* todo: remove this function */
    void *ret = NULL;

    if (len > (int) (keymat->keymatlen - keymat->offset)) {
        HIP_DEBUG("Tried to draw more keys than are available\n");
        goto out_err;
    }

    ret = (uint8_t *) keymat->keymatdst + keymat->offset;

    keymat->offset += len;

out_err:
    return ret;
}

/**
 * draw keying material and copy it to the given buffer
 * @param dst destination buffer
 * @param keymat pointer to the keymat structure which contains information
 *          about the actual
 * @param len size of keymat structure
 *
 * @return pointer the next point where one can draw the next keymaterial
 */
int hip_keymat_draw_and_copy(unsigned char *dst,
                             struct hip_keymat_keymat *keymat,
                             int len)
{
    int   err = 0;
    void *p   = hip_keymat_draw(keymat, len);
    HIP_IFEL(!p, -EINVAL, "Could not draw from keymat\n");
    memcpy(dst, p, len);
out_err:
    return err;
}

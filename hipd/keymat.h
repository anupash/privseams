/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_HIPD_KEYMAT_H
#define HIP_HIPD_KEYMAT_H

#include "lib/core/list.h"

#include "lib/core/crypto.h"
#include "lib/core/state.h"

void hip_make_keymat(char *kij, size_t kij_len,
                     struct hip_keymat_keymat *keymat,
                     void *dstbuf, size_t dstbuflen, struct in6_addr *hit1,
                     struct in6_addr *hit2, uint8_t *calc_index, uint64_t I, uint64_t J);
int hip_keymat_draw_and_copy(unsigned char *dst,
                             struct hip_keymat_keymat *keymat,
                             int len);

#endif /* HIP_HIPD_KEYMAT_H */

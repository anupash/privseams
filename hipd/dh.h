/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_HIPD_DH_H
#define HIP_HIPD_DH_H

#include "hadb.h"
#include "lib/core/crypto.h"

int hip_insert_dh(uint8_t *buffer, int bufsize, int group_id);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(uint8_t *public_value,
                                uint8_t group_id,
                                signed int len,
                                unsigned char *buffer,
                                int bufsize);
#endif /* HIP_HIPD_DH_H */

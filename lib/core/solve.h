/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_SOLVE_H
#define HIP_LIB_CORE_SOLVE_H

#include <sys/types.h>

#include "config.h"
#include "lib/core/crypto.h"
#include "protodefs.h"
#include "state.h"


#define HIP_PUZZLE_MAX_K        28

uint64_t hip_solve_puzzle(void *puzzle, struct hip_common *hdr, int mode);
int hip_solve_puzzle_m(struct hip_common *out,
                       struct hip_common *in,
                       hip_ha_t *entry);

#endif /* HIP_LIB_CORE_SOLVE_H */

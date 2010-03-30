/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_HIPD_UPDATE_LEGACY_H
#define HIP_HIPD_UPDATE_LEGACY_H

#include <stdint.h>
#include "lib/core/protodefs.h"

int hip_build_locators_old(struct hip_common *msg, uint32_t spi);

void hip_empty_oppipdb_old(void);

#endif /* HIP_HIPD_UPDATE_LEGACY_H */

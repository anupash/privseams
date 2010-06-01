/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_DATAPKT_H
#define HIP_FIREWALL_DATAPKT_H

#define _BSD_SOURCE

#include "lib/core/protodefs.h"
#include "firewall_defines.h"

int hip_fw_userspace_datapacket_output(const hip_fw_context_t *ctx);

#endif /* HIP_FIREWALL_DATAPKT_H */

/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_HIPD_BOS_H
#define HIP_HIPD_BOS_H

#include <sys/types.h>
#include <netdb.h>

#include "lib/tool/nlink.h"
#include "lib/core/debug.h"
#include "hidb.h"
#include "hadb.h"
#include "lib/core/list.h"
#include "netdev.h"
#include "lib/core/state.h"

int hip_send_bos(const struct hip_common *msg);
int hip_handle_bos(const uint8_t packet_type,
                   const uint32_t ha_state,
                   struct hip_packet_context *ctx);

#endif /* HIP_HIPD_BOS_H */

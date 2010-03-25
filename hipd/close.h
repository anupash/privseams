/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_HIPD_CLOSE_H
#define HIP_HIPD_CLOSE_H

#include "hadb.h"

#include "hidb.h"
#include "lib/core/builder.h"
#include "cookie.h"
#include "output.h"
#include "lib/core/debug.h"
#include "keymat.h"
#include "lib/core/crypto.h"

#include "lib/tool/pk.h"

int hip_send_close(struct hip_common *msg, int delete_ha_info);
int hip_close_check_packet(const uint8_t packet_type,
                           const uint32_t ha_state,
                           struct hip_packet_context *ctx);
int hip_close_create_response(const uint8_t packet_type,
                              const uint32_t ha_state,
                              struct hip_packet_context *ctx);
int hip_close_send_response(const uint8_t packet_type,
                            const uint32_t ha_state,
                            struct hip_packet_context *ctx);
int hip_handle_close_ack(const uint8_t packet_type,
                         const uint32_t ha_state,
                         struct hip_packet_context *ctx);
int hip_purge_closing_ha(hip_ha_t *ha, void *notused);

#endif /* HIP_HIPD_CLOSE_H */

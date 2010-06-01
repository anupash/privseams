/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief The header file for firewall/midauth.c
 * *
 * @author Thomas Jansen
 *
 */

#ifndef HIP_FIREWALL_MIDAUTH_H
#define HIP_FIREWALL_MIDAUTH_H

#define _BSD_SOURCE

#include <stdint.h>

#include "lib/core/protodefs.h"
#include "firewall_defines.h"

typedef int (*midauth_handler)(hip_fw_context_t *ctx);

struct midauth_handlers {
    midauth_handler i1;
    midauth_handler r1;
    midauth_handler i2;
    midauth_handler r2;
    midauth_handler u1;
    midauth_handler u2;
    midauth_handler u3;
    midauth_handler close;
    midauth_handler close_ack;
};

/**
 * Accepts a packet. Used in midauth_handlers as a default handler.
 *
 * @param ctx context of the packet
 * @return NF_ACCEPT
 */
int midauth_handler_accept(hip_fw_context_t *ctx);

/**
 * Check the correctness of a hip_solution_m
 *
 * @param hip the hip_common that contains the solution
 * @param s the solution to be checked
 * @return 0 if correct, nonzero otherwise
 */
int midauth_verify_challenge_response(struct hip_common *hip,
                                      struct hip_challenge_response *s);



/**
 * Insert a CHALLENGE_REQUEST parameter into a HIP packet.
 *
 * @param ctx context of the packet to be modified
 * @param val_K challenge_request parameter val_K
 * @param ltime challenge_request parameter lifetime
 * @param opaque challenge_request parameter opaque
 * @param opaque_len length of opaque
 * @return 0 on success
 */
int midauth_add_challenge_request(hip_fw_context_t *ctx,
                                  uint8_t val_K, uint8_t ltime,
                                  uint8_t *opaque, uint8_t opaque_len);

/**
 * Initialize midauth infrastructure.
 */
void midauth_init(void);

int midauth_filter_hip(hip_fw_context_t *ctx);

#endif /* HIP_FIREWALL_MIDAUTH_H */

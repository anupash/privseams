/** @file
 * A header file for user.c.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tao Wan <taow_cc.hut.fi>
 * @author  Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPD_USER_H
#define HIP_HIPD_USER_H

#include <stdio.h>
#include <stdint.h> // For uint8_t
#include <stdlib.h>
#include "lib/core/list.h"
#include "bos.h"
#include "close.h"
#include "accessor.h"
#include "hidb.h"
#include "cert.h"
#include "hipd.h"
#include "registration.h"
#include "esp_prot_hipd_msg.h"
#include "user_ipsec_hipd_msg.h"

int hip_user_register_handle(const uint8_t msg_type,
                             int (*handle_func)(hip_common_t *msg,
                                                struct sockaddr_in6 *src),
                             const uint16_t priority);
int hip_user_unregister_handle(const uint8_t msg_type,
                               const int (*handle_func)(hip_common_t *msg,
                                                        struct sockaddr_in6 *src));
int hip_user_run_handles(const uint8_t msg_type,
                         hip_common_t *msg,
                         struct sockaddr_in6 *src);
void hip_user_uninit_handles(void);
int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst);
int hip_handle_user_msg(hip_common_t *msg,
                        struct sockaddr_in6 *src,
                        int *send_response);

#endif /* HIP_HIPD_USER_H */

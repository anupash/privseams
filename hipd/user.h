/** @file
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tao Wan <taow_cc.hut.fi>
 * @author  Rene Hummen
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

#ifndef HIP_HIPD_USER_H
#define HIP_HIPD_USER_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"


int hip_user_register_handle(const uint8_t msg_type,
                             int (*handle_func)(hip_common_t *msg,
                                                struct sockaddr_in6 *src),
                             const uint16_t priority);
int hip_user_run_handles(const uint8_t msg_type,
                         hip_common_t *msg,
                         struct sockaddr_in6 *src);
void hip_user_uninit_handles(void);
int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst);
int hip_handle_user_msg(hip_common_t *msg,
                        struct sockaddr_in6 *src);

#endif /* HIP_HIPD_USER_H */

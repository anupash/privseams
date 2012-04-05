/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPFW_SIGNALING_HIPFW_FEEDBACK_H
#define HIP_HIPFW_SIGNALING_HIPFW_FEEDBACK_H

#include <stdint.h>

#include "config.h"
#include "firewall/firewall_defines.h"
#include "lib/core/protodefs.h"

#include "modules/signaling/lib/signaling_prot_common.h"

int signaling_hipfw_feedback_init(const char *key_file, const char *cert_file);
int signaling_hipfw_feedback_uninit(void);

int signaling_hipfw_send_connection_failed_ntf(UNUSED struct hip_common *common,
                                               UNUSED struct tuple *tuple,
                                               UNUSED const struct hip_fw_context *ctx,
                                               const int reason,
                                               const struct signaling_connection *conn);

/*Utility functions*/
void     *signaling_hipfw_feedback_get_mb_key(void);
X509    *signaling_hipfw_feedback_get_mb_cert(void);
#endif /*HIP_HIPFW_SIGNALING_HIPFW_FEEDBACK_H*/

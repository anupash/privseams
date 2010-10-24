/*
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

/**
 * @file
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 */

#ifndef HIP_LIB_CORE_MESSAGE_H
#define HIP_LIB_CORE_MESSAGE_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "protodefs.h"
#include "state.h"

#define HIP_DEFAULT_MSG_TIMEOUT 4000000000ul /* nanosecs */

int hip_daemon_connect(int hip_user_sock);
int hip_read_user_control_msg(int socket,
                              struct hip_common *hip_msg,
                              struct sockaddr_in6 *saddr);
int hip_read_control_msg_v6(int socket,
                            struct hip_packet_context *ctx,
                            int encap_hdr_size);
int hip_read_control_msg_v4(int socket,
                            struct hip_packet_context *ctx,
                            int encap_hdr_size);
int hip_send_recv_daemon_info(struct hip_common *msg,
                              int send_only,
                              int opt_socket);

#endif /* HIP_LIB_CORE_MESSAGE_H */

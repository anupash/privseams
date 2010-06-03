/** @file
 * A header file for message.c.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
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

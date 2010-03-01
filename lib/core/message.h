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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netinet/in.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/tool/nlink.h"
#include "debug.h"
#include "icomm.h"
#include "lib/conf/hipconf.h"

#define HIP_DEFAULT_MSG_TIMEOUT 4000000000ul /* nanosecs */

int hip_peek_recv_total_len(int socket, int encap_hdr_size, unsigned long timeout);
int hip_daemon_connect(int hip_user_sock);
int hip_daemon_bind_socket(int socket, struct sockaddr *sa);
int hip_send_recv_daemon_info(struct hip_common *msg, int send_only, int socket);
int hip_send_daemon_info(const struct hip_common *msg, int only_send);
int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type);
int hip_read_user_control_msg(int socket,
                              struct hip_common *hip_msg,
                              struct sockaddr_in6 *saddr);
int hip_read_control_msg_all(int socket,
                             struct hip_common *hip_msg,
                             struct in6_addr *saddr,
                             struct in6_addr *daddr,
                             hip_portpair_t *msg_info,
                             int encap_hdr_size,
                             int is_ipv4);
int hip_read_control_msg_v6(int socket,
                            struct hip_common *hip_msg,
                            struct in6_addr *saddr,
                            struct in6_addr *daddr,
                            hip_portpair_t *msg_info,
                            int encap_hdr_size);
int hip_read_control_msg_v4(int socket,
                            struct hip_common *hip_msg,
                            struct in6_addr *saddr,
                            struct in6_addr *daddr,
                            hip_portpair_t *msg_info,
                            int encap_hdr_size);
int hip_sendto(int sock,
               const struct hip_common *msg,
               const struct sockaddr_in6 *dst);
int hip_read_control_msg_plugin_handler(void *msg,
                                        int len,
                                        in6_addr_t *src_addr,
                                        in_port_t port);

#endif /* HIP_LIB_CORE_MESSAGE_H */

#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "nlink.h"
#include "debug.h"
#include "icomm.h"

#define HIP_DAEMON_PORT 3030
int hip_send_recv_daemon_info(struct hip_common *msg);
int hip_send_daemon_info(const struct hip_common *msg);
int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type);
int hip_read_control_msg_v6(int socket, struct hip_common *hip_msg,
			    int read_addr, struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            struct hip_stateless_info *msg_info,
                            int encap_hdr_size);
int hip_read_control_msg_v4(int socket, struct hip_common *hip_msg,
			    int read_addr, struct in6_addr *saddr,
			    struct in6_addr *daddr,
			    struct hip_stateless_info *msg_info,
			    int encap_hdr_size);

#endif /* HIP_MESSAGE_H */

#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <net/hip.h>

#include "debug.h"

int open_hip(void);
int close_hip(int hipfd);
int recv_hipd_request(int hipfd, struct hip_common *msg);
int send_hipd_response(int hipfd, const struct hip_common *msg);
int send_msg(const struct hip_common *msg);

#endif /* HIP_MESSAGE_H */

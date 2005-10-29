#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <hip.h>

#include "debug.h"
#include "nlink.h"

int hip_send_daemon_msg(const struct hip_common *msg);
int hip_recv_daemon_msg(struct hip_common *msg);

#endif /* HIP_MESSAGE_H */

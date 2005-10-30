#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <hip.h>

#include "debug.h"
#include "nlink.h"

int hip_send_daemon_info(const struct hip_common *msg);
int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type);

#endif /* HIP_MESSAGE_H */

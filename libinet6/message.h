#ifndef HIP_MESSAGE_H
#define HIP_MESSAGE_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <net/hip.h>

#include "debug.h"

int open_hip(void);
int close_hip(int hipfd);
int hip_get_global_option(struct hip_common *msg);
int hip_set_global_option(const struct hip_common *msg);


#endif /* HIP_MESSAGE_H */

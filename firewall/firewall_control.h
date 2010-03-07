#ifndef HIP_FIREWALL_FIREWALL_CONTROL_H
#define HIP_FIREWALL_FIREWALL_CONTROL_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"

int hip_handle_msg(struct hip_common *msg);

#endif /*HIP_FIREWALL_FIREWALL_CONTROL_H*/

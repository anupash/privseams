#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"

int handle_msg(struct hip_common * msg);

#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void);
#endif

#endif /*FIREWALL_CONTROL_H_*/

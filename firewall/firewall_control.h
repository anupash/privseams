#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"

int hip_handle_msg(struct hip_common * msg);

#if 0
int request_savah_status(int mode);
int handle_sava_i2_state_update(struct hip_common * msg, int hip_lsi_support);
#endif

#endif /*FIREWALL_CONTROL_H_*/

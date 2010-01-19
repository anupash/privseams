#ifndef HIP_CLOSE_H
#define HIP_CLOSE_H

#include "hadb.h"
#include "lib/core/misc.h"
#include "hidb.h"
#include "lib/core/builder.h"
#include "cookie.h"
#include "output.h"
#include "lib/core/debug.h"
#include "keymat.h"
#include "libhiptool/crypto.h"
#include "lib/core/misc.h"
#include "libhiptool/pk.h"

int hip_send_close(struct hip_common *msg, int delete_ha_info);
int hip_handle_close(struct hip_common *close, hip_ha_t *entry);
int hip_handle_close_ack(struct hip_common *close_ack, hip_ha_t *entry);
int hip_purge_closing_ha(hip_ha_t *ha, void *notused);
int hip_receive_close(struct hip_common *close, hip_ha_t *entry);
int hip_receive_close_ack(struct hip_common *close_ack, hip_ha_t *entry);

#endif /* HIP_CLOSE_H */

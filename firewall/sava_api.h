#ifndef HIP_FIREWALL_SAVA_API_H
#define HIP_FIREWALL_SAVA_API_H

#include "lib/core/hashtable.h"
#include "lib/core/ife.h"

#include "lib/core/builder.h"
#include "lib/core/message.h"
#include "firewall.h"
#include "firewall_defines.h"

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#ifndef ANDROID_CHANGES
#include <openssl/blowfish.h>
#endif

#include <netinet/ip.h>

int hip_sava_init_all(void);
int hip_sava_client_init_all(void);
int hip_sava_handle_bex_completed(struct in6_addr *src, struct in6_addr *hitr);
int hip_sava_handle_output(hip_fw_context_t *ctx);
int hip_sava_handle_router_forward(hip_fw_context_t *ctx);
int request_savah_status(int mode);
int handle_sava_i2_state_update(struct hip_common *msg);
int sava_check_state(struct in6_addr *src, struct in6_addr *hitr);
#endif //HIP_FIREWALL_SAVA_API_H

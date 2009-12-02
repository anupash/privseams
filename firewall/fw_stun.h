#ifndef FW_STUN_H_
#define FW_STUN_H_

#include <pjlib.h>

#include "firewall.h"
#include "ife.h"
#include "debug.h"
#include "misc.h"
#include "firewalldb.h"

extern int raw_sock_v4;

int hip_fw_handle_turn_esp_output(hip_fw_context_t* ctx);
int hip_fw_handle_stun_packet(hip_fw_context_t* ctx);

#endif /*FW_STUN_H_*/

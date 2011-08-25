#include <stdio.h>
#include "lib/core/debug.h"
#include "signaling.h"
#include "hipd/cookie.h"
#include "hipd/esp_prot_hipd_msg.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/input.h"
#include "hipd/maintenance.h"
#include "hipd/netdev.h"
#include "hipd/nsupdate.h"
#include "hipd/output.h"
#include "hipd/pisa.h"
#include "hipd/pkt_handling.h"
#include "hipd/user.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/performance.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/solve.h"
#include "lib/modularization/lmod.h"

static int hip_signaling_print_application(UNUSED const uint8_t packet_type,
							UNUSED const uint32_t ha_state,
							UNUSED struct hip_packet_context *ctx)
{
	printf("SIGNALING:::: We should print our application name right here...\n");
	return 0;
}

int hip_signaling_init(void)
{
	int err;
    HIP_DEBUG("Initialized Signaling Module.\n");

    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_NONE,
                                          &hip_signaling_print_application,
                                          20002),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_R2,
                                          HIP_STATE_I2_SENT,
                                          &hip_signaling_print_application,
                                          20002),
             -1, "Error on registering Signaling handle function.\n");

out_err:
    return 0;
}

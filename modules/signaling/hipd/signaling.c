#include <stdio.h>
#include "lib/core/lmod.h"
#include "lib/core/debug.h"
#include "lib/core/common.h"
#include "lib/core/state.h"
#include "lib/core/ife.h"
#include "hipd/pkt_handling.h"
#include "signaling.h"
#include "signaling_prot_hipd_msg.h"


#define INBOUND_HANDLE_APPLINFO_PRIO              29000
#define OUTBOUND_I2_CREATE_APPINFO_PRIO       	  41500
#define OUTBOUND_R2_CREATE_APPINFO_PRIO       	  41501


int hip_signaling_init(void)
{
	int err = 0;
	/* Print the app info */

    HIP_DEBUG("Initialized Signaling Module.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_handle_appinfo, INBOUND_HANDLE_APPLINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT, &signaling_handle_appinfo, INBOUND_HANDLE_APPLINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add info in I2 */
	HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT, &signaling_i2_add_appinfo, OUTBOUND_I2_CREATE_APPINFO_PRIO),
			-1, "Error on registering Signaling handle function.\n");
	HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT, &signaling_i2_add_appinfo, OUTBOUND_I2_CREATE_APPINFO_PRIO),
			-1, "Error on registering Signaling handle function.\n");

    /* Add info in R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_r2_add_appinfo, OUTBOUND_R2_CREATE_APPINFO_PRIO),
            -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED, &signaling_r2_add_appinfo, OUTBOUND_R2_CREATE_APPINFO_PRIO),
            -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT, &signaling_r2_add_appinfo, OUTBOUND_R2_CREATE_APPINFO_PRIO),
            -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT, &signaling_r2_add_appinfo, OUTBOUND_R2_CREATE_APPINFO_PRIO),
            -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT, &signaling_r2_add_appinfo, OUTBOUND_R2_CREATE_APPINFO_PRIO),
            -1, "Error on registering Signaling handle function.\n");

out_err:
    return err;
}



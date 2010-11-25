#include <stdio.h>
#include "lib/core/modularization.h"
#include "lib/core/debug.h"
#include "lib/core/common.h"
#include "lib/core/state.h"
#include "lib/core/ife.h"
#include "lib/core/icomm.h"
#include "hipd/pkt_handling.h"
#include "hipd/user.h"
#include "signaling.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"
#include "signaling_hipd_state.h"
#include "modules/signaling/lib/signaling_prot_common.h"


#define INBOUND_HANDLE_APPLINFO_PRIO            29000
#define ADD_SCDB_ENTRY_PRIO                     45000
#define OUTBOUND_I2_CREATE_APPINFO_PRIO         41500
#define OUTBOUND_R2_CREATE_APPINFO_PRIO         41501
#define TRIGGER_BEX_PORTS_PRIO                  50000
#define TRIGGER_BEX_UPDATE_PRIO                 30000
#define HANDLE_UPDATE_PRIO                      32000


int hip_signaling_init(void)
{
	int err = 0;

	// register parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APPINFO, "HIP_PARAM_SIGNALING_APPINFO");

    // register initialization function for port information per connection state in hadb
    lmod_register_state_init_function(&signaling_hipd_init_state);

    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_handle_appinfo, INBOUND_HANDLE_APPLINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_send_scdb_add, ADD_SCDB_ENTRY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT, &signaling_handle_appinfo, INBOUND_HANDLE_APPLINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT, &signaling_send_scdb_add, ADD_SCDB_ENTRY_PRIO),
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

    // Handle BEX UPDATES
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_ESTABLISHED, &signaling_handle_bex_update, HANDLE_UPDATE_PRIO),
            -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_R2_SENT, &signaling_handle_bex_update, HANDLE_UPDATE_PRIO),
            -1, "Error on registering Signaling handle function.\n");


    // register user message handler
    HIP_IFEL(hip_user_register_handle(HIP_MSG_TRIGGER_BEX, &signaling_handle_trigger_bex, TRIGGER_BEX_PORTS_PRIO),
            -1, "Error on registering Signaling user handle function.\n");

    HIP_IFEL(hip_user_register_handle(HIP_MSG_SIGNALING_TRIGGER_BEX_UPDATE, &signaling_trigger_first_bex_update, TRIGGER_BEX_UPDATE_PRIO),
                -1, "Error on registering Signaling user handle function.\n");


    HIP_DEBUG("Initialized Signaling Module.\n");

out_err:
    return err;
}



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


#define INBOUND_CHECK_APPINFO_PRIO              29000
#define INBOUND_CHECK_USERINFO_PRIO             29100

#define INBOUND_HANDLE_BEX_PRIO                 32000
#define INBOUND_HANDLE_BEX_UPDATE_PRIO          32000

#define OUTBOUND_I2_CREATE_APPINFO_PRIO         41500
#define OUTBOUND_I2_CREATE_USER_SIG_PRIO        42500
#define OUTBOUND_R2_CREATE_APPINFO_PRIO         41501
#define OUTBOUND_R2_CREATE_USER_SIG_PRIO        42501

#define INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO    30000

int hip_signaling_init(void)
{
	int err = 0;

	// register parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APPINFO, "HIP_PARAM_SIGNALING_APPINFO");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USERINFO, "HIP_PARAM_SIGNALING_USERINFO");

    // register initialization function for port information per connection state in hadb
    lmod_register_state_init_function(&signaling_hipd_init_state);

    /* Handle messages with appinfo or userinfo parameter */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_handle_i2_app_context, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT, &signaling_handle_r2_app_context, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_ESTABLISHED, &signaling_handle_bex_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_R2_SENT, &signaling_handle_bex_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add info in I2 */
	HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT, &signaling_i2_add_appinfo, OUTBOUND_I2_CREATE_APPINFO_PRIO),
			 -1, "Error on registering Signaling handle function.\n");
	HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT, &signaling_i2_add_appinfo, OUTBOUND_I2_CREATE_APPINFO_PRIO),
			 -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT, &signaling_i2_add_user_sig, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT, &signaling_i2_add_user_sig, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
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

    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE, &signaling_r2_add_user_sig, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED, &signaling_r2_add_user_sig, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT, &signaling_r2_add_user_sig, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT, &signaling_r2_add_user_sig, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT, &signaling_r2_add_user_sig, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    // register user message handler
    HIP_IFEL(hip_user_register_handle(HIP_MSG_SIGNALING_REQUEST_CONNECTION, &signaling_handle_connection_request, INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO),
             -1, "Error on registering Signaling user handle function.\n");

    HIP_DEBUG("Initialized Signaling Module.\n");

out_err:
    return err;
}



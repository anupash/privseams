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
#include "modules/signaling/lib/signaling_user_management.h"

#define INBOUND_CHECK_APPINFO_PRIO              29000
#define INBOUND_CHECK_USERINFO_PRIO             29100

#define INBOUND_HANDLE_BEX_PRIO                 32000
#define INBOUND_HANDLE_BEX_UPDATE_PRIO          32000
#define INBOUND_HANDLE_NOTIFY_PRIO              32000

#define OUTBOUND_I2_CREATE_APPINFO_PRIO         41500
#define OUTBOUND_I2_CREATE_USRINFO_PRIO         41502
#define OUTBOUND_I2_CREATE_USER_SIG_PRIO        42500
#define OUTBOUND_I2_CREATE_HOST_INFO_PRIO       41505
#define OUTBOUND_R2_CREATE_APPINFO_PRIO         41501
#define OUTBOUND_R2_CREATE_USRINFO_PRIO         41502
#define OUTBOUND_R2_CREATE_USR_AUTH_PRIO        41504
#define OUTBOUND_R2_CREATE_USER_SIG_PRIO        42501

#define INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO    30000

int hip_signaling_init(void)
{
    int err = 0;

    HIP_IFEL(signaling_user_mgmt_init(), -1, "Could not init user management\n");

    // register I3
    lmod_register_packet_type(HIP_I3, "HIP_I3");

    // register on the wire parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION_ID,      "HIP_PARAM_SIGNALING_CONNECTION_IDENTIFIER");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APPINFO,            "HIP_PARAM_SIGNALING_APPLICATION_CONTEXT");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USERINFO,           "HIP_PARAM_SIGNALING_USER_CONTEXT");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_SIGNATURE,     "HIP_PARAM_SIGNALING_USER_SIGNATURE");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_REQ_U,         "HIP_PARAM_SIGNALING_USER_AUTH_REQ_U");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_REQ_S,         "HIP_PARAM_SIGNALING_USER_AUTH_REQ_S");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CERT_CHAIN_ID,      "HIP_PARAM_SIGNALING_CERT_CHAIN_ID");

    // register internal parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION_CONTEXT, "HIP_PARAM_SIGNALING_CONNECTION_CONTEXT");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION,         "HIP_PARAM_SIGNALING_CONNECTION");


    // register initialization function for port information per connection state in hadb
    lmod_register_state_init_function(&signaling_hipd_init_state);

    /* Handle messages with appinfo or userinfo parameter */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_handle_incoming_i2, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT,         &signaling_handle_incoming_r2, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_ESTABLISHED, &signaling_handle_incoming_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_R2_SENT,     &signaling_handle_incoming_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Handle I3 */
    HIP_IFEL(hip_register_handle_function(HIP_I3, HIP_STATE_ESTABLISHED,     &signaling_handle_incoming_i3, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I3, HIP_STATE_R2_SENT,         &signaling_handle_incoming_i3, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Handle Notifications */
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_NONE,        &signaling_handle_incoming_notification,  INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_UNASSOCIATED, &signaling_handle_incoming_notification,  INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_I1_SENT,     &signaling_handle_incoming_notification,  INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_I2_SENT,     &signaling_handle_incoming_notification,  INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_R2_SENT,     &signaling_handle_incoming_notification,  INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_NOTIFY, HIP_STATE_ESTABLISHED, &signaling_handle_incoming_notification, INBOUND_HANDLE_NOTIFY_PRIO),
             -1, "Error on registering Signaling handle function.\n");



    /* Add application context to I2 */
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_i2_add_application_context, OUTBOUND_I2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_i2_add_application_context, OUTBOUND_I2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add user context to I2 */
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_i2_add_user_context, OUTBOUND_I2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_i2_add_user_context, OUTBOUND_I2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");


    /* Add user signature to I2 */
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_i2_add_user_signature, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_i2_add_user_signature, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add user signature to I2 */
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_i2_add_host_info, OUTBOUND_I2_CREATE_HOST_INFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_i2_add_host_info, OUTBOUND_I2_CREATE_HOST_INFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add application context to in R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_r2_add_application_context, OUTBOUND_R2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED,    &signaling_r2_add_application_context, OUTBOUND_R2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,         &signaling_r2_add_application_context, OUTBOUND_R2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,         &signaling_r2_add_application_context, OUTBOUND_R2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,         &signaling_r2_add_application_context, OUTBOUND_R2_CREATE_APPINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add user context to R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_r2_add_user_context, OUTBOUND_R2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED,    &signaling_r2_add_user_context, OUTBOUND_R2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,         &signaling_r2_add_user_context, OUTBOUND_R2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,         &signaling_r2_add_user_context, OUTBOUND_R2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,         &signaling_r2_add_user_context, OUTBOUND_R2_CREATE_USRINFO_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add user_auth_request_signed to R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_r2_add_user_auth_resp, OUTBOUND_R2_CREATE_USR_AUTH_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED,    &signaling_r2_add_user_auth_resp, OUTBOUND_R2_CREATE_USR_AUTH_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,         &signaling_r2_add_user_auth_resp, OUTBOUND_R2_CREATE_USR_AUTH_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,         &signaling_r2_add_user_auth_resp, OUTBOUND_R2_CREATE_USR_AUTH_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,         &signaling_r2_add_user_auth_resp, OUTBOUND_R2_CREATE_USR_AUTH_PRIO),
             -1, "Error on registering Signaling handle function.\n");


    /* Add user signature to R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_r2_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED,    &signaling_r2_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,         &signaling_r2_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,         &signaling_r2_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,         &signaling_r2_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");


    // register user message handler
    HIP_IFEL(hip_user_register_handle(HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST,  &signaling_handle_connection_request, INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO),
             -1, "Error on registering Signaling user handle function.\n");

    // Init openssl
    OpenSSL_add_all_algorithms();

    HIP_DEBUG("Initialized Signaling Module.\n");

out_err:
    return err;
}

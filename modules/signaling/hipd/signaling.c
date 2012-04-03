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
#include "modules/signaling/lib/signaling_oslayer.h"

#define INBOUND_CHECK_APPINFO_PRIO              29000
#define INBOUND_CHECK_USERINFO_PRIO             29100

#define INBOUND_HANDLE_BEX_PRIO                 32000
#define INBOUND_HANDLE_BEX_UPDATE_PRIO          32000
#define INBOUND_HANDLE_NOTIFY_PRIO              32000

#define OUTBOUND_I2_CREATE_APPINFO_PRIO         41500
#define OUTBOUND_I2_CREATE_USRINFO_PRIO         41502
#define OUTBOUND_I2_CREATE_USER_SIG_PRIO        42500
#define OUTBOUND_I2_CREATE_HOST_INFO_PRIO       41505
#define OUTBOUND_I2_HANDLE_SERVICE_OFFER_PRIO   41506
#define OUTBOUND_R2_HANDLE_SERVICE_OFFER_PRIO   41507
#define OUTBOUND_R2_CREATE_APPINFO_PRIO         41501
#define OUTBOUND_R2_CREATE_USRINFO_PRIO         41502
#define OUTBOUND_R2_CREATE_USR_AUTH_PRIO        41504
#define OUTBOUND_R2_CREATE_USER_SIG_PRIO        42501

#define INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO    30000


int Load_host_info_on_boot_strap()
{
    int err = 0;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I_HOST_CTX_LOOKUP, PERF_R_HOST_CTX_LOOKUP\n");   // test 1.1
    hip_perf_start_benchmark(perf_set, PERF_I_HOST_CTX_LOOKUP);
    hip_perf_start_benchmark(perf_set, PERF_R_HOST_CTX_LOOKUP);
#endif

    HIP_IFEL(signaling_get_verified_host_context(&signaling_persistent_host), -1, "Could not get host context at boot strap.\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I_HOST_CTX_LOOKUP, PERF_R_HOST_CTX_LOOKUP\n");   // test 1.1
    hip_perf_stop_benchmark(perf_set, PERF_I_HOST_CTX_LOOKUP);
    hip_perf_stop_benchmark(perf_set, PERF_R_HOST_CTX_LOOKUP);
#endif
out_err:
    return err;
}

int hip_signaling_init(void)
{
    int err = 0;

    HIP_IFEL(signaling_user_mgmt_init(), -1, "Could not init user management\n");
    HIP_IFEL(signaling_init_host_context(&signaling_persistent_host), -1, "Could not initialize host context.\n");

    // register on the wire parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION_ID,         "HIP_PARAM_SIGNALING_CONNECTION_IDENTIFIER");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CERT_CHAIN_ID,         "HIP_PARAM_SIGNALING_CERT_CHAIN_ID");

    // Information request parameters
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_OS,          "HIP_PARAM_SIGNALING_HOST_INFO_OS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_KERNEL,      "HIP_PARAM_SIGNALING_HOST_INFO_KERNEL");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_ID,          "HIP_PARAM_SIGNALING_HOST_INFO_ID");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_CERTS,       "HIP_PARAM_SIGNALING_HOST_INFO_CERTS");

    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_INFO_ID,          "HIP_PARAM_SIGNALING_USER_INFO_ID");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_INFO_CERTS,       "HIP_PARAM_SIGNALING_USER_INFO_CERTS");

    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_NAME,         "HIP_PARAM_SIGNALING_APP_INFO_NAME");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS,    "HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS,  "HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS, "HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS");

    // register internal parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION_CONTEXT,    "HIP_PARAM_SIGNALING_CONNECTION_CONTEXT");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION,            "HIP_PARAM_SIGNALING_CONNECTION");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_ENCRYPTED,             "HIP_PARAM_SIGNALING_ENCRYPTED");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_OFFER,         "HIP_PARAM_SIGNALING_SERVICE_OFFER");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_OFFER_S,       "HIP_PARAM_SIGNALING_SERVICE_OFFER_S");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_ACK_U,         "HIP_PARAM_SIGNALING_SERVICE_ACK_U");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_ACK_S,         "HIP_PARAM_SIGNALING_SERVICE_ACK_S");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_SIGNATURE,        "HIP_PARAM_SIGNALING_USER_SIGNATURE");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_PORTS,                 "HIP_PARAM_SIGNALING_PORTS");

    // register initialization function for port information per connection state in hadb
    lmod_register_state_init_function(&signaling_hipd_init_state);

    /* Handle Service Offer in R1*/
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_i2_handle_service_offers, OUTBOUND_I2_HANDLE_SERVICE_OFFER_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_i2_handle_service_offers, OUTBOUND_I2_HANDLE_SERVICE_OFFER_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Add user signature to I2 */
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT,         &signaling_add_user_signature, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT,         &signaling_add_user_signature, OUTBOUND_I2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    /* Handle Service Offer in I2*/
    const int service_offer_I2_states[] = { HIP_STATE_UNASSOCIATED,
                                            HIP_STATE_I1_SENT,
                                            HIP_STATE_I2_SENT,
                                            HIP_STATE_R2_SENT,
                                            HIP_STATE_NONE };
    for (unsigned i = 0; i < ARRAY_SIZE(service_offer_I2_states); i++) {
        if (hip_register_handle_function(HIP_I2,
                                         service_offer_I2_states[i],
                                         &signaling_r2_handle_service_offers,
                                         OUTBOUND_R2_CREATE_APPINFO_PRIO)) {
            HIP_ERROR("Error on registering Signaling handle function.\n");
            return -1;
        }
    }

    /* Add user signature to R2 */
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_NONE,            &signaling_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED,    &signaling_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,         &signaling_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,         &signaling_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,         &signaling_add_user_signature, OUTBOUND_R2_CREATE_USER_SIG_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT,         &signaling_handle_incoming_r2, INBOUND_HANDLE_BEX_PRIO),
             -1, "Error on registering Signaling handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_ESTABLISHED, &signaling_handle_incoming_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
             -1, "Error on registering Signaling handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE, HIP_STATE_R2_SENT,     &signaling_handle_incoming_update, INBOUND_HANDLE_BEX_UPDATE_PRIO),
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

    // register user message handler
    HIP_IFEL(hip_user_register_handle(HIP_MSG_SIGNALING_HIPFW_CONNECTION_REQUEST,  &signaling_handle_connection_request, INBOUND_HANDLE_TRIGGER_NEW_CONN_PRIO),
             -1, "Error on registering Signaling user handle function.\n");

    // Init openssl
    OpenSSL_add_all_algorithms();

    HIP_IFEL(Load_host_info_on_boot_strap(), -1, "Error getting host context\n");
    // TODO store host state in global variable

    HIP_DEBUG("Initialized Signaling Module.\n");

out_err:
    return err;
}

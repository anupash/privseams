/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * API for the  functionality for the ESP protection in
 * hipd and hipfw. It also defines necessary TPA parameters used by both
 * hipfw and hipd.
 *
 * @brief Provides common functionality for the ESP protection in hipd and hipfw
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_LIB_CORE_SIGNALING_PROT_COMMON_H
#define HIP_LIB_CORE_SIGNALING_PROT_COMMON_H

#include <sys/time.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "config.h"
#include <openssl/pem.h>

#include "lib/core/protodefs.h"
#ifdef CONFIG_HIP_PERFORMANCE
#include "lib/core/performance.h"
#endif

/* Signaling specific parameters for messages on the wire (adds to protodefs.h) */
#define HIP_PARAM_SIGNALING_CONNECTION_ID       5000
#define HIP_PARAM_SIGNALING_CERT_CHAIN_ID       5008

/* Parameters for internal communication */
#define HIP_PARAM_SIGNALING_CONNECTION_CONTEXT  5100
#define HIP_PARAM_SIGNALING_PORTS               5103

/*Parameter types for the end-point information*/
//TODO check for the values for these parameters
//TODO paramters such as CERTS should be in the signed part
#define HIP_PARAM_SIGNALING_HOST_INFO_OS            5110
#define HIP_PARAM_SIGNALING_HOST_INFO_KERNEL        5111
#define HIP_PARAM_SIGNALING_HOST_INFO_ID            5112
#define HIP_PARAM_SIGNALING_HOST_INFO_CERTS         5113

#define HIP_PARAM_SIGNALING_USER_INFO_ID            5114
#define HIP_PARAM_SIGNALING_USER_INFO_CERTS         5115

#define HIP_PARAM_SIGNALING_APP_INFO_NAME           5116
#define HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS      5117
#define HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS    5118
#define HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS   5119

#define HIP_PARAM_SIGNALING_ENCRYPTED           5120

#define HIP_PARAM_SIGNALING_CONNECTION          5121
#define HIP_PARAM_SIGNALING_SERVICE_ACK         5122
#define HIP_PARAM_SIGNALING_SERVICE_NACK        5123

/*Parameter type for user signature*/
#define HIP_PARAM_SIGNALING_SELECTIVE_HMAC          62498
#define HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE     62502
#define HIP_PARAM_SIGNALING_USER_SIGNATURE          62504

/* Have to be in unsigned part as Middlebox can't sign the message.*/
#define HIP_PARAM_SIGNALING_SERVICE_OFFER       62505
#define HIP_PARAM_SIGNALING_SERVICE_OFFER_S     62506

#define HIP_PARAM_SELECTIVE_HASH_LEAF           62507

/* Update message types */
#define SIGNALING_FIRST_BEX_UPDATE              33001
#define SIGNALING_SECOND_BEX_UPDATE             33002
#define SIGNALING_THIRD_BEX_UPDATE              33003
#define SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE  33010
#define SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE 33011

/* User message types (adds to icomm.h)*/
#define HIP_MSG_SIGNALING_HIPFW_CONNECTION_REQUEST        138
#define HIP_MSG_SIGNALING_HIPD_CONNECTION_CONFIRMATION    139

/* Connection status types */
#define SIGNALING_CONN_PROCESSING  1
#define SIGNALING_CONN_BLOCKED  10
#define SIGNALING_CONN_ALLOWED  11
#define SIGNALING_CONN_USER_AUTHED   20
#define SIGNALING_CONN_USER_UNAUTHED 21

/* Maximum lengths for application and user context */
#define SIGNALING_APP_DN_MAX_LEN     128
#define SIGNALING_ISS_DN_MAX_LEN     128
#define SIGNALING_APP_REQ_MAX_LEN    64
#define SIGNALING_APP_GRP_MAX_LEN    64
#define SIGNALING_APP_CONN_MAX_LEN   32
#define SIGNALING_USER_ID_MAX_LEN    256
#define SIGNALING_USER_KEY_MAX_LEN   HIP_MAX_RSA_KEY_LEN / 8 + 4 // see lib/core/protodefs.h
#define SIGNALING_PATH_MAX_LEN       PATH_MAX

#define SIGNALING_HOST_INFO_PROFILE 128
#define SIGNALING_HOST_INFO_MAX_LEN 128
#define SIGNALING_HOST_INFO_REQ_MAX_LEN 128
#define SIGNALING_HOST_CERTS_MAX_LEN HIP_MAX_RSA_KEY_LEN / 8 + 4
#define SIGNALING_USER_INFO_REQ_MAX_LEN 128
#define SIGNALING_APP_INFO_REQ_MAX_LEN  128


/* Maximum of sockets per connection */
#define SIGNALING_MAX_SOCKETS       50

/* Failure types for user authentication */
#define SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED    1
#define SIGNALING_USER_AUTH_AUTHORITY_REJECTED      2
#define SIGNALING_USER_AUTH_KEY_MISSMATCH           3

/* Signaling notification message types */
#define SIGNALING_USER_AUTH_FAILED                  124
#define SIGNALING_CONNECTION_FAILED                 125

/* Parameters for the information items
 * Information items is a data structure to store values requested by the middlebox
 */
#define MAX_INFO_LENGTH                             200
#define MAX_NUM_INFO_ITEMS                          12
#define MAX_NUM_SERVICE_OFFER_ACCEPTABLE            10
#define MAX_SIZE_HOST_KERNEL                        24
#define MAX_SIZE_HOST_OS                            24
#define MAX_SIZE_CERT_GRP                           64
#define MAX_SIZE_APP_INFO_REQ_CLASS                 16
#define MAX_SIZE_APP_VERSION                        16
#define MAX_NUM_PORT_PAIR                           10
#define MAX_SIZE_PROGNAME                           20


#define SIGNALING_HIP_SYMM_KEY_LEN 16

/* Direction for connections */
enum direction {
    UNINIT, // for unassigned connection contexts
    IN,     // incoming traffic
    OUT,    // outgoing traffic
    FWD     // pass through traffic (routers)
};

/*
 * enum flag_internal {
 *  USER_AUTH_REQUEST,
 *  USER_AUTHED,
 *  HOST_AUTH_REQUEST,
 *  HOST_AUTHED,
 *  HOST_INFO_SHORT,
 *  HOST_INFO_LONG,
 *  HOST_INFO_CERTS,
 * };
 */

enum flag_internal {
    /*New flags to request for host informatin*/
    HOST_INFO_OS     = 0,
    HOST_INFO_KERNEL = 1,
    HOST_INFO_ID     = 2,
    HOST_INFO_CERTS  = 3,

    /*New flags to request for user informatin*/
    USER_INFO_ID    = 4,
    USER_INFO_CERTS = 5,

    /*New flags to request for user informatin*/
    APP_INFO_NAME         = 6,
    APP_INFO_QOS_CLASS    = 7,
    APP_INFO_CONNECTIONS  = 8,
    APP_INFO_REQUIREMENTS = 9,

    /*New flags checked on receiving a response for the request*/
    HOST_INFO_OS_RECV     = 10,
    HOST_INFO_KERNEL_RECV = 11,
    HOST_INFO_ID_RECV     = 12,
    HOST_INFO_CERTS_RECV  = 13,

    USER_INFO_ID_RECV    = 14,
    USER_INFO_CERTS_RECV = 15,

    APP_INFO_NAME_RECV         = 16,
    APP_INFO_QOS_CLASS_RECV    = 17,
    APP_INFO_CONNECTIONS_RECV  = 18,
    APP_INFO_REQUIREMENTS_RECV = 19
};

enum flags_service_state {
    SERVICE_OFFER   = 0,
    SERVICE_OFFER_S = 1,
    SERVICE_ACK_U   = 2,
    SERVICE_ACK_S   = 3,
    SERVICE_NACK    = 4,

    SERVICE_OFFER_RECV   = 5,
    SERVICE_OFFER_S_RECV = 6,
    SERVICE_ACK_U_RECV   = 7,
    SERVICE_ACK_S_RECV   = 8,
    SERVICE_NACK_RECV    = 9
};

enum flags_service_options {
    SERVICE_OPTION1 = 0,
    SERVICE_OPTION2 = 1,
    SERVICE_OPTION3 = 2,
};

enum flags_nack_reason {
    SERVICE_REASON1 = 0,
    SERVICE_REASON2 = 1,
    SERVICE_REASON3 = 2,
};

enum profile_subtype{
    INFO_OS,
    INFO_KERNEL,
    INFO_NAME,
    INFO_CERTS,
    INFO_DN,
    INFO_PRR
};

enum flag_connection_reject {
    APPLICATION_BLOCKED = 1,
    USER_BLOCKED        = 2,
    HOST_BLOCKED        = 4,
    PRIVATE_REASON      = 8
};

enum flag_conn_id {
    FH1,
    FU1,
    FH2,
    FU2
};

enum side {
    INITIATOR,
    RESPONDER,
    MIDDLEBOX
};


/*
 * Moving on from bitwise representation and usage of flags to structures
 * Structure to represent the new profiles / request types
 */
struct flags_connection_context{
    uint8_t USER_AUTH_REQUEST;
    uint8_t USER_AUTHED;
    uint8_t HOST_AUTH_REQUEST;
    uint8_t HOST_AUTHED;
};

struct signaling_flags_info_req {
    uint8_t HOST_INFO_OS;
    uint8_t HOST_INFO_OS_RECV;
    uint8_t HOST_INFO_KERNEL;
    uint8_t HOST_INFO_KERNEL_RECV;
    uint8_t HOST_INFO_ID;
    uint8_t HOST_INFO_ID_RECV;
    uint8_t HOST_INFO_CERTS;
    uint8_t HOST_INFO_CERTS_RECV;

    uint8_t USER_INFO_ID;
    uint8_t USER_INFO_ID_RECV;
    uint8_t USER_INFO_CERTS;
    uint8_t USER_INFO_CERTS_RECV;

    uint8_t APP_INFO_NAME;
    uint8_t APP_INFO_NAME_RECV;
    uint8_t APP_INFO_QOS_CLASS;
    uint8_t APP_INFO_QOS_CLASS_RECV;
    uint8_t APP_INFO_CONNECTIONS;
    uint8_t APP_INFO_CONNECTIONS_RECV;
    uint8_t APP_INFO_REQUIREMENTS;
    uint8_t APP_INFO_REQUIREMENTS_RECV;
} __attribute__((packed));


/*
 * FLags to keep track of the state of services offered and received
 */
struct signaling_flags_service_info {
    uint8_t SERVICE_OFFER;
    uint8_t SERVICE_OFFER_S;
    uint8_t SERVICE_ACK_U;
    uint8_t SERVICE_ACK_S;
    uint8_t SERVICE_NACK;

    uint8_t SERVICE_OFFER_RECV;
    uint8_t SERVICE_OFFER_S_RECV;
    uint8_t SERVICE_ACK_U_RECV;
    uint8_t SERVICE_ACK_S_RECV;
    uint8_t SERVICE_NACK_RECV;
} __attribute__((packed));

/*
 * Data structure to store the values of the various information requests
 */

struct info_item {
    uint16_t info_type;
    uint16_t info_length;
    uint8_t  info[MAX_INFO_LENGTH];
};

/* ------------------------------------------------------------------------------------
 *
 *                    PARAMETER DEFINITIONS
 *
 * ------------------------------------------------------------------------------------ */

/*
 *   Format for the notification data, for the "connection failed" notification.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           REASON              |                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                           PADDING                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct signaling_ntf_connection_failed_data {
    uint16_t reason;
} __attribute__((packed));

/*
 * Format for the notification data, for the "user authentication failed" notification.
 *
 * REASON has the following format
 * 0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 RESERVED                          | H | U | A |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |
 * |   H = host blocked
 * |   U = user blocked
 * |   A = application blocked
 * |
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           REASON              |                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                            PADDING                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |
 */

struct signaling_ntf_user_auth_failed_data {
    uint16_t reason;
} __attribute__((packed));

/*
 *   Parameter for a connection identifier.
 *   The parameter contains source and destination port numbers,
 *   as well as a connection identifier, that is unique per host association.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Network Identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |
 */
struct signaling_param_user_auth_request {
    hip_tlv     type;
    hip_tlv_len length;
    uint32_t    network_id;
} __attribute__((packed));

/*
 *   Parameter certificate chain identifier.
 *   This parameter contains all necessary information needed
 *   to process the parts of a users certificate chain.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Connection Identifier                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Network Identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |
 */
struct signaling_param_cert_chain_id {
    hip_tlv     type;
    hip_tlv_len length;
    uint32_t    connection_id;
    uint32_t    network_id;
} __attribute__((packed));

/*
 *   Parameter for a connection identifier.
 *   The parameter contains source and destination port numbers,
 *   as well as a connection identifier, that is unique per host association.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Connection Identifier                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |
 */
struct signaling_param_connection_identifier {
    hip_tlv     type;
    hip_tlv_len length;
    uint32_t    id;
} __attribute__((packed));

/*
 *   Parameter for a user context.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          UN Length            |         PKEY RR Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --+
 * |          Flags                |    Protocol   |   Algorithm   |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
 * |                                                               |    +--- Comprises the public key rr
 * |                 Public Key Resource Record                    |    |
 * |                                                               |    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --+
 * |                                                               |
 * |    X509 Subject Name          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |            PADDING            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct signaling_param_user_context {
    hip_tlv     type;
    hip_tlv_len length;
    hip_tlv_len un_length;
    hip_tlv_len pkey_rr_length;
    /** ---- end of header ---- */

    /* The public key is in dns key rr format.
     * It is comprised of the rrdata and the actual key */
    struct hip_host_id_key_rdata rdata;
} __attribute__((packed));

/*
 *   Generic structure for the context of an application.
 *   Structure is optimized for use on the wire,
 *   but is used for inter process-communication, too.
 *   Using only one structure simplifies handling.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    APP-DN  Length             |     ISS-DN  Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    REQ     Length             |     GRP     Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          CONN COUNT           |       RESERVED                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      PORT PARI <1>                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      PORT PARI <2>                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      PORT PARI <CONN COUNT>                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /           Distinguished Name of Application                   /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /           Distinguished Name of Issuer                        /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /           Requirement Information                             /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /           Group Information                                   /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    PADDING                                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct signaling_param_app_context {
    hip_tlv     type;
    hip_tlv_len length;
    hip_tlv_len app_dn_length;
    hip_tlv_len iss_dn_length;
    hip_tlv_len req_length;
    hip_tlv_len grp_length;
    uint16_t    port_count;
    uint16_t    reserved;
} __attribute__((packed));

/*
 *   Parameter for a host context.
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Reserved           |       Number of Items         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        INFO_KERNEL            |      Length of the Info       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                    Value  INFO_KERNEL                         /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        INFO_OS                |      Length of the Info       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                    Value   INFO_OS                            /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         INFO_NAME             |      Length of the Info       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                    Value   INFO_NAME                          /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Info Type - INFO_OS, INFO_KERNEL, INFO_NAME
 *  Info Length - Length occupied by the value
 *  There can be a number of these fields. Have a look at
 *  https://code.comsys.rwth-aachen.de/projects/tinyhip/cgi-bin/trac.wsgi/wiki/anupamashish/minutes
 *  for more information
 */

struct signaling_param_host_context {
    hip_tlv          type;
    hip_tlv_len      length;
    uint16_t         reserved;
    uint16_t         num_items;
    struct info_item items[MAX_NUM_INFO_ITEMS];
} __attribute__((packed));



/*
 *   Parameter in response for the information request about host identity in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        HOST_INFO_ID           |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           HI Length           | DI - Type     | DI - Length   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Host Identity                          /
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                               |        Domain - Identifier    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+
 * /                                               |     Padding   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_host_info_id {
    hip_tlv     type;
    hip_tlv_len length;
    hip_tlv_len host_id_length;
    uint8_t     domain_id_type;
    uint8_t     domain_id_length;

    /* Host Identity is the Public Key
     * Length = Size of rdata + length of the key
     */
    struct hip_host_id_key_rdata rdata;
    unsigned char                host_id[HIP_MAX_RSA_KEY_LEN / 8 + 4];

    //TODO clarify what to store here.
    char domain_id[HIP_HOST_ID_HOSTNAME_LEN_MAX];
} __attribute__((packed));


/*
 *   Parameter in response for the information request about kernel in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      HOST_INFO_KERNEL         |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Kernel                            /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_host_info_kernel {
    hip_tlv       type;
    hip_tlv_len   length;
    unsigned char kernel[MAX_SIZE_HOST_KERNEL];
} __attribute__((packed));


/*
 *   Parameter in response for certificate information of the host in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      HOST_INFO_CERTS          |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Certificate Group                       /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
struct signaling_param_host_info_certs {
    hip_tlv       type;
    hip_tlv_len   length;
    unsigned char certificate_grp[MAX_SIZE_CERT_GRP];
} __attribute__((packed));


/*
 *   Parameter in response for certificate information of the host in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      HOST_INFO_OS             |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Length OS                |        Length Version         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Operating System                        /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          OS Version                           /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
struct signaling_param_host_info_os {
    hip_tlv       type;
    hip_tlv_len   length;
    uint16_t      os_len;
    uint16_t      os_version_len;
    unsigned char os_name[MAX_SIZE_HOST_OS];
    unsigned char os_version[MAX_SIZE_HOST_OS];
} __attribute__((packed));


/*
 *   Parameter in response for the information request about user identity in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          USER_INFO_ID         |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        USER DN Length         |            PRR Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Flags                 |   Protocol    |  Algorithm    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                              ...                              /
 * /                           Public Key                          /
 * /                        ( Variable Length )                    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                    X.509 Subject Length                       /
 * /                             ...                -+-+-+-+-+-+-+-+
 * /                                                |  Padding     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_user_info_id {
    hip_tlv     type;
    hip_tlv_len length;
    hip_tlv_len user_dn_length;
    hip_tlv_len prr_length;

    struct hip_host_id_key_rdata rdata;
    unsigned char                pkey[SIGNALING_USER_KEY_MAX_LEN];
    unsigned char                subject_name[SIGNALING_USER_ID_MAX_LEN];
} __attribute__((packed));


/*
 *   Parameter in response for certificate information of the user in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      USER_INFO_CERTS          |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Certificate Group                       /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_user_info_certs {
    hip_tlv       type;
    hip_tlv_len   length;
    unsigned char certificate_group[MAX_SIZE_CERT_GRP];
} __attribute__((packed));


/*
 *   Parameter in response for name information of the application in the endpoint
 *   Responds with both the distinguished name of the application
 *   and the distinguished name of the issuer
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      APP_INFO_NAME            |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Length Application DN      |        Length Issuer DN       /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          X.500 Distinguished Name of the Application          /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             X.500 Distinguished Name of the Issuer            /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Version of the application               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_app_info_name {
    hip_tlv       type;
    hip_tlv_len   length;
    hip_tlv_len   app_dn_length;
    hip_tlv_len   issuer_dn_length;
    unsigned char application_dn[SIGNALING_APP_DN_MAX_LEN];
    unsigned char issuer_dn[SIGNALING_ISS_DN_MAX_LEN];
    unsigned char application_version[MAX_SIZE_APP_VERSION];
} __attribute__((packed));



/*
 *   Parameter in response for connection information of the application in the endpoint
 *   Responds with the connection count and the port-pairs
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     APP_INFO_CONNECTIONS      |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Connection Count       |        Length Port Pair       /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                        Port Pair <0>                          /
 * /                        Port Pair <1>                          /
 * /                              ...                              /
 * /                        Port Pair <n>                          /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

//TODO check this structure with Rene
// Done because of this error: array type has incomplete element type
struct signaling_param_app_info_connections {
    hip_tlv     type;
    hip_tlv_len length;
    uint16_t    connection_count;
    hip_tlv_len port_pair_length;
    uint16_t    sockets[2 * SIGNALING_MAX_SOCKETS];
} __attribute__((packed));



/*
 *   Parameter in response for certificate information of the user in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       APP_INFO_QOS_CLASS      |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Class                             /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_app_info_qos_class {
    hip_tlv     type;
    hip_tlv_len length;
    unsigned char class[MAX_SIZE_APP_INFO_REQ_CLASS];
} __attribute__((packed));



/*
 *   Parameter in response for certificate information of the user in the endpoint
 *
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     APP_INFO_REQUIREMENTS     |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Requirements                         /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_app_info_requirements {
    hip_tlv       type;
    hip_tlv_len   length;
    unsigned char requirements[MAX_SIZE_APP_INFO_REQ_CLASS];
} __attribute__((packed));



/*
 *   Parameter for the middlebox to offer services
 *   The parameter contains Service Offer Identifier, Service Type and Service Description
 *   Also contains the information parameters requested by the middlebox
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       SERVICE_OFFER_ID        | SERVICE_TYPE  |   INFO_LEN    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          SERVICE_DESCRIPTION                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | EP_INFO_REQ   | EP_INFO_REQ   | EP_INFO_REQ   |   ...         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                              ...                              /
 * /                              ...                              /
 * /                              ...                              /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        SERVICE_CERT_HINT                      /
 * /                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   SIG_ALGO    |    SIG_LEN    |                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.                              /
 * /                       SERVICE_SIGNATURE                       /
 * /                              ...                              /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_service_offer {
    hip_tlv       type;
    hip_tlv_len   length;
    uint16_t      service_offer_id;
    uint8_t       service_type;
    uint8_t       service_info_len;
    uint32_t      service_description;
    uint8_t       endpoint_info_req[MAX_NUM_INFO_ITEMS];
    unsigned char service_cert_hint[HIP_AH_SHA_LEN];
    /* To be used only in the case of selective signature*/
    uint8_t       service_sig_algo;
    uint8_t       service_sig_len;
    unsigned char service_signature[HIP_MAX_RSA_KEY_LEN / 8];
} __attribute__((packed));


/*
 *   Parameter for the middlebox to offer services
 *   The parameter contains Service Offer Identifier, Service Type and Service Description
 *   Also contains the information parameters requested by the middlebox
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       SERVICE_OFFER_ID        |          SERVICE_TYPE         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    SERVICE_CERT_HINT_LEN      |   SIG_ALGO    |    SIG_LEN    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          SERVICE_DESCRIPTION                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       ENDPOINT_INFO_REQ       |              ...              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                              ...                              /
 * /                              ...                              /
 * /                              ...                              /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        SERVICE_CERT_HINT                      /
 * /                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                              ...                              /
 * /                       SERVICE_SIGNATURE                       /
 * /                              ...                              /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_service_offer_s {
    hip_tlv       type;
    hip_tlv_len   length;
    uint16_t      service_offer_id;
    uint16_t      service_type;
    uint16_t      service_cert_hint_len;
    uint8_t       service_sig_algo;
    uint8_t       service_sig_len;
    uint32_t      service_description;
    uint16_t      endpoint_info_req[MAX_NUM_INFO_ITEMS];
    unsigned char service_cert_hint[HIP_MAX_RSA_KEY_LEN / 8];
    unsigned char service_signature[HIP_MAX_RSA_KEY_LEN / 8];
} __attribute__((packed));


/*
 *   Parameter for acknowledging the Service Offer from middlebox
 *   The parameter contains Service Offer Identifier and Service Options
 *   Also contains the hash of the service offer
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       SERVICE_OFFER_ID        |         SERVICE_OPTION        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               /
 * /                         SERVICE_OFFER_HASH                    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |         Initial Vector for DH Symmetric encryption            |
 * |           (Set to 0 when RSA used instead of DH)              |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                  ---
 * /    Length   |     Algo        |            KEY_HINT           /                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                     |
 * /       KEY_HINT ctd            |                               /                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /                     \    Encrypted with mbox public key
 * /                                                               /                     /
 * /         Symmetric Key used in HIP_ENCRYPT                     /                     |
 * /                                               +-+-+-+-+-+-+-+-+                     |
 * /                                               |   Padding     |                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                  ---
 */

struct signaling_param_service_ack {
    hip_tlv       type;
    hip_tlv_len   length;
    uint16_t      service_offer_id;
    uint16_t      service_option;
    unsigned char service_offer_hash[HIP_AH_SHA_LEN];
    uint8_t       iv[16];
    // The field below is used only when building acknowledgment for signed service offer
    //unsigned char end_point_info_secret[HIP_MAX_RSA_KEY_LEN / 8];
    /*
     *   uint8_t      symm_key_len;
     *   uint8_t      symm_enc_algo;
     *   uint32_t    key_hint;    // To be used in the HIP_ENCRYPTED param, reserved field
     *   unsigned char symm_key[SIGNALING_HIP_SYMM_KEY_LEN];
     *
     */
} __attribute__((packed));


/*
 *   Parameter for not accepting the Service Offer from middlebox
 *   The parameter contains Service Offer Identifier and reason for the NACK
 *   Also contains the hash of the service offer
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       SERVICE_OFFER_ID        |           NACK_REASON         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               /
 * /                         SERVICE_OFFER_HASH                    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct signaling_param_service_nack {
    hip_tlv       type;
    hip_tlv_len   length;
    uint16_t      service_offer_id;
    uint16_t      nack_reason;
    unsigned char service_offer_hash[HIP_AH_SHA_LEN];
} __attribute__((packed));


/*
 *   Parameter for storing the hash of the portion of hip_msg when
 *   endpoint secret is removed by the mbox after processing
 *   All integers are in network byte order.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 POSITION OF THE LEAF IN THE HASH TREE         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               /
 * /                         LEAF_HASH                             /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct siganling_param_selective_hash_leaf {
    hip_tlv       type;
    hip_tlv_len   length;
    uint32_t      leaf_pos;
    unsigned char leaf_hash[HIP_AH_SHA_LEN];
} __attribute__((packed));


/* ------------------------------------------------------------------------------------
 *
 *                    INTERNAL STATE DEFINITIONS
 *
 * ------------------------------------------------------------------------------------ */


/*
 *  Convenient struct to hold pairs of ports.
 */
struct signaling_port_pair {
    uint16_t src_port;
    uint16_t dst_port;
};

/*
 *   Internal representation of context information for an application.
 *   This structure should be used whenever state needs to be kept about a application.
 *
 *   Use signaling_init_application_context() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_application_context {
    char                       application_dn[SIGNALING_APP_DN_MAX_LEN];
    char                       issuer_dn[SIGNALING_ISS_DN_MAX_LEN];
    char                       requirements[SIGNALING_APP_REQ_MAX_LEN];
    char                       groups[SIGNALING_APP_GRP_MAX_LEN];
    struct signaling_port_pair sockets[SIGNALING_MAX_SOCKETS];
    int                        connections; // Maximum num of permissible connections
};

/*
 *   Internal representation of context information for a user.
 *
 *   Use signaling_init_user_context() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_user_context {
    uid_t uid;
    int   subject_name_len;
    int   key_rr_len;

    /* The key_rr is comprised of the rrdata and the actual key */
    struct hip_host_id_key_rdata rdata;
    unsigned char                pkey[SIGNALING_USER_KEY_MAX_LEN];

    /* Subject name in DER encoding */
    unsigned char subject_name[SIGNALING_USER_ID_MAX_LEN];
};


/*
 *   Internal representation of context information for a host.
 *
 *   Use signaling_init_host_context() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_host_context {
//  char    *host_id;
    int      host_kernel_len;
    int      host_name_len;
    int      host_domain_name_len;
    int      host_os_len;
    int      host_os_ver_len;
    long int host_certs_len;

    char            host_kernel[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_os[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_os_version[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_name[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_domain_name[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_certs[SIGNALING_HOST_CERTS_MAX_LEN];
    struct in6_addr host_id;
};



/*
 * Internal representation of a service offer sent
 */
struct signaling_services_context {
    uint16_t                            service_offer_id;
    uint16_t                            service_type;
    uint32_t                            service_description;
    uint8_t                             service_options;
    struct signaling_flags_service_info flag_services;
    struct signaling_flags_info_req     flag_info_requests;
    uint8_t                             nack_reason;
};


/*
 * Internal representation to store the services offered or the services received
 */
struct signaling_service_container {
    int                               num_items;
    struct signaling_flags_info_req   service_flags;
    struct signaling_services_context services[MAX_NUM_SERVICE_OFFER_ACCEPTABLE];
};


/*
 *   Internal representation of context information for a unidirectional connection.
 *
 *   Use signaling_init_connection_context() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
 *
 *   @note: User and userdb_entry are redundant, but we keep the user context unitl it has been fully
 *          replaced by the new user database.
 */
struct signaling_connection_context {
    uint16_t service_offer_id;
    uint16_t service_type;
    uint32_t service_description;
    uint8_t  service_options;

    uint8_t                              direction;
    struct signaling_application_context app;
    struct signaling_user_context        user;
    struct signaling_host_context        host;
    struct userdb_user_entry            *userdb_entry;
};


/*
 *   Internal representation of information to be requested
 *
 *   All integers are in host-byte-order.
 *
 *   The flags will be set by the middlebox and need not be stored
 */

struct signaling_connection_flags{
    struct signaling_flags_service_info flag_services;
    struct signaling_flags_info_req     flag_info_requests;
};

/*
 *   Internal representation of a service offer
 *
 *   Use signaling_init_host_context() to initialize this structure.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_service_offer {
    uint16_t service_offer_id;
    uint16_t service_type;
    uint32_t service_description;
    uint16_t endpoint_info_req[MAX_NUM_INFO_ITEMS];
};


/*
 *   Internal representation of a service ack
 *
 *   Use signaling_init_host_context() to initialize this structure.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_service_ack {
    uint16_t      service_offer_id;
    uint16_t      service_option;
    unsigned char service_offer_hash[HIP_AH_SHA_LEN];
};


/*
 *   Internal representation of a service nack
 *
 *   Use signaling_init_host_context() to initialize this structure.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_service_nack {
    uint16_t      service_offer_id;
    uint16_t      nack_reason;
    unsigned char service_offer_hash[HIP_AH_SHA_LEN];
};


/**
 *   Internal representation of context information for a bidirectional connection.
 *   This structure should be used whenever state needs to be kept about a connection.
 *
 *   Use signaling_init_connection() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
 */
struct signaling_connection {
    uint32_t id;
    uint16_t src_port;
    uint16_t dst_port;
    char     application_name[MAX_SIZE_PROGNAME];
    uid_t    uid;
};


/*
 *  Internal representation of the optional fields of the host information in short.
 *  Not necessary to be removed
 */
struct signaling_host_info_short {
    uint16_t length;
    uint8_t  priority;
    char     req_info[SIGNALING_HOST_INFO_REQ_MAX_LEN];
};

/* ------------------------------------------------------------------------------------
 *
 *                    UTILITY FUNCTIONS
 *
 * ------------------------------------------------------------------------------------ */

/* Printing of parameters and internal structures */
void signaling_param_host_context_print(const struct signaling_param_host_context *const param_host_ctx);
void signaling_param_user_context_print(const struct signaling_param_user_context *const param_user_ctx);
void signaling_param_application_context_print(const struct signaling_param_app_context *const param_app_ctx);
void signaling_param_connection_identifier_print(const struct signaling_param_connection_identifier *const conn_id);

void signaling_host_context_print(const struct signaling_host_context *const host_ctx,
                                  const char *prefix, const int header);
void signaling_application_context_print(const struct signaling_application_context *const app_ctx,
                                         const char *prefix, const int header);
void signaling_user_context_print(const struct signaling_user_context *const user_ctx,
                                  const char *prefix, const int header);
void signaling_connection_context_print(const struct signaling_connection_context *const ctx, const char *prefix);
void signaling_connection_print(const struct signaling_connection *const conn, const char *prefix);

/* Initialization of internal structures */
int signaling_init_host_context(struct signaling_host_context *const host_ctx);

int signaling_init_user_context(struct signaling_user_context *const user_ctx);

int signaling_init_application_context(struct signaling_application_context *const app_ctx);

int signaling_init_connection_context(struct signaling_connection_context *const ctx,
                                      enum direction dir);
int signaling_init_connection_context_from_msg(struct signaling_connection_context *const ctx,
                                               struct hip_common *msg,
                                               enum direction dir);
int signaling_copy_connection_context(struct signaling_connection_context *const dst,
                                      const struct signaling_connection_context *const src);

int signaling_init_connection(struct signaling_connection *const conn);
int signaling_init_connection_from_msg(struct signaling_connection *const conn,
                                       const struct hip_common *const msg,
                                       enum direction dir);
int signaling_init_app_context_from_msg(struct signaling_application_context *const ctx,
                                        const struct hip_common *const msg,
                                        UNUSED enum direction dir);
int signaling_init_host_context_from_msg(struct signaling_host_context *const ctx,
                                         const struct hip_common *const msg,
                                         UNUSED enum direction dir);
int signaling_init_user_context_from_msg(struct signaling_user_context *const ctx,
                                         struct hip_common *msg,
                                         UNUSED enum direction dir);
int signaling_update_connection_from_msg(struct signaling_connection *const conn,
                                         const struct hip_common *const msg,
                                         enum direction dir);
int signaling_update_info_flags_from_msg(struct signaling_connection_flags *flags,
                                         const struct hip_common *const msg,
                                         enum direction dir);
int signaling_copy_connection(struct signaling_connection *const dst,
                              const struct signaling_connection *const src);
int signaling_connection_add_port_pair(uint16_t src_port, uint16_t dst_port,
                                       struct signaling_connection *const conn);
int signaling_copy_port_pair(struct signaling_port_pair *const dst,
                             const struct signaling_port_pair *const src);
int signaling_copy_service_offer(struct signaling_param_service_offer *const dst,
                                 const struct signaling_param_service_offer *const src);
int signaling_copy_service_offer_s(struct signaling_param_service_offer_s *const dst,
                                   const struct signaling_param_service_offer_s *const src);
int signaling_copy_service_ack(struct signaling_param_service_ack *const dst,
                               const struct signaling_param_service_ack *const src);

/* Flag handling */
int signaling_update_flags_from_connection_id(const struct hip_common *const msg,
                                              struct signaling_connection *const conn);

int signaling_flag_check_auth_complete(struct flags_connection_context flags);
void signaling_flags_print(struct flags_connection_context flags, const char *const prefix);
int signaling_flag_check(struct flags_connection_context flags, int f);
void signaling_flag_set(struct flags_connection_context *flags, int f);
void signaling_flag_unset(struct flags_connection_context *flags, int f);
void signaling_flag_init(struct flags_connection_context *flags);

void signaling_service_info_flags_print(struct signaling_flags_service_info *flags, const char *const prefix);
int signaling_service_info_flag_check(struct signaling_flags_service_info *flags, int f);
void signaling_service_info_flag_set(struct signaling_flags_service_info *flags, int f);
void signaling_service_info_flag_unset(struct signaling_flags_service_info *flags, int f);
void signaling_service_info_flag_init(struct signaling_flags_service_info *flags);

void signaling_info_req_flags_print(struct signaling_flags_info_req  *flags, const char *const prefix);
int signaling_info_req_flag_check(struct signaling_flags_info_req  *flags, int f);
void signaling_info_req_flag_set(struct signaling_flags_info_req *flags, int f);
void signaling_info_req_flag_unset(struct signaling_flags_info_req *flags, int f);
void signaling_info_req_flag_init(struct signaling_flags_info_req *flags);


/* Misc */
const char *signaling_connection_status_name(int status);


#endif /*HIP_LIB_CORE_SIGNALING_PROT_COMMON_H*/

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

#include <stdint.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "lib/core/protodefs.h"

// definition of additional packet I3,
// which we need for user authentication
#define HIP_I3                                      6

/* Signaling specific parameters for messages on the wire (adds to protodefs.h) */
#define HIP_PARAM_SIGNALING_CONNECTION_ID       5000
#define HIP_PARAM_SIGNALING_APPINFO             5002
#define HIP_PARAM_SIGNALING_USERINFO            5004
#define HIP_PARAM_SIGNALING_USER_REQ_S          5006
#define HIP_PARAM_SIGNALING_USER_SIGNATURE      62500
#define HIP_PARAM_SIGNALING_USER_REQ_U          62502

/* Parameters for internal communication */
#define HIP_PARAM_SIGNALING_CONNECTION_CONTEXT  5100
#define HIP_PARAM_SIGNALING_CONNECTION          5102

/* Update message types */
#define SIGNALING_FIRST_BEX_UPDATE              33001
#define SIGNALING_SECOND_BEX_UPDATE             33002
#define SIGNALING_THIRD_BEX_UPDATE              33003
#define SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE  33010
#define SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE 33011

/* User message types (adds to icomm.h)*/
#define HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST        138
#define HIP_MSG_SIGNALING_SECOND_CONNECTION_REQUEST       139
#define HIP_MSG_SIGNALING_CONNECTION_UPDATE_REQUEST       140
#define HIP_MSG_SIGNALING_CONFIRMATION                    141

/* Connection status types */
#define SIGNALING_CONN_NEW      0
#define SIGNALING_CONN_PROCESSING  1
#define SIGNALING_CONN_WAITING  2
#define SIGNALING_CONN_BLOCKED  10
#define SIGNALING_CONN_ALLOWED  11
#define SIGNALING_CONN_USER_AUTHED   20
#define SIGNALING_CONN_USER_UNAUTHED 21

/* Maximum lengths for application and user context */
#define SIGNALING_APP_DN_MAX_LEN    128
#define SIGNALING_ISS_DN_MAX_LEN    128
#define SIGNALING_APP_REQ_MAX_LEN   64
#define SIGNALING_APP_GRP_MAX_LEN   64
#define SIGNALING_USER_ID_MAX_LEN   256
#define SIGNALING_USER_KEY_MAX_LEN  HIP_MAX_RSA_KEY_LEN / 8 + 4 // see lib/core/protodefs.h
#define SIGNALING_PATH_MAX_LEN      PATH_MAX

/* Maximum of sockets per connection */
#define SIGNALING_MAX_SOCKETS       50

/* Failure types for user authentication */
#define SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED    1
#define SIGNALING_USER_AUTH_AUTHORITY_REJECTED      2
#define SIGNALING_USER_AUTH_KEY_MISSMATCH           3

/* Signaling notification message types */
#define SIGNALING_USER_AUTH_FAILED                  124

/* Direction for connections */
enum direction {
    IN,     // incoming traffic
    OUT,    // outgoing traffic
    FWD     // pass through traffic (routers)
};

enum flag_internal {
    USER_AUTH_REQUEST,
    USER_AUTHED,
    HOST_AUTH_REQUEST,
    HOST_AUTHED
};

enum flag_conn_id {
    FH1,
    FU1,
    FH2,
    FU2
};

enum side {
    INITIATOR,
    RESPONDER
};


/* ------------------------------------------------------------------------------------
 *
 *                    PARAMETER DEFINITIONS
 *
 * ------------------------------------------------------------------------------------ */

/*
     Format for the notification data, for the "user authentication failed" notification.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           REASON              |                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                            PADDING                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */

struct signaling_ntf_user_auth_failed_data {
    uint16_t reason;
} __attribute__ ((packed));

/*
     Parameter for a connection identifier.
     The parameter contains source and destination port numbers,
     as well as a connection identifier, that is unique per host association.

     All integers are in network byte order.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Type              |             Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Network Identifier                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
struct signaling_param_user_auth_request {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t network_id;
} __attribute__ ((packed));

/*
     Parameter for a connection identifier.
     The parameter contains source and destination port numbers,
     as well as a connection identifier, that is unique per host association.

     All integers are in network byte order.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Type              |             Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Connection Identifier                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    FLAGS    |                                                 /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            PADDING                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Flags has the following format

     0       1       2       3       4       5       6       7
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   R   |   R   |   R   |   R   | F(U2) | F(H2) | F(U1) | F(H1) |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
struct signaling_param_connection_identifier {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t id;
    uint8_t flags;
} __attribute__ ((packed));

/*
     Parameter for a user signature.

     All integers are in network byte order.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Type              |             Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          UN Length            |         PKEY RR Length        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --+
     |          Flags                |    Protocol   |   Algorithm   |    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |
     |                                                               |    +--- Comprises the public key rr
     |                 Public Key Resource Record                    |    |
     |                                                               |    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --+
     |                                                               |
     |    X509 Subject Name          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                               |            PADDING            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

struct signaling_param_user_context {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    hip_tlv_len_t  un_length;
    hip_tlv_len_t  pkey_rr_length;
    /** ---- end of header ---- */

    /* The public key is in dns key rr format.
     * It is comprised of the rrdata and the actual key */
    struct hip_host_id_key_rdata rdata;
} __attribute__ ((packed));

/*
     Generic structure for the context of an application.
     Structure is optimized for use on the wire,
     but is used for inter process-communication, too.
     Using only one structure simplifies handling.

     All integers are in network byte order.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Type              |             Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    APP-DN  Length             |     ISS-DN  Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    REQ     Length             |     GRP     Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          CONN COUNT           |       RESERVED                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      PORT PARI <1>                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      PORT PARI <2>                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      PORT PARI <CONN COUNT>                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     /           Distinguished Name of Application                   /
     /                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     /           Distinguished Name of Issuer                        /
     /                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     /           Requirement Information                             /
     /                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     /           Group Information                                   /
     /                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    PADDING                                    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

struct signaling_param_app_context {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    hip_tlv_len_t app_dn_length;
    hip_tlv_len_t iss_dn_length;
    hip_tlv_len_t req_length;
    hip_tlv_len_t grp_length;
    uint16_t port_count;
    uint16_t reserved;
} __attribute__ ((packed));


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
     Internal representation of context information for an application.
     This structure should be used whenever state needs to be kept about a application.

     Use signaling_init_application_context() to initialize this structure to standard values.

     All integers are in host-byte-order.
*/
struct signaling_application_context {
    char application_dn[SIGNALING_APP_DN_MAX_LEN];
    char issuer_dn[SIGNALING_ISS_DN_MAX_LEN];
    char requirements[SIGNALING_APP_REQ_MAX_LEN];
    char groups[SIGNALING_APP_GRP_MAX_LEN];
};

/*
     Internal representation of context information for a user.

     Use signaling_init_user_context() to initialize this structure to standard values.

     All integers are in host-byte-order.
*/
struct signaling_user_context {
    long int uid;
    int subject_name_len;
    int key_rr_len;

    /* The key_rr is comprised of the rrdata and the actual key */
    struct hip_host_id_key_rdata rdata;
    unsigned char pkey[SIGNALING_USER_KEY_MAX_LEN];

    /* Subject name in DER encoding */
    unsigned char subject_name[SIGNALING_USER_ID_MAX_LEN];
};


/*
 *   Internal representation of context information for a unidirectional connection.
 *
 *   Use signaling_init_connection_context() to initialize this structure to standard values.
 *
 *   All integers are in host-byte-order.
*/
struct signaling_connection_context {
    uint8_t  flags;
    uint8_t  direction;
    struct signaling_application_context app;
    struct signaling_user_context user;
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
    int status;
    int side;
    uint16_t src_port;
    struct signaling_port_pair sockets[SIGNALING_MAX_SOCKETS];
    struct signaling_connection_context ctx_out;
    struct signaling_connection_context ctx_in;
};

/* ------------------------------------------------------------------------------------
 *
 *                    UTILITY FUNCTIONS
 *
 * ------------------------------------------------------------------------------------ */

/* Printing of parameters and internal structures */
void signaling_param_user_context_print(const struct signaling_param_user_context * const param_user_ctx);
void signaling_param_application_context_print(const struct signaling_param_app_context * const param_app_ctx);
void signaling_param_connection_identifier_print(const struct signaling_param_connection_identifier *const conn_id);

void signaling_application_context_print(const struct signaling_application_context *const app_ctx,
                                         const char *prefix, const int header);
void signaling_user_context_print(const struct signaling_user_context *const user_ctx,
                                  const char * prefix, const int header);
void signaling_connection_context_print(const struct signaling_connection_context *const ctx, const char * prefix);
void signaling_connection_print(const struct signaling_connection *const conn, const char * prefix);

/* Initalization of internal structures */
int signaling_init_user_context(struct signaling_user_context * const user_ctx);

int signaling_init_application_context(struct signaling_application_context * const app_ctx);

int signaling_init_connection_context(struct signaling_connection_context *const ctx,
                                      enum direction dir);
int signaling_init_connection_context_from_msg(struct signaling_connection_context * const ctx,
                                               const struct hip_common * const msg);
int signaling_copy_connection_context(struct signaling_connection_context * const dst,
                                      const struct signaling_connection_context * const src);

int signaling_init_connection(struct signaling_connection *const conn);
int signaling_init_connection_from_msg(struct signaling_connection *const conn,
                                       const hip_common_t * const msg);
int signaling_update_connection_from_msg(struct signaling_connection *const conn,
                                         const hip_common_t * const msg);
int signaling_copy_connection(struct signaling_connection * const dst,
                              const struct signaling_connection * const src);

/* Flag handling */
int signaling_update_flags_from_connection_id(const struct hip_common *const msg,
                                              struct signaling_connection *const conn);
int signaling_flag_check_auth_complete(uint8_t flags);
void signaling_flags_print(uint8_t flags, const char *const prefix);
int signaling_flag_check(uint8_t flags, int f);
void signaling_flag_set(uint8_t *flags, int f);
void signaling_flag_unset(uint8_t *flags, int f);

/* Misc */
const char *signaling_connection_status_name(int status);


#endif /*HIP_LIB_CORE_SIGNALING_PROT_COMMON_H*/


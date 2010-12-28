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


/* Signaling specific parameters for messages on the wire (adds to protodefs.h) */
#define HIP_PARAM_SIGNALING_APPINFO             5000
#define HIP_PARAM_SIGNALING_CONNECTION_CONTEXT  5002
#define HIP_PARAM_SIGNALING_USERINFO            62500


/* User message types (adds to icomm.h)*/
#define HIP_MSG_SIGNALING_REQUEST_CONNECTION        138
#define HIP_MSG_SIGNALING_CONFIRM_CONNECTION        139

/* Connection status types */
#define SIGNALING_CONN_NEW      0
#define SIGNALING_CONN_PENDING  1
#define SIGNALING_CONN_BLOCKED  10
#define SIGNALING_CONN_ALLOWED  11

/* Maximum lengths for application and user context */
#define SIGNALING_APP_DN_MAX_LEN    128
#define SIGNALING_ISS_DN_MAX_LEN    128
#define SIGNALING_APP_REQ_MAX_LEN   64
#define SIGNALING_APP_GRP_MAX_LEN   64
#define SIGNALING_USER_ID_MAX_LEN   128
#define SIGNALING_PATH_MAX_LEN      2048

/* ------------------------------------------------------------------------------------
 *
 *                    PARAMETER DEFINITIONS
 *
 * ------------------------------------------------------------------------------------ */

/*
     Parameter for a user signature.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Type              |             Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          UI Length            |           SIG Length          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          User ID                                              /
     /                                                               /
     /                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Signature                                                   /
     /                                                               /
     /                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                               |            PADDING            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

struct signaling_param_user_context {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    hip_tlv_len_t  ui_length;
    hip_tlv_len_t  sig_length;
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
     |         SRC PORT              |          DEST PORT            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    APP-DN  Length             |     ISS-DN  Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    REQ     Length             |     GRP     Length            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Distinguished Name of Application                          /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /    ...        |    Distinguished Name of Issuer               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /    ...                                        |               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /    Requirement Information                                    /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /  ....                         | Group Information             /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |               |             PADDING                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

struct signaling_param_app_context {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t src_port;
    uint16_t dest_port;
    hip_tlv_len_t app_dn_length;
    hip_tlv_len_t iss_dn_length;
    hip_tlv_len_t req_length;
    hip_tlv_len_t grp_length;
} __attribute__ ((packed));


/* ------------------------------------------------------------------------------------
 *
 *                    INTERNAL STATE DEFINITIONS
 *
 * ------------------------------------------------------------------------------------ */

/*
     Internal representation of context information for an application.
     This structure should be used whenever state needs to be kept about a application.

     Use signaling_init_application_context() to initialize this structure to standard values.

     All integers are in host-byte-order.
*/
struct signaling_application_context {
    pid_t pid;
    char path[SIGNALING_PATH_MAX_LEN];
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
    long int euid;
    char username[SIGNALING_USER_ID_MAX_LEN];
};

/*
     Internal representation of context information for a connection.
     This structure should be used whenever state needs to be kept about a connection.

     Use signaling_init_connection_context() to initialize this structure to standard values.

     All integers are in host-byte-order.
*/
struct signaling_connection_context {
    uint16_t src_port;
    uint16_t dest_port;
    int connection_status;
    struct signaling_application_context app_ctx;
    struct signaling_user_context user_ctx;
};

/* ------------------------------------------------------------------------------------
 *
 *                    UTILITY FUNCTIONS
 *
 * ------------------------------------------------------------------------------------ */

/* Printing of parameters and internal structures */
void signaling_param_user_context_print(const struct signaling_param_user_context * const param_user_ctx);
void signaling_param_application_context_print(const struct signaling_param_app_context * const param_app_ctx);

void signaling_application_context_print(const struct signaling_application_context * const app_ctx,
                                         const char *prefix, const int header);
void signaling_user_context_print(const struct signaling_user_context * const user_ctx,
                                  const char * prefix, const int header);
void signaling_connection_context_print(const struct signaling_connection_context * const ctx, const char * prefix);

/* Initalization of internal structures */
int signaling_init_user_context(struct signaling_user_context * const user_ctx);
int signaling_init_application_context(struct signaling_application_context * const app_ctx);
int signaling_init_connection_context(struct signaling_connection_context * const ctx);
int signaling_init_connection_context_from_msg(struct signaling_connection_context * const ctx,
                                               const hip_common_t * const msg);
int signaling_copy_connection_context(struct signaling_connection_context * const dst,
                                      const struct signaling_connection_context * const src);

#endif /*HIP_LIB_CORE_SIGNALING_PROT_COMMON_H*/


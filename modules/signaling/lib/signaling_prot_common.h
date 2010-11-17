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

#include "lib/core/protodefs.h"

/* Signaling specific parameters for messages on the wire (adds to protodefs.h) */
#define HIP_PARAM_SIGNALING_APPINFO     5000
#define HIP_PARAM_SIGNALING_PORTINFO    32830

/* User message types (adds to icomm.h)*/
#define HIP_MSG_SIGNALING_CDB_ADD_CONN  138

/* Definition of the fields in an appinfo parameter */
#define SIGNALING_APPINFO_APP_DN 1
#define SIGNALING_APPINFO_ISSUER_DN 2
#define SIGNALING_APPINFO_REQS 3
#define SIGNALING_APPINFO_GROUPS 4

/*
  Structure for parameter

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

struct signaling_param_appinfo {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t src_port;
    uint16_t dest_port;
    hip_tlv_len_t app_dn_length;
    hip_tlv_len_t iss_dn_length;
    hip_tlv_len_t req_length;
    hip_tlv_len_t grp_length;
};

struct signaling_param_portinfo {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t srcport;
    uint16_t destport;
} __attribute__ ((packed));

void signaling_param_appinfo_print(const struct signaling_param_appinfo *appinfo);

#endif /*HIP_LIB_CORE_SIGNALING_PROT_COMMON_H*/


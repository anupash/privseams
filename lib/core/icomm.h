/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

#ifndef HIP_LIB_CORE_ICOMM_H
#define HIP_LIB_CORE_ICOMM_H

/* Workaround for kernels before 2.6.15.3. */
#ifndef IPV6_2292PKTINFO
#define IPV6_2292PKTINFO 2
#endif

#include <netinet/in.h>

#include "protodefs.h"

/* Use this port to send asynchronous/unidirectional messages
 * from hipd to hipfw */
#define HIP_FIREWALL_PORT                      971
/* Use this port to send synchronous/bidirectional (request-response)
 * messages from hipd to firewall*/
#define HIP_DAEMON_LOCAL_PORT                  973
#define HIP_FIREWALL_SYNC_PORT                 974


/** @defgroup hip_so HIP socket options
 * Define a constant HIP_MSG_NEWMODE which has value
 * between 0 and HIP_MSG_ROOT_MAX. You may also need to increase the value of
 * HIP_MSG_ROOT_MAX.
 *
 * @note Values 1 - 64 overlap the message values and thus cannot be used in
 *       hip_message_type_name().
 * @todo Should socket option values 1 - 64 be renumbered starting from 65?
 * @{
 */
#define HIP_MSG_ANY_MIN                          1
#define HIP_MSG_ADD_PEER_MAP_HIT_IP              2
#define HIP_MSG_DEL_PEER_MAP_HIT_IP              3
/* free slots */
#define HIP_MSG_NULL_OP                          8
/* free slots */
#define HIP_MSG_GET_PEER_HIT                     14
/* free slot */
#define HIP_MSG_DEFAULT_HIT                      16
/* Free slots here */
#define HIP_MSG_GET_HITS                         21
#define HIP_MSG_GET_HA_INFO                      22
/* free slots */
#define HIP_MSG_GET_LSI_PEER                     26
/* several free slots here */
#define HIP_MSG_HEARTBEAT                        31
/* inclusive */
#define HIP_MSG_PING                             32
#define HIP_MSG_TRIGGER_BEX                      33
#define HIP_MSG_MAP_ID_TO_ADDR                   34
#define HIP_MSG_LSI_TO_HIT                       35
#define HIP_MSG_ANY_MAX                          63
#define HIP_MSG_ROOT_MIN                         64
#define HIP_MSG_ADD_LOCAL_HI                     65
#define HIP_MSG_DEL_LOCAL_HI                     66
#define HIP_MSG_RUN_UNIT_TEST                    67
#define HIP_MSG_RST                              68
#define HIP_MSG_UNIT_TEST                        69
/* free slot */
#define HIP_MSG_NETLINK_DUMMY                    71
#define HIP_MSG_CONF_PUZZLE_NEW                  72
#define HIP_MSG_CONF_PUZZLE_GET                  73
#define HIP_MSG_CONF_PUZZLE_SET                  74
#define HIP_MSG_CONF_PUZZLE_INC                  75
#define HIP_MSG_CONF_PUZZLE_DEC                  76
/* free slot */
#define HIP_MSG_SET_OPPORTUNISTIC_MODE           78
/* Free slots here */
#define HIP_MSG_SET_DEBUG_ALL                    82
#define HIP_MSG_SET_DEBUG_MEDIUM                 83
#define HIP_MSG_SET_DEBUG_NONE                   84
#define HIP_MSG_LOCATOR_GET                      85
#define HIP_MSG_MHADDR_ACTIVE                    86
#define HIP_MSG_MHADDR_LAZY                      87
/** Socket option for hipconf to restart daemon. */
#define HIP_MSG_RESTART                          88
#define HIP_MSG_SET_LOCATOR_ON                   89
#define HIP_MSG_SET_LOCATOR_OFF                  90
/* Free slots here */
#define HIP_MSG_SET_OPPTCP_ON                    94
#define HIP_MSG_SET_OPPTCP_OFF                   95


#define HIP_MSG_RESET_FIREWALL_DB                98

#define HIP_MSG_OPPTCP_SEND_TCP_PACKET           99
#define HIP_MSG_TRANSFORM_ORDER                  100

/** Socket option for the server to offer the RVS service. (server side) */
#define HIP_MSG_OFFER_RVS                        101
/** Socket option for the server to cancel the RVS service. (server side) */
#define HIP_MSG_CANCEL_RVS                       102
/** Socket option for the server to reinit the RVS service. (server side) */
#define HIP_MSG_REINIT_RVS                       103
/**
 * Socket option to ask for additional services or service cancellation from a
 * server, i.e.\ to send a REG_REQUEST parameter to the server. (client side)
 */
#define HIP_MSG_ADD_DEL_SERVER                   104
/** Socket option for the server to offer the HIP relay service. (server
 *  side) */
#define HIP_MSG_OFFER_HIPRELAY                   106
/** Socket option for the server to cancel the HIP relay service. (server
 *  side) */
#define HIP_MSG_CANCEL_HIPRELAY                  107
/** Socket option for hipconf to reinit the HIP relay service. (server side) */
#define HIP_MSG_REINIT_RELAY                     108
#define HIP_MSG_ADD_DB_HI                        115
#define HIP_MSG_FIREWALL_PING                    120
#define HIP_MSG_FIREWALL_PING_REPLY              121
#define HIP_MSG_FIREWALL_QUIT                    122
/* free slots */
#define HIP_MSG_DAEMON_QUIT                      126
#define HIP_MSG_I1_REJECT                        127
/* Free slot */
#define HIP_MSG_SET_NAT_PLAIN_UDP                129
#define HIP_MSG_SET_NAT_NONE                     130
/* Free slots here */
#define HIP_MSG_IPSEC_ADD_SA                     136
/* Free slots here */
#define HIP_PARAM_INT                            140
#define HIP_MSG_CERT_SPKI_SIGN                   141
#define HIP_MSG_CERT_SPKI_VERIFY                 142
#define HIP_MSG_CERT_X509V3_SIGN                 143
#define HIP_MSG_CERT_X509V3_VERIFY               144
#define HIP_MSG_USERSPACE_IPSEC                  145
#define HIP_MSG_ESP_PROT_TFM                     146
#define HIP_MSG_BEX_STORE_UPDATE                 147
/* Free slot */
#define HIP_MSG_TRIGGER_UPDATE                   149
#define HIP_MSG_FW_UPDATE_DB                     152
#define HIP_MSG_IPSEC_DELETE_SA                  153
#define HIP_MSG_IPSEC_FLUSH_ALL_SA               154
#define HIP_MSG_ANCHOR_CHANGE                    155
/* Free slot */
#define HIP_MSG_FW_BEX_DONE                      157
#define HIP_MSG_RESTART_DUMMY_INTERFACE          158
/* free slots */
#define HIP_MSG_TURN_INFO                        164
/* Free slots here */
#define HIP_MSG_NSUPDATE_OFF                     179
#define HIP_MSG_NSUPDATE_ON                      180
#define HIP_MSG_HIT_TO_IP_OFF                    181
#define HIP_MSG_HIT_TO_IP_ON                     182
#define HIP_MSG_HIT_TO_IP_SET                    183
#define HIP_MSG_SET_NAT_PORT                     184
#define HIP_MSG_SHOTGUN_ON                       185
#define HIP_MSG_SHOTGUN_OFF                      186
#define HIP_MSG_SIGN_BUDDY_X509V3                187
#define HIP_MSG_SIGN_BUDDY_SPKI                  188
#define HIP_MSG_VERIFY_BUDDY_X509V3              189
#define HIP_MSG_VERIFY_BUDDY_SPKI                190
#define HIP_MSG_OFFER_FULLRELAY                  191
#define HIP_MSG_CANCEL_FULLRELAY                 192
#define HIP_MSG_REINIT_FULLRELAY                 193
#define HIP_MSG_FIREWALL_START                   194
#define HIP_MSG_MANUAL_UPDATE_PACKET             198
/** Socket option for hipconf to set handover mode, hard or soft. */
#define HIP_MSG_HANDOVER_HARD                    199
#define HIP_MSG_HANDOVER_SOFT                    200
#define HIP_MSG_FIREWALL_STATUS                  201
/* @} */

/* inclusive */
#define HIP_MSG_ROOT_MAX                         255

#endif /* HIP_LIB_CORE_ICOMM_H */

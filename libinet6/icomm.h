#ifndef _HIP_ICOMM
#define _HIP_ICOMM

/* Workaround for kernels before 2.6.15.3. */
#ifndef IPV6_2292PKTINFO
#  define IPV6_2292PKTINFO 2
#endif

/* Do not move this before the definition of struct endpoint, as i3
   headers refer to libinet6 headers which in turn require the
   definition of the struct. */
#ifdef CONFIG_HIP_HI3
#   include "i3_client_api.h" 
#endif

//#define HIP_DAEMONADDR_PATH		        "/tmp/hip_daemonaddr_path.tmp"
#define HIP_FIREWALL_PORT                      60600
#define HIP_DAEMON_LOCAL_PORT                  40400
#define HIP_AGENTADDR_PATH			"/tmp/hip_agentaddr_path.tmp"
#define HIP_USERADDR_PATH		        "/tmp/hip_useraddr_path.tmp"
#define HIP_FIREWALLADDR_PATH			"/tmp/hip_firewalladdr_path.tmp"

#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2
#define SO_HIP_GET_HIT_LIST 3

/** @addtogroup hip_so
 * HIP socket options.
 * @{
 */
#define SO_HIP_ADD_LOCAL_HI                     101
#define SO_HIP_DEL_LOCAL_HI                     102
#define SO_HIP_ADD_PEER_MAP_HIT_IP              103
#define SO_HIP_DEL_PEER_MAP_HIT_IP              104
#define SO_HIP_RUN_UNIT_TEST                    105
#define SO_HIP_RST                              106
//      free                                    107
//      free                                    108
#define SO_HIP_GET_MY_EID                       109
#define SO_HIP_SET_MY_EID                       110
#define SO_HIP_GET_PEER_EID                     111
#define SO_HIP_SET_PEER_EID                     112
#define SO_HIP_NULL_OP                          113
#define SO_HIP_UNIT_TEST                        114
#define SO_HIP_BOS                              115
#define SO_HIP_GET_PEER_LIST                    116
#define SO_HIP_NETLINK_DUMMY                    117
//      free                                    118
//      free                                    119
//      free                                    120
#define SO_HIP_CONF_PUZZLE_NEW                  121
#define SO_HIP_CONF_PUZZLE_GET                  122
#define SO_HIP_CONF_PUZZLE_SET                  123
#define SO_HIP_CONF_PUZZLE_INC                  124
#define SO_HIP_CONF_PUZZLE_DEC                  125
#define SO_HIP_SET_NAT_ON			126
#define SO_HIP_SET_NAT_OFF			127
#define SO_HIP_SET_OPPORTUNISTIC_MODE           128
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         129
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  130
#define SO_HIP_GET_PSEUDO_HIT                   131 
#define SO_HIP_SET_PSEUDO_HIT                   132 
#define SO_HIP_QUERY_IP_HIT_MAPPING		133 
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY	134
#define SO_HIP_GET_PEER_HIT			136
#define SO_HIP_SET_PEER_HIT			137
#define SO_HIP_SET_BLIND_ON                     138
#define SO_HIP_SET_BLIND_OFF                    139
#define SO_HIP_GET_LOCAL_HI                     140
/** Socket option for hipconf to change the used gateway with OpenDHT */
#define SO_HIP_DHT_GW                           141
#define SO_HIP_GET_HITS                         142
#define SO_HIP_GET_HA_INFO			143
#define SO_HIP_DEFAULT_HIT			144
#define SO_HIP_SET_DEBUG_ALL			145
#define SO_HIP_SET_DEBUG_MEDIUM			146
#define SO_HIP_SET_DEBUG_NONE			147
/** Socket option for hipconf to ask about the used gateway with OpenDHT */
#define SO_HIP_DHT_SERVING_GW                   148
#define SO_HIP_HANDOFF_ACTIVE			149
#define SO_HIP_HANDOFF_LAZY			150
//      free                                    151
//      free                                    152
/** Socket option for hipconf to restart daemon. */
#define SO_HIP_RESTART		      		153
#define SO_HIP_SET_LOCATOR_ON                   154
#define SO_HIP_SET_LOCATOR_OFF                  155
#define SO_HIP_DHT_SET                          156
#define SO_HIP_DHT_ON                           157
#define SO_HIP_DHT_OFF                          158
#define SO_HIP_SET_OPPTCP_ON			159
#define SO_HIP_SET_OPPTCP_OFF			160
#define SO_HIP_GET_PEER_HIT_FROM_FIREWALL	161
#define SO_HIP_OPPTCP_UNBLOCK_APP_and_OPPIPDB_ADD_ENTRY		162
#define SO_HIP_OPPTCP_SEND_TCP_PACKET		163
#define SO_HIP_TRANSFORM_ORDER                  164
#define SO_HIP_TRIGGER_BEX                      165
/** @} */

#endif /* _HIP_ICOMM */


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
#define HIP_DAEMON_LOCAL_PORT                  970
#define HIP_FIREWALL_PORT                      971
#define HIP_AGENT_PORT                         972
//#define HIP_AGENTADDR_PATH			"/tmp/hip_agentaddr_path.tmp"
//#define HIP_USERADDR_PATH		        "/tmp/hip_useraddr_path.tmp"
//#define HIP_FIREWALLADDR_PATH			"/tmp/hip_firewalladdr_path.tmp"

#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2
#define SO_HIP_GET_HIT_LIST 3

/** @addtogroup hip_so
 * HIP socket options.
 * @{
 */
#define HIP_SO_ANY_MIN 				1
#define SO_HIP_ADD_PEER_MAP_HIT_IP              2
#define SO_HIP_DEL_PEER_MAP_HIT_IP              3
#define SO_HIP_GET_MY_EID                       4
#define SO_HIP_SET_MY_EID                       5
#define SO_HIP_GET_PEER_EID                     6
#define SO_HIP_SET_PEER_EID                     7
#define SO_HIP_NULL_OP                          8
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         9
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  10
#define SO_HIP_SET_PSEUDO_HIT                   11
#define SO_HIP_QUERY_IP_HIT_MAPPING		12
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY	13
#define SO_HIP_GET_PEER_HIT			14
#define SO_HIP_SET_PEER_HIT			15
#define SO_HIP_DEFAULT_HIT			16
#define SO_HIP_GET_PEER_LIST                    17
#define SO_HIP_CONF_PUZZLE_GET                  18
#define SO_HIP_GET_PSEUDO_HIT                   19 
#define SO_HIP_GET_LOCAL_HI                     20
#define SO_HIP_GET_HITS                         21
#define SO_HIP_GET_HA_INFO			22
#define SO_HIP_TRIGGER_BEX                      23
#define SO_HIP_DHT_SERVING_GW                   24
/* inclusive */
#define HIP_SO_ANY_MAX 				63


/** @addtogroup hip_so
 * HIP socket options.
 * @{
 */
#define HIP_SO_ROOT_MIN 			64
#define SO_HIP_ADD_LOCAL_HI                     65
#define SO_HIP_DEL_LOCAL_HI                     66
#define SO_HIP_RUN_UNIT_TEST                    67
#define SO_HIP_RST                              68
#define SO_HIP_UNIT_TEST                        69
#define SO_HIP_BOS                              70
#define SO_HIP_NETLINK_DUMMY                    71
#define SO_HIP_CONF_PUZZLE_NEW                  72
#define SO_HIP_CONF_PUZZLE_SET                  73
#define SO_HIP_CONF_PUZZLE_INC                  74
#define SO_HIP_CONF_PUZZLE_DEC                  75
/* Three free slots here */
#define SO_HIP_SET_OPPORTUNISTIC_MODE           78
#define SO_HIP_SET_BLIND_ON                     79
#define SO_HIP_SET_BLIND_OFF                    80
/** Socket option for hipconf to change the used gateway with OpenDHT */
#define SO_HIP_DHT_GW                           81
#define SO_HIP_SET_DEBUG_ALL			82
#define SO_HIP_SET_DEBUG_MEDIUM			83
#define SO_HIP_SET_DEBUG_NONE			84
/** Socket option for hipconf to ask about the used gateway with OpenDHT */
/* 85 is free slot */
#define SO_HIP_HANDOFF_ACTIVE			86
#define SO_HIP_HANDOFF_LAZY			87
/** Socket option for hipconf to restart daemon. */
#define SO_HIP_RESTART		      		88
#define SO_HIP_SET_LOCATOR_ON                   89
#define SO_HIP_SET_LOCATOR_OFF                  90
#define SO_HIP_DHT_SET                          91
#define SO_HIP_DHT_ON                           92
#define SO_HIP_DHT_OFF                          93
#define SO_HIP_SET_OPPTCP_ON			94
#define SO_HIP_SET_OPPTCP_OFF			95
/* slot 96 is free */
#define SO_HIP_OPPTCP_UNBLOCK_APP		97
#define SO_HIP_OPPTCP_OPPIPDB_ADD_ENTRY		98
#define SO_HIP_OPPTCP_SEND_TCP_PACKET		99
#define SO_HIP_TRANSFORM_ORDER                  100

/** Socket option for the server to offer the RVS service. (server side) */
#define SO_HIP_OFFER_RVS			101
/** Socket option for the server to cancel the RVS service. (server side) */
#define SO_HIP_CANCEL_RVS                       102
/** Socket option for the server to reinit the RVS service. (server side) */
#define SO_HIP_REINIT_RVS                       103
/** Socket option to ask for the RVS service, i.e.\ send REG_REQUEST parameter
    to the server. (client side) */
#define SO_HIP_ADD_RVS			        104
/** Socket option to ask for cancellation of the RVS service, i.e.\ send
    REG_REQUEST parameter with zero lifetime to the server. (client side) */
#define SO_HIP_DEL_RVS                          105
/** Socket option for the server to offer the HIP relay service. (server
    side) */
#define SO_HIP_OFFER_HIPRELAY                   106
/** Socket option for the server to cancel the HIP relay service. (server
    side) */
#define SO_HIP_CANCEL_HIPRELAY                  107
/** Socket option for hipconf to reinit the HIP relay service. (server side) */
#define SO_HIP_REINIT_RELAY                     108
/** Socket option to ask for the HIP relay service, i.e.\ send REG_REQUEST
    parameter to the server. (client side) */
#define SO_HIP_ADD_RELAY                        109
/** Socket option to ask for cancellation of the HIP relay service, i.e.\ send
    REG_REQUEST parameter with zero lifetime to the server. (client side) */
#define SO_HIP_DEL_RELAY                        110
/** Socket option for the server to offer the escrow service. (server side) */
#define SO_HIP_OFFER_ESCROW			111
/** Socket option for the server to cancel the escrow service. (server side) */
#define SO_HIP_CANCEL_ESCROW                    112
/** Socket option to ask for the escrow service, i.e.\ send REG_REQUEST parameter
    to the server. (client side) */
#define SO_HIP_ADD_ESCROW			113
/** Socket option to ask for cancellation of the escrow service, i.e.\ send
    REG_REQUEST parameter with zero lifetime to the server. (client side) */
#define SO_HIP_DEL_ESCROW			114
#define SO_HIP_ADD_DB_HI                        115
#define SO_HIP_ADD_ESCROW_DATA                  116
#define SO_HIP_DELETE_ESCROW_DATA               117
#define SO_HIP_SET_ESCROW_ACTIVE                118
#define SO_HIP_SET_ESCROW_INACTIVE              119
#define SO_HIP_FIREWALL_PING                    120
#define SO_HIP_FIREWALL_PING_REPLY              121
#define SO_HIP_FIREWALL_QUIT                    122
#define SO_HIP_AGENT_PING                       123
#define SO_HIP_AGENT_PING_REPLY                 124
#define SO_HIP_AGENT_QUIT                       125
#define SO_HIP_DAEMON_QUIT                      126
#define SO_HIP_I1_REJECT                        127
#define SO_HIP_UPDATE_HIU                       128
#define SO_HIP_SET_NAT_PLAIN_UDP                129
#define SO_HIP_SET_NAT_ON                       129 // XX FIXME: REMOVE
#define SO_HIP_SET_NAT_PLAIN_UDP                129
#define SO_HIP_SET_NAT_NONE                     130
#define SO_HIP_SET_NAT_OFF                      130 // XX FIXME: REMOVE
#define SO_HIP_SET_HIPPROXY_ON		      	131
#define SO_HIP_SET_HIPPROXY_OFF			132
#define SO_HIP_GET_PROXY_LOCAL_ADDRESS		133
#define SO_HIP_HIPPROXY_STATUS_REQUEST		134
#define SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST     135
#define SO_HIP_FIREWALL_BEX_DONE                136 /* addes by Tao Wan, for informing the firewall the BEX is done*/
#define SO_HIP_SET_TCPTIMEOUT_ON                137
#define SO_HIP_SET_TCPTIMEOUT_OFF               138
#define SO_HIP_SET_NAT_ICE_UDP                  139
#define HIP_PARAM_INT                           140
#define SO_HIP_CERT_SPKI_SIGN                   141
#define SO_HIP_CERT_SPKI_VERIFY                 142
/** @} */
/* inclusive */
#define HIP_SO_ROOT_MAX 			255

#endif /* _HIP_ICOMM */


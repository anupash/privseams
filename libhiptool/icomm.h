#ifndef _HIP_ICOMM
#define _HIP_ICOMM


/*
 * HIP header and parameter related constants and structures.
 *
 */


#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2
#define SO_HIP_GET_HIT_LIST 3

/* HIP socket options */
#define SO_HIP_ADD_LOCAL_HI                     101
#define SO_HIP_DEL_LOCAL_HI                     102
#define SO_HIP_ADD_PEER_MAP_HIT_IP              103
#define SO_HIP_DEL_PEER_MAP_HIT_IP              104
#define SO_HIP_RUN_UNIT_TEST                    105
#define SO_HIP_RST                              106
#define SO_HIP_ADD_RVS                          107
#define SO_HIP_DEL_RVS                          108
#define SO_HIP_GET_MY_EID                       109
#define SO_HIP_SET_MY_EID                       110
#define SO_HIP_GET_PEER_EID                     111
#define SO_HIP_SET_PEER_EID                     112
#define SO_HIP_NULL_OP                          113
#define SO_HIP_UNIT_TEST                        114
#define SO_HIP_BOS                              115
#define SO_HIP_GET_PEER_LIST                    116
#define SO_HIP_NETLINK_DUMMY                    117
#define SO_HIP_AGENT_PING                       118
#define SO_HIP_AGENT_PING_REPLY                 119
#define SO_HIP_AGENT_QUIT                       120
#define SO_HIP_CONF_PUZZLE_NEW                  121
#define SO_HIP_CONF_PUZZLE_GET                  122
#define SO_HIP_CONF_PUZZLE_SET                  123
#define SO_HIP_CONF_PUZZLE_INC                  124
#define SO_HIP_CONF_PUZZLE_DEC                  125
#define SO_HIP_SET_NAT_ON						126
#define SO_HIP_SET_NAT_OFF						127
#define SO_HIP_SET_OPPORTUNISTIC_MODE           128 /*Bing, trial */
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         129
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  130
#define SO_HIP_GET_PSEUDO_HIT                   131 
#define SO_HIP_SET_PSEUDO_HIT                   132 
#define SO_HIP_QUERY_IP_HIT_MAPPING				133 
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY		134
#define SO_HIP_ADD_DB_HI						135
#define SO_HIP_GET_PEER_HIT						136
#define SO_HIP_SET_PEER_HIT						137
#define SO_HIP_I1_REJECT						138
#define SO_HIP_ADD_ESCROW						139
#define SO_HIP_OFFER_ESCROW						140


#endif /* _HIP_ICOMM */


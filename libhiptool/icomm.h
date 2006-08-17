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
#define SO_HIP_ADD_LOCAL_HI                     1001
#define SO_HIP_DEL_LOCAL_HI                     1002
#define SO_HIP_ADD_PEER_MAP_HIT_IP              1003
#define SO_HIP_DEL_PEER_MAP_HIT_IP              1004
#define SO_HIP_RUN_UNIT_TEST                    1005
#define SO_HIP_RST                              1006
#define SO_HIP_ADD_RVS                          1007
#define SO_HIP_DEL_RVS                          1008
#define SO_HIP_GET_MY_EID                       1009
#define SO_HIP_SET_MY_EID                       1010
#define SO_HIP_GET_PEER_EID                     1011
#define SO_HIP_SET_PEER_EID                     1012
#define SO_HIP_NULL_OP                          1013
#define SO_HIP_UNIT_TEST                        1014
#define SO_HIP_BOS                              1015
#define SO_HIP_GET_PEER_LIST                    1016
#define SO_HIP_NETLINK_DUMMY                    1017
#define SO_HIP_AGENT_PING                       1018
#define SO_HIP_AGENT_PING_REPLY                 1019
#define SO_HIP_AGENT_QUIT                       1020
#define SO_HIP_CONF_PUZZLE_NEW                  1021
#define SO_HIP_CONF_PUZZLE_GET                  1022
#define SO_HIP_CONF_PUZZLE_SET                  1023
#define SO_HIP_CONF_PUZZLE_INC                  1024
#define SO_HIP_CONF_PUZZLE_DEC                  1025
#define SO_HIP_SET_NAT_ON						1026
#define SO_HIP_SET_NAT_OFF						1027
#define SO_HIP_SET_OPPORTUNISTIC_MODE           1028 /*Bing, trial */
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         1029
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  1030
#define SO_HIP_GET_PSEUDO_HIT                   1031 
#define SO_HIP_SET_PSEUDO_HIT                   1032 
#define SO_HIP_QUERY_IP_HIT_MAPPING				1033 
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY		1034
#define SO_HIP_ADD_DB_HI						1035
#define SO_HIP_GET_PEER_HIT						1036
#define SO_HIP_SET_PEER_HIT						1037
#define SO_HIP_I1_REJECT						1038
#define SO_HIP_ADD_ESCROW						1039
#define SO_HIP_OFFER_ESCROW						1040


#endif /* _HIP_ICOMM */


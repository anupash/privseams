#ifndef _NET_HIP
#define _NET_HIP

/*
 * HIP header and parameter related constants and structures.
 *
 *  Authors:
 *  - Janne Lundberg <jlu@tcs.hut.fi>
 *  - Miika Komu <miika@iki.fi>
 *  - Mika Kousa <mkousa@cc.hut.fi>
 *  - Kristian Slavov <kslavov@hiit.fi>
 *  - Tobias Heer <tobi@tobibox.de>
 *  - Abhinav Pathak <abhinav.pathak@hiit.fi>
 *
 *  TODO:
 *  - split this file into net/hip.h (packet structs etc) and linux/hip.h
 *    (implementation specific stuff)
 *  - hip_local_hi and hip_lhid contain reduntantly the anonymous bit?
 *  - hip_tlv_common should be packed?
 *  - the packing of the structures could be hidden in the builder
 *  - replace all in6add6 with hip_hit
 *
 *  BUGS:
 *  -
 *
 */

#ifdef __KERNEL__
#  include "usercompat.h"
#else
#  include "kerncompat.h"
#endif

#define HIP_HIT_TYPE_MASK_HAA   0x80
#define HIP_HIT_TYPE_MASK_120   0x11
#define HIP_HIT_PREFIX          0x1100
#define HIP_HIT_PREFIX_LEN      8     /* bits */
#define HIP_HIT_FULL_PREFIX_STR "/128"
#define HIP_HIT_PREFIX_STR      "/8"
#define HIP_KHI_CONTEXT_ID_INIT { 0xF0,0xEF,0xF0,0x2F,0xBF,0xF4,0x3D,0x0F, \
                                  0xE7,0x93,0x0C,0x3C,0x6E,0x61,0x74,0xEA }

#define HIP_NAT_UDP_PORT 50500 /* For NAT traversal */
#define HIP_NAT_UDP_DATA_PORT 54500 /* For data traffic*/
#define UDP_ENCAP 100 /* For setting socket to listen for beet-udp packets*/
#define UDP_ENCAP_ESPINUDP 2 
#define UDP_ENCAP_ESPINUDP_NONIKE 1 


#define NETLINK_HIP             32   /* Host Identity Protocol signalling messages */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP             253 /* Also in libinet6/include/netinet/in.h */
#endif

/* Workaround for kernels before 2.6.15.3. */
#ifndef IPV6_2292PKTINFO
#  define IPV6_2292PKTINFO 2
#endif

#ifdef CONFIG_HIP_OPPORTUNISTIC

#include <sys/un.h> // for sockaddr_un
struct hip_opp_blocking_request_entry {
  struct list_head     	next_entry;
  spinlock_t           	lock;
  atomic_t             	refcnt;

  struct in6_addr      	hash_key;       /* hit_our XOR hit_peer */
  struct in6_addr       peer_real_hit;
  struct sockaddr_un    caller;
};
typedef struct hip_opp_blocking_request_entry hip_opp_block_t;

#define SET_NULL_HIT(hit)                      \
        { memset(hit, 0, sizeof(hip_hit_t));        \
          (hit)->s6_addr32[0] = htons(HIP_HIT_PREFIX);}

inline static ipv6_addr_is_null(struct in6_addr *ip){
  return ((ip->s6_addr32[0] | ip->s6_addr32[1] | 
	   ip->s6_addr32[2] | ip->s6_addr32[3] ) == 0); 
  /*  return ((ip->s6_addr32[0] == 0) &&          
	  (ip->s6_addr32[1] == 0) &&          
	  (ip->s6_addr32[2] == 0) &&          
	  (ip->s6_addr32[3] == 0));
  */
}

static inline int create_new_socket(int type, int protocol)
{
  return socket(AF_INET6, type, protocol);
}

static inline int hit_is_real_hit(const struct in6_addr *hit){
  return ((hit->s6_addr[0] == htons(HIP_HIT_PREFIX)) &&
	  (hit->s6_addr[1] != 0x00));
}

static inline int hit_is_opportunistic_hit(const struct in6_addr *hit){
  return ((hit->s6_addr32[0] == htons(HIP_HIT_PREFIX)) &&
	  (hit->s6_addr32[1] == 0) &&
	  (hit->s6_addr32[2] == 0) &&
	  (hit->s6_addr32[3] == 0));
}

static inline int hit_is_opportunistic_hashed_hit(const struct in6_addr *hit){
  return ((hit->s6_addr[0] == htons(HIP_HIT_PREFIX)) &&
	  (hit->s6_addr[1] == 0x00));

}
static inline int hit_is_opportunistic_null(const struct in6_addr *hit){
  return ((hit->s6_addr32[0] | hit->s6_addr32[1] |
	   hit->s6_addr32[2] | (hit->s6_addr32[3]))  == 0);
}
#endif // CONFIG_HIP_OPPORTUNISTIC

static inline int ipv6_addr_is_hit(const struct in6_addr *a)
{
	return (a->s6_addr[0] == HIP_HIT_TYPE_MASK_120);
}

#define IPV4_TO_IPV6_MAP(in_addr_from, in6_addr_to)                       \
         {(in6_addr_to)->s6_addr32[0] = 0;                                \
          (in6_addr_to)->s6_addr32[1] = 0;                                \
          (in6_addr_to)->s6_addr32[2] = htonl(0xffff);                    \
         (in6_addr_to)->s6_addr32[3] = (uint32_t) ((in_addr_from)->s_addr);}

#define IPV6_TO_IPV4_MAP(in6_addr_from,in_addr_to)    \
       { ((in_addr_to)->s_addr) =                       \
          ((in6_addr_from)->s6_addr32[3]); }

#define IPV6_EQ_IPV4(in6_addr_a,in_addr_b)   \
       ( IN6_IS_ADDR_V4MAPPED(in6_addr_a) && \
	((in6_addr_a)->s6_addr32[3] == (in_addr_b)->s_addr)) 

#define HIT2LSI(a) ( 0x01000000L | \
                     (((a)[HIT_SIZE-3]<<16)+((a)[HIT_SIZE-2]<<8)+((a)[HIT_SIZE-1])))

#define IS_LSI32(a) ((a & 0xFF) == 0x01)

#define HIT_IS_LSI(a) \
        ((((__const uint32_t *) (a))[0] == 0)                                 \
         && (((__const uint32_t *) (a))[1] == 0)                              \
         && (((__const uint32_t *) (a))[2] == 0)                              \
         && IS_LSI32(((__const uint32_t *) (a))[3]))        

#define HIPL_VERSION 0.2

#define HIP_MAX_PACKET 2048
#define HIP_MAX_NETLINK_PACKET 3072

#define HIP_SELECT_TIMEOUT      1
#define HIP_RETRANSMIT_MAX      10
#define HIP_RETRANSMIT_INTERVAL 1 /* seconds */
/* the interval with which the hadb entries are checked for retransmissions */
#define HIP_RETRANSMIT_INIT \
           (HIP_RETRANSMIT_INTERVAL / HIP_SELECT_TIMEOUT)
/* wait about n seconds before retransmitting.
   the actual time is between n and n + RETRANSMIT_INIT seconds */
#define HIP_RETRANSMIT_WAIT 5 
#define HIP_R1_PRECREATE_INTERVAL 60 /* seconds */
#define HIP_R1_PRECREATE_INIT \
           (HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)
#define OPENDHT_REFRESH_INTERVAL 60 /* seconds */
#define OPENDHT_REFRESH_INIT \
           (OPENDHT_REFRESH_INTERVAL / HIP_SELECT_TIMEOUT)

/* How many duplicates to send simultaneously: 1 means no duplicates */
#define HIP_PACKET_DUPLICATES                1
/* Set to 1 if you want to simulate lost output packet */
#define HIP_SIMULATE_PACKET_LOSS             0
 /* Packet loss probability in percents */
#define HIP_SIMULATE_PACKET_LOSS_PROBABILITY 30
#define HIP_SIMULATE_PACKET_IS_LOST() (random() < ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100)

#define HIP_NETLINK_TALK_ACK 1 /* see netlink_talk */

#define HIP_HIT_KNOWN 1
#define HIP_HIT_ANON  2

#define HIP_LOWER_TRANSFORM_TYPE 2048
#define HIP_UPPER_TRANSFORM_TYPE 4095

//#define HIP_HIT_TYPE_HASH126    1
#define HIP_HIT_TYPE_HASH120    1
#define HIP_HIT_TYPE_HAA_HASH   2

#define HIP_I1         1
#define HIP_R1         2
#define HIP_I2         3
#define HIP_R2         4
#define HIP_CER        5
#define HIP_UPDATE     16
#define HIP_NOTIFY     17
#define HIP_CLOSE      18
#define HIP_CLOSE_ACK  19
//#define HIP_REA 10     /* removed from ietf-hip-mm-00   */
#define HIP_BOS 11     /* removed from ietf-hip-base-01 */
//#define HIP_AC 12      /* removed from ietf-hip-mm-00   */
//#define HIP_ACR 13     /* removed from ietf-hip-mm-00   */
#define HIP_PSIG 20 /* lightweight HIP pre signature */
#define HIP_TRIG 21 /* lightweight HIP signature trigger*/
#define HIP_PAYLOAD 64 /* xxx */

#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2
#define SO_HIP_GET_HIT_LIST 3

/* HIP socket options */
#define SO_HIP_ADD_LOCAL_HI                     1
#define SO_HIP_DEL_LOCAL_HI                     2
#define SO_HIP_ADD_PEER_MAP_HIT_IP              3
#define SO_HIP_DEL_PEER_MAP_HIT_IP              4
#define SO_HIP_RUN_UNIT_TEST                    5
#define SO_HIP_RST                              6
#define SO_HIP_ADD_RVS                          7
#define SO_HIP_DEL_RVS                          8
#define SO_HIP_GET_MY_EID                       9
#define SO_HIP_SET_MY_EID                       10
#define SO_HIP_GET_PEER_EID                     11
#define SO_HIP_SET_PEER_EID                     12
#define SO_HIP_NULL_OP                          13
#define SO_HIP_UNIT_TEST                        14
#define SO_HIP_BOS                              15
#define SO_HIP_GET_PEER_LIST                    16
#define SO_HIP_NETLINK_DUMMY                    17
#define SO_HIP_AGENT_PING                       18
#define SO_HIP_AGENT_PING_REPLY                 19
#define SO_HIP_AGENT_QUIT                       20
#define SO_HIP_CONF_PUZZLE_NEW                  21
#define SO_HIP_CONF_PUZZLE_GET                  22
#define SO_HIP_CONF_PUZZLE_SET                  23
#define SO_HIP_CONF_PUZZLE_INC                  24
#define SO_HIP_CONF_PUZZLE_DEC                  25
#define SO_HIP_SET_NAT_ON			26
#define SO_HIP_SET_NAT_OFF			27
#define SO_HIP_SET_OPPORTUNISTIC_MODE           28 /*Bing, trial */
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         29
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  30
#define SO_HIP_GET_PSEUDO_HIT                   31 
#define SO_HIP_SET_PSEUDO_HIT                   32 
#define SO_HIP_QUERY_IP_HIT_MAPPING		33 
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY	34
#define SO_HIP_ADD_DB_HI			35
#define SO_HIP_GET_PEER_HIT			36
#define SO_HIP_SET_PEER_HIT			37
#define SO_HIP_I1_REJECT			38
#define SO_HIP_ADD_ESCROW			39
#define SO_HIP_OFFER_ESCROW			40
#define SO_HIP_FIREWALL_PING		40
#define SO_HIP_FIREWALL_PING_REPLY	41
#define SO_HIP_FIREWALL_QUIT		42
#define SO_HIP_ADD_ESCROW_DATA		43

#define HIP_DAEMONADDR_PATH                    "/tmp/hip_daemonaddr_path.tmp"
#define HIP_AGENTADDR_PATH                     "/tmp/hip_agentaddr_path.tmp"
#define HIP_USERADDR_PATH                     "/tmp/hip_useraddr_path.tmp"
#define HIP_FIREWALLADDR_PATH				"/tmp/hip_firewalladdr_path.tmp"

#define HIP_HOST_ID_HOSTNAME_LEN_MAX 64

#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
#define HIP_HI_REUSE_UID                   4
#define HIP_HI_REUSE_GID                   8
#define HIP_HI_REUSE_ANY                  16
/* Other flags: keep them to the power of two! */

#define HIP_HOST_ID_RR_DSA_MAX_T_VAL           8
#define HIP_HOST_ID_RR_T_SIZE                  1
#define HIP_HOST_ID_RR_Q_SIZE                  20
#define HIP_HOST_ID_RR_P_BASE_SIZE             20
#define HIP_HOST_ID_RR_G_BASE_SIZE             20
#define HIP_HOST_ID_RR_Y_BASE_SIZE             20
#define HIP_HOST_ID_RR_DSA_PRIV_KEY_SIZE       20

//#define HIP_CONTROL_PIGGYBACK_ALLOW 0x4000   /* Host accepts piggybacked ESP in I2 and R2 */

#define HIP_PSEUDO_CONTROL_REQ_RVS  0x8000
//#define HIP_CONTROL_ESP_64          0x1000   /* Use 64-bit sequence number */
#define HIP_CONTROL_RVS_CAPABLE     0x8000    /* not yet defined */
#define HIP_CONTROL_CONCEAL_IP               /* still undefined */
//#define HIP_CONTROL_CERTIFICATES    0x0002   /* Certificate packets follow */
#define HIP_CONTROL_HIT_ANON        0x0001   /* Anonymous HI */
#define HIP_CONTROL_NONE            0x0000

#if 0
#define HIP_CONTROL_SHT_SHIFT       13
#define HIP_CONTROL_DHT_SHIFT       10
#define HIP_CONTROL_SHT_MASK        (0x8000|0x4000|0x2000) /* bits 16-14 */
#define HIP_CONTROL_DHT_MASK        (0x1000|0x800|0x400)  /* bits 13-11 */
#define HIP_CONTROL_SHT_TYPE1       1
#define HIP_CONTROL_SHT_TYPE2       2
#define HIP_CONTROL_DHT_TYPE1       HIP_CONTROL_SHT_TYPE1
#define HIP_CONTROL_DHT_TYPE2       HIP_CONTROL_SHT_TYPE2
#define HIP_CONTROL_SHT_ALL         (HIP_CONTROL_SHT_MASK >> HIP_CONTROL_SHT_SHIFT)
#define HIP_CONTROL_DHT_ALL         (HIP_CONTROL_DHT_MASK >> HIP_CONTROL_DHT_SHIFT)
#endif

#define HIP_VER_RES                 0x01     /* Version 1, reserved 0 */
#define HIP_VER_MASK                0xF0
#define HIP_RES_MASK                0x0F 

#define HIP_STATE_NONE              0      /* No state, structure unused */
#define HIP_STATE_UNASSOCIATED      1      /* ex-E0 */
#define HIP_STATE_I1_SENT           2      /* ex-E1 */
#define HIP_STATE_I2_SENT           3      /* ex-E2 */
#define HIP_STATE_R2_SENT           4
#define HIP_STATE_ESTABLISHED       5      /* ex-E3 */
//#define HIP_STATE_REKEYING          6      /* XX TODO: REMOVE */
/* when adding new states update debug.c hip_state_str */
#define HIP_STATE_FAILED            7
#define HIP_STATE_CLOSING           8
#define HIP_STATE_CLOSED            9
#define HIP_STATE_FILTERING			10

#define HIP_UPDATE_STATE_REKEYING    1      /* XX TODO: REMOVE */
#define HIP_UPDATE_STATE_DEPRECATING 2

#define HIP_PARAM_MIN                 -1 /* exclusive */

#define HIP_PARAM_ESP_INFO             65
//#define HIP_PARAM_SPI                  1 /* XX REMOVE:replaced with ESP_INFO */
#define HIP_PARAM_R1_COUNTER           128
//#define HIP_PARAM_REA                  3 /* XX REMOVE:replaced with LOCATOR */
#define HIP_PARAM_LOCATOR              193
#define HIP_PARAM_PUZZLE               257
#define HIP_PARAM_SOLUTION             321
//#define HIP_PARAM_NES                  9
#define HIP_PARAM_SEQ                  385
#define HIP_PARAM_ACK                  449
#define HIP_PARAM_DIFFIE_HELLMAN       513
#define HIP_PARAM_HIP_TRANSFORM        577
#define HIP_PARAM_ESP_TRANSFORM        4095
#define HIP_PARAM_ENCRYPTED            641
#define HIP_PARAM_HOST_ID              705
#define HIP_PARAM_CERT                 768
#define HIP_PARAM_RVA_REQUEST          100
#define HIP_PARAM_RVA_REPLY            102
#define HIP_PARAM_HASH_CHAIN_VALUE     221 // lhip hash chain. 221 is just temporary
#define HIP_PARAM_HASH_CHAIN_ANCHORS   222 // lhip hash chain anchors. 222 is just temporary
#define HIP_PARAM_HASH_CHAIN_PSIG                 223 // lhip hash chain signature. 223 is just temporary

#define HIP_PARAM_NOTIFY               832
#define HIP_PARAM_ECHO_REQUEST_SIGN    897
#define HIP_PARAM_ECHO_RESPONSE_SIGN   961

/* Range 32768 - 49141 can be used for HIPL private parameters. */
#define HIP_PARAM_HIT                   32768
#define HIP_PARAM_IPV6_ADDR             32769
#define HIP_PARAM_DSA_SIGN_DATA         32770 /* XX TODO: change to digest */
#define HIP_PARAM_HI                    32771
#define HIP_PARAM_DH_SHARED_KEY         32772
#define HIP_PARAM_UNIT_TEST             32773
#define HIP_PARAM_EID_SOCKADDR          32774
#define HIP_PARAM_EID_ENDPOINT          32775 /* Pass endpoint_hip structures into kernel */
#define HIP_PARAM_EID_IFACE             32776
#define HIP_PARAM_EID_ADDR              32777
#define HIP_PARAM_UINT                  32778 /* Unsigned integer */
#define HIP_PARAM_KEYS                  32779
#define HIP_PSEUDO_HIT                  32780 
#define HIP_PARAM_REG_INFO				32781 /* TODO: move somewhere else*/
#define HIP_PARAM_REG_REQUEST			32782 /* TODO: move somewhere else*/
#define HIP_PARAM_REG_RESPONSE			32783 /* TODO: move somewhere else*/
#define HIP_PARAM_REG_FAILED			32784 /* TODO: move somewhere else*/
/* End of HIPL private parameters. */

#define HIP_PARAM_FROM_SIGN       65100
#define HIP_PARAM_TO_SIGN         65102
#define HIP_PARAM_HMAC            61505
#define HIP_PARAM_HMAC2           61569
#define HIP_PARAM_HIP_SIGNATURE2  61633
#define HIP_PARAM_HIP_SIGNATURE   61697
#define HIP_PARAM_ECHO_REQUEST    63661
#define HIP_PARAM_ECHO_RESPONSE   63425
#define HIP_PARAM_FROM            65300
#define HIP_PARAM_TO              65302
#define HIP_PARAM_RVA_HMAC        65320
#define HIP_PARAM_VIA_RVS         65500
#define HIP_PARAM_MAX             65536 /* exclusive */

#define HIP_HIP_RESERVED                0
#define HIP_HIP_AES_SHA1                1
#define HIP_HIP_3DES_SHA1               2
#define HIP_HIP_3DES_MD5                3
#define HIP_HIP_BLOWFISH_SHA1           4
#define HIP_HIP_NULL_SHA1               5
#define HIP_HIP_NULL_MD5                6

#define HIP_TRANSFORM_HIP_MAX           6
#define HIP_TRANSFORM_ESP_MAX           6

#define HIP_ESP_RESERVED                0
#define HIP_ESP_AES_SHA1                1
#define HIP_ESP_3DES_SHA1               2
#define HIP_ESP_3DES_MD5                3
#define HIP_ESP_BLOWFISH_SHA1           4
#define HIP_ESP_NULL_SHA1               5
#define HIP_ESP_NULL_MD5                6

#define ESP_AES_KEY_BITS                128
#define ESP_3DES_KEY_BITS               192

/* Only for testing!!! */
#define HIP_ESP_NULL_NULL            0x0

#define HIP_HI_DSA                    3
#define HIP_SIG_DSA                   3
#define HIP_HI_RSA                    5
#define HIP_SIG_RSA                   5
#define HIP_HI_DEFAULT_ALGO           HIP_HI_RSA
#define HIP_SIG_DEFAULT_ALGO          HIP_SIG_RSA
#define HIP_ANY_ALGO                  -1

#define HIP_DIGEST_MD5                1
#define HIP_DIGEST_SHA1               2
#define HIP_DIGEST_SHA1_HMAC          3
#define HIP_DIGEST_MD5_HMAC           4

#define HIP_DIRECTION_ENCRYPT         1
#define HIP_DIRECTION_DECRYPT         2

#define HIP_KEYMAT_INDEX_NBR_SIZE     1

#define HIP_VERIFY_PUZZLE             0
#define HIP_SOLVE_PUZZLE              1
#define HIP_PUZZLE_OPAQUE_LEN         2

#define HIP_PARAM_ENCRYPTED_IV_LEN    8

#define HIP_DSA_SIGNATURE_LEN        41
/* Assume that RSA key is 1024 bits. RSA signature is as long as the key
   (1024 bits -> 128 bytes) */
#define HIP_RSA_SIGNATURE_LEN       128

#define ENOTHIT                     666

/* Domain Identifiers (to be used in HOST_ID TLV) */
#define HIP_DI_NONE                   0
#define HIP_DI_FQDN                   1
#define HIP_DI_NAI                    2


/* Rendezvous types */
#define HIP_RVA_RELAY_I1              1
#define HIP_RVA_RELAY_I1R1            2
#define HIP_RVA_RELAY_I1R1I2          3
#define HIP_RVA_RELAY_I1R1I2R2        4
#define HIP_RVA_RELAY_ESP_I1          5
#define HIP_RVA_REDIRECT_I1           6

#define HIP_ESCROW_SERVICE			  7

#define PEER_ADDR_STATE_UNVERIFIED 1
#define PEER_ADDR_STATE_ACTIVE 2
#define PEER_ADDR_STATE_DEPRECATED 3

#define ADDR_STATE_ACTIVE 1
#define ADDR_STATE_WAITING_ECHO_REQ 2

#define HIP_LOCATOR_TRAFFIC_TYPE_DUAL    0
#define HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL  1
#define HIP_LOCATOR_TRAFFIC_TYPE_DATA    2

#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1

#define HIP_SPI_DIRECTION_OUT 1
#define HIP_SPI_DIRECTION_IN 2

#define SEND_UPDATE_ESP_INFO (1 << 0)
#define SEND_UPDATE_LOCATOR (1 << 1)


#define HIP_ESCROW_OPERATION_ADD	1
#define HIP_ESCROW_OPERATION_MODIFY	2
#define HIP_ESCROW_OPERATION_DELETE	3

/* Returns length of TLV option (contents) with padding. */
#define HIP_LEN_PAD(len) \
    ((((len) & 0x07) == 0) ? (len) : ((((len) >> 3) << 3) + 8))

#define HIP_AH_SHA_LEN                 20

/* HIP_IFCS takes a pointer and an command to execute.
   it executes the command exec if cond != NULL */ 
#define HIP_IFCS(condition, consequence)\
	 if( condition ) {	\
	 	consequence ; 						\
	 } else {							\
	 	HIP_ERROR("No state information found.\n");		\
	 }
	 								
typedef struct in6_addr hip_hit_t;
typedef struct in_addr hip_lsi_t;
typedef uint16_t se_family_t;
typedef uint16_t se_length_t;
typedef uint16_t se_hip_flags_t;
typedef uint32_t sa_eid_t;
typedef uint8_t hip_hdr_type_t;
typedef uint8_t hip_hdr_len_t;
typedef uint16_t hip_hdr_err_t;
typedef uint16_t hip_tlv_type_t;
typedef uint16_t hip_tlv_len_t;
typedef struct hip_hadb_state hip_ha_t;
typedef struct hip_hadb_rcv_func_set hip_rcv_func_set_t;
typedef struct hip_hadb_handle_func_set hip_handle_func_set_t;
typedef struct hip_hadb_update_func_set hip_update_func_set_t;
typedef struct hip_hadb_misc_func_set hip_misc_func_set_t;
typedef struct hip_hadb_xmit_func_set hip_xmit_func_set_t;
typedef struct hip_hadb_input_filter_func_set hip_input_filter_func_set_t;
typedef struct hip_hadb_output_filter_func_set hip_output_filter_func_set_t;

/* todo: remove HIP_HASTATE_SPIOK */
typedef enum { HIP_HASTATE_INVALID=0, HIP_HASTATE_SPIOK=1,
	       HIP_HASTATE_HITOK=2, HIP_HASTATE_VALID=3 } hip_hastate_t;
/*
 * Use accessor functions defined in builder.c, do not access members
 * directly to avoid hassle with byte ordering and number conversion.
 */
struct hip_common {
	uint8_t      payload_proto;
	uint8_t      payload_len;
	uint8_t      type_hdr;
	uint8_t      ver_res;

	uint16_t     checksum;
	uint16_t     control;

	struct in6_addr hits;  /* Sender HIT   */
	struct in6_addr hitr;  /* Receiver HIT */
} __attribute__ ((packed));


/*
 * hip stateless info: Used to send parameters 
 * across function calls carrying stateless info
 */
struct hip_stateless_info 
{
	uint32_t src_port;
	uint32_t dst_port;
};

/*
 * Localhost Host Identity. Used only internally in the implementation.
 * Used for wrapping anonymous bit with the corresponding HIT.
 */
struct hip_lhi
{
	uint16_t           anonymous; /* Is this an anonymous HI */
	struct in6_addr    hit;
} __attribute__ ((packed));


/*
 * Use accessor functions defined in hip_build.h, do not access members
 * directly to avoid hassle with byte ordering and length conversion.
 */ 
struct hip_tlv_common {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
} __attribute__ ((packed));

#if 0
struct hip_i1 {
	uint8_t         payload_proto;
	hip_hdr_len_t   payload_len;
	hip_hdr_type_t  type_hdr;
	uint8_t         ver_res;

	uint16_t        control;
	uint16_t        checksum;

	struct in6_addr hits;  /* Sender HIT   */
	struct in6_addr hitr;  /* Receiver HIT */
} __attribute__ ((packed));
#endif

struct hip_keymat_keymat
{
	size_t offset;      /* Offset into the key material */
	size_t keymatlen;   /* Length of the key material */

	void *keymatdst; /* Pointer to beginning of key material */
};

/*
 * Used in executing a unit test case in a test suite in the kernel module.
 */
struct hip_unit_test {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
	uint16_t           suiteid;
	uint16_t           caseid;
} __attribute__ ((packed));

#if 0
/* XX FIXME: obsoleted by esp_info in draft-ietf-esp-00 */
struct hip_spi {
	hip_tlv_type_t      type;
	hip_tlv_len_t      length;

	uint32_t      spi;
} __attribute__ ((packed));
#endif

struct hip_esp_info {
	hip_tlv_type_t      type;
	hip_tlv_len_t      length;

	uint16_t reserved;
	uint16_t keymat_index;
	uint32_t old_spi;
	uint32_t new_spi;
} __attribute__ ((packed));

struct hip_r1_counter {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;

	uint32_t           reserved;
	uint64_t           generation;
} __attribute__ ((packed));


struct hip_puzzle {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t           K;
	uint8_t           lifetime;
	uint8_t           opaque[HIP_PUZZLE_OPAQUE_LEN];
	uint64_t          I;
} __attribute__ ((packed));

struct hip_solution {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t           K;
	uint8_t           reserved;
	uint8_t           opaque[HIP_PUZZLE_OPAQUE_LEN];
	uint64_t          I;
	uint64_t          J;
} __attribute__ ((packed));

struct hip_diffie_hellman {
	hip_tlv_type_t    type;
	hip_tlv_len_t     length;

	uint8_t           group_id;  
	/* fixed part ends */
        uint8_t           public_value[0];
} __attribute__ ((packed));

typedef uint16_t hip_transform_suite_t;

struct hip_hip_transform {
	hip_tlv_type_t        type;
	hip_tlv_len_t         length;

	hip_transform_suite_t suite_id[HIP_TRANSFORM_HIP_MAX];
} __attribute__ ((packed));

struct hip_esp_transform {
	hip_tlv_type_t        type;
	hip_tlv_len_t         length;

	uint16_t reserved;

	hip_transform_suite_t suite_id[HIP_TRANSFORM_ESP_MAX];
} __attribute__ ((packed));

/*
 * XX FIXME: HIP AND ESP TRANSFORM ARE NOT SYMMETRIC (RESERVED)
 */
struct hip_any_transform {
	hip_tlv_type_t        type;
	hip_tlv_len_t         length;
		/* XX TODO: replace with MAX(HIP, ESP) */
	hip_transform_suite_t suite_id[HIP_TRANSFORM_HIP_MAX +
				       HIP_TRANSFORM_ESP_MAX];
} __attribute__ ((packed));

/* RFC2535 3.1 KEY RDATA format */
struct hip_host_id_key_rdata {
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	/* fixed part ends */
} __attribute__ ((packed));

struct hip_host_id {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;

	uint16_t     hi_length;
	uint16_t     di_type_length;

	struct hip_host_id_key_rdata rdata;
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted_aes_sha1 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

        uint32_t     reserved;
	uint8_t      iv[16];
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted_3des_sha1 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

        uint32_t     reserved;
	uint8_t      iv[8];
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted_null_sha1 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

        uint32_t     reserved;
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_sig {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t      algorithm;
	uint8_t      signature[0]; /* variable length */

	/* fixed part end */
} __attribute__ ((packed));

struct hip_sig2 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t      algorithm;
	uint8_t      signature[0]; /* variable length */

	/* fixed part end */
} __attribute__ ((packed));

#if 0
/* XX FIXME: obsoloted by esp_info in draft-esp-00 */
struct hip_nes {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint16_t reserved;
	uint16_t keymat_index;
	uint32_t old_spi;
	uint32_t new_spi;
} __attribute__ ((packed));
#endif

struct hip_seq {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint32_t update_id;
} __attribute__ ((packed));

struct hip_ack {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint32_t peer_update_id; /* n items */
} __attribute__ ((packed));

struct hip_notify {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint16_t reserved;
	uint16_t msgtype;
	/* end of fixed part */
} __attribute__ ((packed));

#if 0
/* XX FIX: depracated in mm-02, use the locator addr item structure */
struct hip_rea_info_addr_item {
	uint32_t lifetime;
	uint32_t reserved;
	struct in6_addr address;
}  __attribute__ ((packed));
#endif

struct hip_locator_info_addr_item {
	uint8_t traffic_type;
	uint8_t locator_type;
	uint8_t locator_length;
	uint8_t reserved;
	uint32_t lifetime;
	/* end of fixed part - locator of arbitrary length follows but 
	   currently support only IPv6 */
	struct in6_addr address;
	int state; /*State of our addresses,
		     possible states are:
		     WAITING_ECHO_REQUEST, ACTIVE
		   */

}  __attribute__ ((packed));

#if 0
/* XX FIX: depracated in mm-02, use the locator structure */
struct hip_rea {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint32_t spi;
	/* fixed part ends */
} __attribute__ ((packed));
#endif

struct hip_locator {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_hmac {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t hmac_data[HIP_AH_SHA_LEN];
} __attribute__ ((packed));

struct hip_cert {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;

	uint8_t  cert_count;
	uint8_t  cert_id;
	uint8_t  cert_type;
	/* end of fixed part */
} __attribute__ ((packed));

/************* RVS *******************/

struct hip_rva_request {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint32_t       lifetime;
	/* RVA types */
} __attribute__ ((packed));

struct hip_rva_reply {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint32_t       lifetime;
	/* RVA types */
} __attribute__ ((packed));

struct hip_rva_hmac {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t hmac_data[HIP_AH_SHA_LEN];
} __attribute__ ((packed));

struct hip_from {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t address[16];
} __attribute__ ((packed));

struct hip_to {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t address[16];
} __attribute__ ((packed));

struct hip_via_rvs {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t address[16];
	/* the rest of the addresses */
} __attribute__ ((packed));

struct hip_echo_request {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	/* opaque */
} __attribute__ ((packed));

struct hip_echo_response {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	/* opaque */
} __attribute__ ((packed));

/* Structure describing an endpoint. This structure is used by the resolver in
 * the userspace, so it is not length-padded like HIP parameters. All of the
 * members are in network byte order.
 */
struct endpoint {
	se_family_t   family;    /* PF_HIP, PF_XX */
	se_length_t   length;    /* length of the whole endpoint in octets */
};

/*
 * Note: not padded
 */
struct endpoint_hip {
	se_family_t         family; /* PF_HIP */
	se_length_t         length; /* length of the whole endpoint in octets */
	se_hip_flags_t      flags;  /* e.g. ANON or HIT */
	union {
		struct hip_host_id host_id;
		struct in6_addr hit;
	} id;
};

struct sockaddr_eid {
	unsigned short int eid_family;
	uint16_t eid_port;
	sa_eid_t eid_val;
} __attribute__ ((packed));

/*
 * This structure is by the native API to carry local and peer identities
 * from libc (setmyeid and setpeereid calls) to the HIP socket handler
 * (setsockopt). It is almost the same as endpoint_hip, but it is
 * length-padded like HIP parameters to make it usable with the builder
 * interface.
 */
struct hip_eid_endpoint {
	hip_tlv_type_t      type;
	hip_tlv_len_t       length;
	struct endpoint_hip endpoint;
} __attribute__ ((packed));

typedef uint16_t hip_eid_iface_type_t;

struct hip_eid_iface {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	hip_eid_iface_type_t if_index;
} __attribute__ ((packed));

struct hip_eid_sockaddr {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	struct sockaddr sockaddr;
} __attribute__ ((packed));

/* Both for storing peer host ids and localhost host ids */
#define HIP_HOST_ID_MAX                16
#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */

struct hip_crypto_key {
	char key[HIP_MAX_KEY_LEN];
};


/******** ESCROW *********/

struct hip_reg_info {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t       min_lifetime;
	uint8_t       max_lifetime;
} __attribute__ ((packed));


struct hip_reg_request {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t       lifetime;
} __attribute__ ((packed));

struct hip_reg_failed {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t       failure_type;
} __attribute__ ((packed));


struct hip_keys {
	hip_tlv_type_t 	type;
	hip_tlv_len_t 	length;
	uint16_t 		operation;
	uint16_t 		alg_id;
	uint8_t 		address[16];
	uint8_t 		hit[16];
	uint32_t 		spi;
	uint32_t 		spi_old;
	uint16_t 		key_len;
	struct hip_crypto_key enc;
	//int direction; // ?
} __attribute__ ((packed));




struct hip_context
{
	//struct sk_buff *skb_in;         /* received skbuff */
	struct hip_common *input;       /* received packet */
	struct hip_common *output;      /* packet to be built and sent */

	struct hip_crypto_key hip_enc_out;
	struct hip_crypto_key hip_hmac_out;
	struct hip_crypto_key esp_out;
	struct hip_crypto_key auth_out;

	struct hip_crypto_key hip_enc_in;
	struct hip_crypto_key hip_hmac_in;
	struct hip_crypto_key esp_in;
	struct hip_crypto_key auth_in;

	char   *dh_shared_key;
	size_t dh_shared_key_len;

	uint16_t current_keymat_index; /* the byte offset index in draft chapter HIP KEYMAT */
	unsigned char current_keymat_K[HIP_AH_SHA_LEN];
	uint8_t keymat_calc_index; /* the one byte index number used
				    * during the keymat calculation */
	uint16_t keymat_index; /* KEYMAT offset */
	uint16_t esp_keymat_index; /* pointer to the esp keymat index */
};

struct hip_packet_dh_sig
{
	struct hip_common *common; 
	struct hip_diffie_hellman *dh;
	struct hip_host_id *host_id;
	struct hip_sig2 *hsig2;
};

struct hip_context_dh_sig
{
	struct hip_common *out_packet;                 /* kmalloced */
	struct hip_packet_dh_sig hip_out; /* packet to be built and sent */
};

struct hip_peer_addr_list_item
{
	struct list_head list;

	struct in6_addr  address;
	int              address_state; /* current state of the
					 * address (PEER_ADDR_STATE_xx) */
	int              is_preferred;  /* 1 if this address was set as
					   preferred address in the LOCATOR */
	uint32_t         lifetime;
	struct timeval   modified_time; /* time when this address was
					   added or updated */
	uint32_t         seq_update_id; /* the Update ID in SEQ parameter
					   this address is related to */
	uint8_t          echo_data[4];  /* data put into the ECHO_REQUEST parameter */
};

/* for HIT-SPI hashtable only */
struct hip_hit_spi {
	struct list_head list;
	spinlock_t       lock;
	atomic_t         refcnt;
	hip_hit_t        hit_our;
	hip_hit_t        hit_peer;
	uint32_t         spi; /* this SPI spi belongs to the HIT hit */
};

struct hip_spi_in_item
{
	struct list_head list;
	uint32_t         spi;
	uint32_t         new_spi; /* SPI is changed to this when rekeying */
        /* ifindex if the netdev to which this is related to */
	int              ifindex;
	unsigned long    timestamp; /* when SA was created */
	int              updating; /* UPDATE is in progress */
	uint32_t         esp_info_spi_out; /* UPDATE, the stored outbound
					    * SPI related to the inbound
					    * SPI we sent in reply (useless?)*/
	uint16_t         keymat_index; /* advertised keymat index */
	int              update_state_flags; /* 0x1=received ack for
						sent SEQ, 0x2=received
						peer's ESP_INFO,
						both=0x3=can move back
						to established */
        /* the Update ID in SEQ parameter these SPI are related to */
	uint32_t seq_update_id;
        /* the corresponding esp_info of peer */
	struct hip_esp_info stored_received_esp_info;
        /* our addresses this SPI is related to, reuse struct to ease coding */
	struct hip_locator_info_addr_item *addresses;
	int addresses_n; /* number of addresses */
};

struct hip_spi_out_item
{
	struct list_head list;
	uint32_t         spi;
	uint32_t         new_spi;   /* spi is changed to this when rekeying */
	uint32_t         seq_update_id; /* USELESS, IF SEQ ID WILL BE RELATED TO ADDRESS ITEMS,
					 * NOT OUTBOUND SPIS *//* the Update ID in SEQ parameter these SPI are related to */

	struct list_head peer_addr_list; /* Peer's IPv6 addresses */
	struct in6_addr  preferred_address; /* check */
};

struct hip_hadb_state
{
	struct list_head     next_hit;
	spinlock_t           lock;
	atomic_t             refcnt;

	hip_hastate_t        hastate;
	int                  state;
	int                  update_state;
	uint16_t             local_controls;
	uint16_t             peer_controls;
	hip_hit_t            hit_our;        /* The HIT we use with this host */
	hip_hit_t            hit_peer;       /* Peer's HIT */
	hip_hit_t            hash_key;       /* hit_our XOR hit_peer */
	struct list_head     spis_in;        /* SPIs for inbound SAs,  hip_spi_in_item  */
	struct list_head     spis_out;       /* SPIs for outbound SAs, hip_spi_out_item */
	uint32_t             default_spi_out;
	struct in6_addr      preferred_address; /* preferred peer address to use when
						 * sending data to peer */
        struct  in6_addr     local_address;   /* Our IP address */
  //	struct in6_addr      bex_address;    /* test, for storing address during the base exchange */
	hip_lsi_t            lsi_peer;
	hip_lsi_t            lsi_our;
	int                  esp_transform;
	uint64_t             birthday;
	char                 *dh_shared_key;
	size_t               dh_shared_key_len;

	uint16_t	     nat;    /* 1, if this hadb_state is behind nat */
	uint32_t	     peer_udp_port;    /* NAT mangled port */
	//struct in6_addr      peer_udp_address; /* NAT address */
	int					escrow_used;
	struct in6_addr		escrow_server_hit;
	/* The initiator computes the keys when it receives R1.
	 * The keys are needed only when R2 is received. We store them
	 * here in the mean time.
	 */
	struct hip_crypto_key hip_enc_out; /* outgoing HIP packets */
	struct hip_crypto_key hip_hmac_out;
	struct hip_crypto_key esp_out;  /* outgoing ESP packets */
	struct hip_crypto_key auth_out;
	struct hip_crypto_key hip_enc_in; /* incoming HIP packets */
	struct hip_crypto_key hip_hmac_in;
	struct hip_crypto_key esp_in; /* incoming ESP packets */
	struct hip_crypto_key auth_in;

	uint16_t current_keymat_index; /* the byte offset index in draft chapter HIP KEYMAT */
	uint8_t keymat_calc_index; /* the one byte index number used
				    * during the keymat calculation */
	uint16_t esp_keymat_index; /* for esp_info */
	unsigned char current_keymat_K[HIP_AH_SHA_LEN]; /* last Kn, where n is keymat_calc_index */
	uint32_t update_id_out; /* stored outgoing UPDATE ID counter */
	uint32_t update_id_in; /* stored incoming UPDATE ID counter */

	/* Our host identity functions */
	struct hip_host_id *our_pub;
	struct hip_host_id *our_priv;
	int (*sign)(struct hip_host_id *, struct hip_common *);
	
	/* Peer host identity functions */
        struct hip_host_id *peer_pub;
 	int (*verify)(struct hip_host_id *, struct hip_common *);

        uint64_t puzzle_solution; /* For retransmission */
	uint64_t puzzle_i;        /* For retransmission */

	char echo_data[4]; /* For base exchange or CLOSE, not for UPDATE */

	struct {
		int count;
		time_t last_transmit;
		struct in6_addr saddr, daddr;
		struct hip_common *buf;
	} hip_msg_retrans;

	/* function pointer sets for modifying hip behaviour based on state information */
	
	/* receive func set. Do not modify these values directly.
	   Use hip_hadb_set_rcv_function_set instead */
	hip_rcv_func_set_t *hadb_rcv_func;
	
	/* handle func set. Do not modify these values directly. 
	Use hip_hadb_set_handle_function_set instead */
	hip_handle_func_set_t *hadb_handle_func;

	/* handle func set. Do not modify these values directly. 
	Use hip_hadb_set_handle_function_set instead */
	hip_misc_func_set_t *hadb_misc_func;	

	/* handle func set. Do not modify these values directly. 
	Use hip_hadb_set_handle_function_set instead */
	hip_update_func_set_t *hadb_update_func;	

	/* transmission func set. Do not modify these values directly. 
	Use hip_hadb_set_handle_function_set instead */
	hip_xmit_func_set_t *hadb_xmit_func;

	/* For e.g. GUI agent */
	hip_input_filter_func_set_t *hadb_input_filter_func;
	hip_output_filter_func_set_t *hadb_output_filter_func;
};

struct hip_hadb_rcv_func_set {
	int (*hip_receive_i1)(struct hip_common *,
			      struct in6_addr *, 
			      struct in6_addr *,
			      hip_ha_t*,
			      struct hip_stateless_info *);

	int (*hip_receive_r1)(struct hip_common *,
				 struct in6_addr *, 
				 struct in6_addr *,
				 hip_ha_t*,
			      struct hip_stateless_info *);
				 
	/* as there is possibly no state established when i2
	messages are received, the hip_handle_i2 function pointer
	is not executed during the establishment of a new connection*/
	int (*hip_receive_i2)(struct hip_common *,
				 struct in6_addr *, 
				 struct in6_addr *,
				 hip_ha_t*,
			     struct hip_stateless_info *);
				 
	int (*hip_receive_r2)(struct hip_common *,
				 struct in6_addr *,
				 struct in6_addr *,
				 hip_ha_t*,
			     struct hip_stateless_info *);
				 
	int (*hip_receive_update)(struct hip_common *,
				  struct in6_addr *,
				  struct in6_addr *,
				  hip_ha_t*,
				  struct hip_stateless_info *);
				     
	int (*hip_receive_notify)(struct hip_common *,
				  struct in6_addr *,
				  struct in6_addr *,
				  hip_ha_t*);
  
	int (*hip_receive_bos)(struct hip_common *,
			       struct in6_addr *,
			       struct in6_addr *,
			       hip_ha_t*,
			       struct hip_stateless_info *);
				     
	int (*hip_receive_close)(struct hip_common *,
				 hip_ha_t*);
				       
	int (*hip_receive_close_ack)(struct hip_common *,
				     hip_ha_t*);	 
	
};

struct hip_hadb_handle_func_set{   
	int (*hip_handle_i1)(struct hip_common *r1,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     struct hip_stateless_info *);

	int (*hip_handle_r1)(struct hip_common *r1,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     struct hip_stateless_info *);
			     
	/* as there is possibly no state established when i2
	   messages are received, the hip_handle_i2 function pointer
	   is not executed during the establishment of a new connection*/
	int (*hip_handle_i2)(struct hip_common *i2,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *ha,
			     struct hip_stateless_info *i2_info);
			     
	int (*hip_handle_r2)(struct hip_common *r2,
			     struct in6_addr *r2_saddr,
			     struct in6_addr *r2_daddr,
			     hip_ha_t *ha,
			     struct hip_stateless_info *r2_info);
	int (*hip_handle_bos)(struct hip_common *bos,
			      struct in6_addr *r2_saddr,
			      struct in6_addr *r2_daddr,
			      hip_ha_t *ha,
			      struct hip_stateless_info *);
	int (*hip_handle_close)(struct hip_common *close,
				hip_ha_t *entry);
	int (*hip_handle_close_ack)(struct hip_common *close_ack,
				    hip_ha_t *entry);
};

struct hip_hadb_update_func_set{   
	int (*hip_handle_update_plain_locator)(hip_ha_t *entry, 
					       struct hip_common *msg,
					       struct in6_addr *src_ip,
					       struct in6_addr *dst_ip,
					       struct hip_esp_info *esp_info);

	int (*hip_handle_update_addr_verify)(hip_ha_t *entry,
					     struct hip_common *msg,
					     struct in6_addr *src_ip,
					     struct in6_addr *dst_ip);

	void (*hip_update_handle_ack)(hip_ha_t *entry,
				      struct hip_ack *ack,
				      int have_nes);				      

	int (*hip_handle_update_established)(hip_ha_t *entry,
					     struct hip_common *msg,
					     struct in6_addr *src_ip,
					     struct in6_addr *dst_ip,
					     struct hip_stateless_info *);
	int (*hip_handle_update_rekeying)(hip_ha_t *entry,
					  struct hip_common *msg,
					  struct in6_addr *src_ip);

	int (*hip_update_send_addr_verify)(hip_ha_t *entry,
					   struct hip_common *msg,
					   struct in6_addr *src_ip,
					   uint32_t spi);

	int (*hip_update_send_echo)(hip_ha_t *entry,
				    struct hip_peer_addr_list_item *addr,
			            uint32_t spi);	    
};

struct hip_hadb_misc_func_set{ 
	uint64_t (*hip_solve_puzzle)(void *puzzle,
				  struct hip_common *hdr,
				  int mode);  
	int (*hip_produce_keying_material)(struct hip_common *msg,
					   struct hip_context *ctx,
					   uint64_t I,
					   uint64_t J);
	int (*hip_create_i2)(struct hip_context *ctx, uint64_t solved_puzzle, 
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     struct hip_stateless_info *);
	int (*hip_create_r2)(struct hip_context *ctx,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *entry,
			     struct hip_stateless_info *);
	void (*hip_build_network_hdr)(struct hip_common *msg, uint8_t type_hdr,
				      uint16_t control,
				      const struct in6_addr *hit_sender,
				      const struct in6_addr *hit_receiver);
};

struct hip_hadb_xmit_func_set{ 
	int  (*hip_csum_send)(struct in6_addr *local_addr,
			      struct in6_addr *peer_addr,
			      uint32_t src_port, uint32_t dst_port,
			      struct hip_common* msg,
			      hip_ha_t *entry,
			      int retransmit);
};

struct hip_hadb_input_filter_func_set { 
	int (*hip_input_filter)(struct hip_common *msg);
};

struct hip_hadb_output_filter_func_set { 
	int (*hip_output_filter)(struct hip_common *msg);
};


struct hip_cookie_entry {
	int used;
	struct in6_addr peer_hit;
	uint64_t i;
	uint64_t j; /* not needed ? */
	uint64_t  k;
	uint64_t hash_target;
	struct in6_addr initiator;
	struct in6_addr responder;
};

struct hip_work_order_hdr {
	int type;
	int subtype;
	struct in6_addr id1, id2, id3; /* can be a HIT or IP address */
	int arg1, arg2, arg3;
};

struct hip_work_order {
	struct hip_work_order_hdr hdr;
	struct hip_common *msg; /* NOTE: reference only with &hwo->msg ! */
	uint32_t seq;
	struct list_head queue;
	void (*destructor)(struct hip_work_order *hwo);
};

/* Do not move this before the definition of struct endpoint, as i3
   headers refer to libinet6 headers which in turn require the
   definition of the struct. */
#ifdef CONFIG_HIP_HI3
#   include "i3_client_api.h" 
#endif

struct hip_host_id_entry {
/* this needs to be first (list_for_each_entry, list 
   head being of different type) */
	struct list_head next; 

	struct hip_lhi lhi;
	hip_lsi_t lsi;
	/* struct in6_addr ipv6_addr[MAXIP]; */
	struct hip_host_id *host_id; /* allocated dynamically */
	struct hip_r1entry *r1; /* precreated R1s */
	/* Handler to call after insert with an argument, return 0 if OK*/
	int (*insert)(struct hip_host_id_entry *, void **arg);
	/* Handler to call before remove with an argument, return 0 if OK*/
	int (*remove)(struct hip_host_id_entry *, void **arg);
	void *arg;
};

struct hip_eid_owner_info {
	uid_t            uid;
	gid_t            gid;
	pid_t            pid;
	se_hip_flags_t   flags;  /* HIP_HI_REUSE_* */
};

struct hip_eid_db_entry {
	struct list_head           next;
	struct hip_eid_owner_info  owner_info;
	struct sockaddr_eid        eid; /* XX FIXME: the port is unneeded */
	struct hip_lhi             lhi;
	int                        use_cnt;
};

#define HIP_UNIT_ERR_LOG_MSG_MAX_LEN 200

/* Some default settings for HIPL */
#define HIP_DEFAULT_AUTH             HIP_AUTH_SHA    /* AUTH transform in R1 */
#define HIP_DEFAULT_RVA_LIFETIME     600             /* in seconds? */
#define GOTO_OUT -3

#define HIP_IFE(func, eval) \
{ \
	if (func) { \
		err = eval; \
		goto out_err; \
	} \
}

#define HIP_IFEL(func, eval, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
		goto out_err; \
	} \
}

#define HIP_IFEB(func, eval, finally) \
{ \
	if (func) { \
		err = eval; \
                finally;\
		goto out_err; \
	} else {\
		finally;\
        }\
}

#define HIP_IFEBL(func, eval, finally, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
                finally;\
		goto out_err; \
	} else {\
		finally;\
        }\
}

#define HIP_IFEBL2(func, eval, finally, args...) \
{ \
	if (func) { \
		HIP_ERROR(args); \
		err = eval; \
                finally;\
        }\
}
#ifndef MIN
#  define MIN(a,b)	((a)<(b)?(a):(b))
#endif

#ifndef MAX
#  define MAX(a,b)	((a)>(b)?(a):(b))
#endif

/* used by hip worker to announce completion of work order */
#define KHIPD_OK                   0
#define KHIPD_QUIT                -1
#define KHIPD_ERROR               -2
#define KHIPD_UNRECOVERABLE_ERROR -3
#define HIP_MAX_SCATTERLISTS       5 // is this enough?

int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
void hip_net_event(int ifindex, uint32_t event_src, uint32_t event);

extern struct socket *hip_output_socket;
extern time_t load_time;

#endif /* _NET_HIP */

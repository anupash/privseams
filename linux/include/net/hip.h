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
 *
 *  TODO:
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
#  include <linux/types.h>
#  include <linux/config.h>
#  include <linux/module.h>
#  include <linux/kernel.h>
#  include <linux/slab.h>
#  include <linux/errno.h>
#  include <linux/skbuff.h>
#  include <net/ip.h>
#  include <net/sock.h>
#  include <asm/string.h>
#  include <asm/byteorder.h>
#  include <linux/in6.h>
#  include <linux/timer.h>
#  include <linux/time.h>
#  include <linux/ioctl.h>

typedef uint16_t in_port_t;

#else
#  include <sys/ioctl.h>
#  include <netinet/in.h>

#endif /* __KERNEL__ */

#define HIP_MAX_PACKET 2048

#define HIP_HIT_KNOWN 1
#define HIP_HIT_ANON  2

#define HIP_HIT_TYPE_MASK_HAA   0x80
#define HIP_HIT_TYPE_MASK_126   0x40

#define HIP_HIT_TYPE_HASH126    1
#define HIP_HIT_TYPE_HAA_HASH   2

#define HIP_I1  1
#define HIP_R1  2
#define HIP_I2  3
#define HIP_R2  4
#define HIP_UPDATE 5
#define HIP_REA 6 /* xxx */
#define HIP_BOS 7
#define HIP_CER 8
#define HIP_NOTIFY 9
#define HIP_AC 15   /* conflicts now with notify packet */
#define HIP_ACR 16 /* moved from 10 -> 16 */
#define HIP_PAYLOAD 64 /* xxx */

#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2

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

#define HIP_HOST_ID_HOSTNAME_LEN_MAX 64

#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
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
#define HIP_CONTROL_CERTIFICATES    0x0002   /* Certificate packets follow */
#define HIP_CONTROL_HIT_ANON        0x0001   /* Anonymous HI */
#define HIP_CONTROL_NONE            0x0000

#define HIP_VER_RES                 0x10     /* Version 1, reserved 0 */
#define HIP_VER_MASK                0xF0
#define HIP_RES_MASK                0x0F 

#define HIP_STATE_NONE              0      /* No state, structure unused */
#define HIP_STATE_UNASSOCIATED      1      /* ex-E0 */
#define HIP_STATE_I1_SENT           2      /* ex-E1 */
#define HIP_STATE_I2_SENT           3      /* ex-E2 */
#define HIP_STATE_R2_SENT           4
#define HIP_STATE_ESTABLISHED       5      /* ex-E3 */
#define HIP_STATE_REKEYING          6      /* ex-E4 */
#define HIP_STATE_FAILED            7

#define HIP_PARAM_MIN                 -1 /* exclusive */

#define HIP_PARAM_SPI                  1
#define HIP_PARAM_R1_COUNTER           2
#define HIP_PARAM_REA                  3
#define HIP_PARAM_PUZZLE               5
#define HIP_PARAM_SOLUTION             7
#define HIP_PARAM_NES                  9
#define HIP_PARAM_SEQ                 11
#define HIP_PARAM_ACK                 13
#define HIP_PARAM_DIFFIE_HELLMAN      15
#define HIP_PARAM_HIP_TRANSFORM       17
#define HIP_PARAM_ESP_TRANSFORM       19
#define HIP_PARAM_ENCRYPTED           21
#define HIP_PARAM_HOST_ID             35
#define HIP_PARAM_CERT                64
#define HIP_PARAM_RVA_REQUEST        100
#define HIP_PARAM_RVA_REPLY          102

#define HIP_PARAM_REA_INFO           128
#define HIP_PARAM_AC_INFO            129 /* mm-01: to be removed */
#define HIP_PARAM_FA_INFO            130 /* mm-01: to be removed */

#define HIP_PARAM_NOTIFY             256
#define HIP_PARAM_ECHO_REQUEST_SIGN    1022
#define HIP_PARAM_ECHO_RESPONSE_SIGN   1024

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
/* End of HIPL private parameters. */

#define HIP_PARAM_FROM_SIGN       65100
#define HIP_PARAM_TO_SIGN         65102
#define HIP_PARAM_HMAC            65245
#define HIP_PARAM_HIP_SIGNATURE2  65277
#define HIP_PARAM_HIP_SIGNATURE   65279
#define HIP_PARAM_ECHO_REQUEST    65281
#define HIP_PARAM_ECHO_RESPONSE   65283
#define HIP_PARAM_FROM            65300
#define HIP_PARAM_TO              65302
#define HIP_PARAM_RVA_HMAC        65320
#define HIP_PARAM_VIA_RVS         65500
#define HIP_PARAM_MAX             65536 /* exclusive */


#define HIP_HIP_RESERVED                0
#define HIP_HIP_AES_SHA1                1
#define HIP_HIP_3DES_SHA1               2
#define HIP_HIP_3DES_MD5                3
#define HIP_HIP_NULL_SHA1               5
#define HIP_HIP_NULL_SHA1               5

#define HIP_TRANSFORM_HIP_MAX           6
#define HIP_TRANSFORM_ESP_MAX           6

#define HIP_ESP_RESERVED                0
#define HIP_ESP_AES_SHA1                1
#define HIP_ESP_3DES_SHA1               2
#define HIP_ESP_3DES_MD5                3
#define HIP_ESP_BLOWFISH_SHA1           4
#define HIP_ESP_NULL_SHA1               5
#define HIP_ESP_NULL_MD5                6

/* Only for testing!!! */
#define HIP_ESP_NULL_NULL            0x0

#define HIP_DH_384                    1 /* 384-bit group */
#define HIP_DH_OAKLEY_1               2 /* 768-bit OAKLEY well known group 1 */
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
#define HIP_DH_OAKLEY_17              5 /* 6144-bit MODP group */
#define HIP_DH_OAKLEY_18              6 /* 8192-bit MODP group */
#define HIP_DEFAULT_DH_GROUP_ID       HIP_DH_OAKLEY_5

#define HIP_HI_DSA                    3
#define HIP_SIG_DSA                   3

#define HIP_DIGEST_MD5                1
#define HIP_DIGEST_SHA1               2
#define HIP_DIGEST_SHA1_HMAC          3
#define HIP_DIGEST_MD5_HMAC           4

#define HIP_DIRECTION_ENCRYPT         1
#define HIP_DIRECTION_DECRYPT         2

#define HIP_KEYMAT_INDEX_NBR_SIZE     1

#define HIP_VERIFY_PUZZLE             0
#define HIP_SOLVE_PUZZLE              1
#define HIP_PUZZLE_OPAQUE_LEN         3

#define HIP_PARAM_ENCRYPTED_IV_LEN    8

#define HIP_DSA_SIGNATURE_LEN        41

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

/* Returns length of TLV option (contents) with padding. */
#define HIP_LEN_PAD(len) \
    ((((len) & 0x07) == 0) ? (len) : ((((len) >> 3) << 3) + 8))

#ifdef __KERNEL__
 #ifndef hton64
 #define hton64(n) __cpu_to_be64(n)
 #endif
 #ifndef ntoh64
 #define ntoh64(n) __be64_to_cpu(n)
 #endif
#else
 #if __BYTE_ORDER == __BIG_ENDIAN
  #define hton64(i) (i)
  #define ntoh64(i) (i)
 #else
  #define hton64(i) ( ((__u64)(htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff ) )
  #define ntoh64 hton64
 #endif

#endif /* __KERNEL__ */


#define HIP_AH_SHA_LEN                 20

typedef struct in6_addr hip_hit_t;
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
typedef enum { HIP_HASTATE_INVALID=0, HIP_HASTATE_SPIOK=1,
	       HIP_HASTATE_HITOK=2, HIP_HASTATE_VALID=3 } hip_hastate_t;
/*
 * Use accessor functions defined in hip_build.h, do not access members
 * directly to avoid hassle with byte ordering and number conversion.
 */
struct hip_common {
	uint8_t      payload_proto;
	uint8_t      payload_len;
	uint8_t      type_hdr;
	uint8_t      ver_res;

	uint16_t     control;
	uint16_t     checksum;

	struct in6_addr hits;  /* Sender HIT   */
	struct in6_addr hitr;  /* Receiver HIT */
} __attribute__ ((packed));


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

struct hip_spi {
	hip_tlv_type_t      type;
	hip_tlv_len_t      length;

	uint32_t      spi;
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
	uint8_t           opaque[HIP_PUZZLE_OPAQUE_LEN];
	uint64_t          I;
} __attribute__ ((packed));

struct hip_solution {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;
	
	uint8_t           K;
	uint8_t           opaque[3];
	uint64_t          I;
	uint64_t          J;
} __attribute__ ((packed));

struct hip_diffie_hellman {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t      group_id;
	/* fixed part ends */
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

	/* fixed part end */
} __attribute__ ((packed));

struct hip_sig2 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t      algorithm;
	
	/* fixed part end */
} __attribute__ ((packed));

struct hip_nes {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint16_t reserved;
	uint16_t keymat_index;
	uint32_t old_spi;
	uint32_t new_spi;
} __attribute__ ((packed));


struct hip_seq {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint32_t update_id;
} __attribute__ ((packed));

struct hip_ack {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint32_t peer_update_id;
} __attribute__ ((packed));

struct hip_notify {
	hip_tlv_type_t type;
	hip_tlv_len_t length;

	uint16_t reserved;
	uint16_t msgtype;
	/* end of fixed part */
} __attribute__ ((packed));

struct hip_rea_info_addr_item {
	uint32_t lifetime;
	uint32_t reserved;
	struct in6_addr address;
}  __attribute__ ((packed));

struct hip_rea {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
  	uint32_t spi;
	/* fixed part ends */
} __attribute__ ((packed));

struct hip_rea_info {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint32_t interface_id;
	uint32_t current_spi_rev;
	uint32_t current_spi;
	uint32_t new_spi;
	uint16_t keymat_index;
	uint16_t rea_id;
} __attribute__ ((packed));

struct hip_hmac {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t hmac_data[HIP_AH_SHA_LEN];
} __attribute__ ((packed));

struct hip_ac_info { /* mm-01: to be removed */
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint16_t ac_id;
	uint16_t rea_id;
	uint32_t rtt;
	uint32_t reserved;
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
	in_port_t eid_port;
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

#ifdef __KERNEL__

#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */

/* Both for storing peer host ids and localhost host ids */
#define HIP_HOST_ID_MAX                16

struct hip_crypto_key {
	char key[HIP_MAX_KEY_LEN];
};

struct hip_packet_dh_sig
{
	struct hip_common *common; 
	struct hip_diffie_hellman *dh;
	struct hip_host_id *host_id;
	struct hip_sig2 *hsig2;
};

struct hip_context
{
	struct sk_buff *skb_in;         /* received skbuff */
	struct hip_common *input;       /* received packet */
	struct hip_common *output;      /* packet to be built and sent */
  /*
    struct hip_crypto_key hip_i;
    struct hip_crypto_key hip_r;
    struct hip_crypto_key hip_espi;
    struct hip_crypto_key hip_espr;
    struct hip_crypto_key hip_authi;
    struct hip_crypto_key hip_authr;
    struct hip_crypto_key hip_hmaci;
    struct hip_crypto_key hip_hmacr;
  */
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
};

struct hip_context_dh_sig
{
	struct hip_common *out_packet;                 /* kmalloced */
	struct hip_packet_dh_sig hip_out; /* packet to be built and sent */
};

struct hip_context_rea_sig
{
	struct hip_common *out_packet;                 /* kmalloced */
	struct hip_hadb_state *entry;
	int netdev_flags;   /* indicates how REA is sent, see #defines below */
};

/* flags for struct hip_context_rea_sig */
#define REA_OUT_NETDEV_ANY 0   /* REA can be sent out from any interface */
#define REA_OUT_NETDEV_GIVEN 1 /* REA must be sent out from given interface */

struct hip_peer_addr_list_item
{
	struct list_head list;
	uint32_t         interface_id;
	struct in6_addr  address;
	int address_state;              /* current state of the
					 * address (PEER_ADDR_STATE_xx) */
	uint32_t         lifetime;
	struct timeval   modified_time; /* time when this address was
					   added or updated */
};

/* peer address is assumed to be currently reachable */
#define PEER_ADDR_STATE_REACHABLE 1
/* peer address is assumed not to be currently reachable */
#define PEER_ADDR_STATE_UNREACHABLE 2

struct hip_hadb_state
{
	struct list_head     next_hit;
	struct list_head     next_spi;


	spinlock_t           lock;
	atomic_t             refcnt;
	hip_hastate_t        hastate;

	int                  state;

	uint16_t             local_controls;
	uint16_t             peer_controls;  

	hip_hit_t            hit_our;        /* The HIT we use with this host */
	hip_hit_t            hit_peer;       /* Peer's HIT */
	struct list_head     peer_addr_list; /* Peer's IPv6 addresses */

	uint32_t             spi_out;       /* outbound IPsec SA SPI */
	uint32_t             spi_in;        /* inbound IPsec SA SPI */
	uint32_t             new_spi_out;   /* new outbound IPsec SA SPI received in UPDATE */
	uint32_t             new_spi_in;    /* new inbound IPsec SA SPI when rekey was initiated */

	uint32_t             lsi_peer;
	uint32_t             lsi_our;

	int                  esp_transform;

	uint64_t             birthday;
	
	char                 *dh_shared_key;
	size_t               dh_shared_key_len;

	/* The initiator computes the keys when it receives R1.
	 * The keys are needed only when R2 is received. We store them
	 * here in the mean time.
	 */
#if 0
	struct hip_crypto_key esp_our; //espi_key;
	struct hip_crypto_key esp_peer; //spr_key;
	struct hip_crypto_key auth_our; //authi_key;
	struct hip_crypto_key auth_peer; //authr_key;
	struct hip_crypto_key hmac_our;
	struct hip_crypto_key hmac_peer;
#endif
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
	unsigned char current_keymat_K[HIP_AH_SHA_LEN]; /* last Kn, where n is keymat_calc_index */

	uint32_t update_id_out; /* stored outgoing UPDATE ID counter */
	uint32_t update_id_in; /* stored incoming UPDATE ID counter */
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

struct hip_sent_rea_info {
	struct list_head list;
	uint16_t rea_id; /* sent REA ID in network byte order */
	struct in6_addr hit; /* HIT where this REA was sent to*/
	atomic_t use_count;
	struct timer_list timer;
};

struct hip_sent_ac_info { /* mm-01: to be removed */
	struct list_head list;
	uint16_t ac_id; /* sent AC ID in network byte order */
	uint16_t rea_id; /* corresponding REA ID in network byte order */
	struct in6_addr ip; /* IPv6 address where this REA was sent to */
	uint32_t interface_id;
	uint32_t lifetime;
	uint32_t rtt_sent;
	/* struct timeval rtt_sent ?*/
	//unsigned long rtt_sent; /* jiffies value when this packet was sent out */
	struct timer_list timer;
};

struct hip_work_order {
	int type;
	int subtype;
	void *arg1;
	void *arg2;
	union {
		char ch[8];
		uint32_t u32[2];
		uint64_t u64;
	} arg;
	struct list_head queue;
	void (*destructor)(struct hip_work_order *hwo);
};


struct hip_host_id_entry {
/* this needs to be first (list_for_each_entry, list 
   head being of different type) */
	struct list_head next; 

	struct hip_lhi lhi;
	/* struct in_addr lsi; */
	/* struct in6_addr ipv6_addr[MAXIP]; */
	struct hip_host_id *host_id; /* allocated dynamically */
};

struct hip_eid_owner_info {
	uid_t uid;
	gid_t gid;
};

struct hip_eid_db_entry {
	struct list_head           next;
	struct hip_eid_owner_info  owner_info;
	struct sockaddr_eid        eid; /* XX FIXME: the port is unneeded */
	struct hip_lhi             lhi;
};





#define HIP_UNIT_ERR_LOG_MSG_MAX_LEN 200
#endif /* __KERNEL__ */

/* Some default settings for HIPL */
#define HIP_DEFAULT_HIP_ENCR         HIP_ENCR_3DES   /* HIP transform in R1 */
#define HIP_DEFAULT_ESP_ENCR         HIP_ENCR_3DES   /* ESP transform in R1 */
#define HIP_DEFAULT_AUTH             HIP_AUTH_SHA    /* AUTH transform in R1 */
#define HIP_DEFAULT_RVA_LIFETIME     600             /* in seconds? */
#endif /* _NET_HIP */

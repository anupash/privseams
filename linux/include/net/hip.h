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
 *
 *  BUGS:
 *  -
 *
 */

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/sock.h>
#include <asm/string.h>
#include <linux/hip_ioctl.h>
#include <asm/byteorder.h>
#include <linux/in6.h>
#include <linux/timer.h>

#else

#include <netinet/in.h>

#endif /* __KERNEL__ */

#define HIP_MAX_PACKET 2048

#define HIP_HIT_KNOWN 1
#define HIP_HIT_ANON  2

#define HIP_I1  1
#define HIP_R1  2
#define HIP_I2  3
#define HIP_R2  4
#define HIP_NES 5
#define HIP_REA 6
#define HIP_BOS 7
#define HIP_CER 8
#define HIP_AC 9   /* check */
#define HIP_ACR 10 /* check */

/* Extended message types for the daemon */
#define HIP_USER_BASE_MIN                  15 /* exclusive */
#define HIP_USER_NULL_OPERATION            16
#define HIP_USER_ADD_HI                    17
#define HIP_USER_DEL_HI                    18
#define HIP_USER_ADD_MAP_HIT_IP            19
#define HIP_USER_DEL_MAP_HIT_IP            20
#define HIP_USER_UNIT_TEST                 21
#define HIP_USER_RST                       22
#define HIP_USER_BASE_MAX                  23 /* exclusive */
/* End of extended messages for the daemon */

#define HIP_PAYLOAD 64


#define HIP_CONTROL_PIGGYBACK_ALLOW 0x4000   /* Host accepts piggybacked ESP in I2 and R2 */
#define HIP_CONTROL_CERTIFICATES    0x2000   /* Certificate packets follow */
#define HIP_CONTROL_ESP_64          0x1000   /* Use 64-bit sequence number */
#define HIP_CONTROL_HIT_ANON        0x0001   /* Anonymous HI */
#define HIP_CONTROL_NONE            0x0000

#define HIP_VER_RES                 0x10     /* Version 1, reserved 0 */
#define HIP_VER_MASK                0xF0
#define HIP_RES_MASK                0x0F 

#define HIP_STATE_NONE                0      /* No state, structure unused */
#define HIP_STATE_START               1      /* E0 */
#define HIP_STATE_INITIATING          2      /* E1 */
#define HIP_STATE_WAIT_FINISH         3      /* E2 */
#define HIP_STATE_ESTABLISHED         4      /* E3 */
#define HIP_STATE_ESTABLISHED_REKEY   5      /* E4 */

#define HIP_PARAM_MIN                -1 /* exclusive */
#define HIP_PARAM_SPI_LSI             1
#define HIP_PARAM_BIRTHDAY_COOKIE_R1  3
#define HIP_PARAM_BIRTHDAY_COOKIE_I2  5
#define HIP_PARAM_DH_FIXED            7
#define HIP_PARAM_NES_INFO           11
#define HIP_PARAM_HIP_TRANSFORM      17
#define HIP_PARAM_ESP_TRANSFORM      19
#define HIP_PARAM_ENCRYPTED          21
#define HIP_PARAM_HOST_ID            33
#define HIP_PARAM_HOST_ID_FQDN       35
#define HIP_PARAM_CERT               64
#define HIP_PARAM_REA_INFO          128
#define HIP_PARAM_AC_INFO           129 /* mm-01: to be removed */
#define HIP_PARAM_FA_INFO           130 /* mm-01: to be removed */

/* Range 32768 - 49141 can be used for HIPL private parameters. */
#define HIP_PARAM_HIT                   32768
#define HIP_PARAM_IPV6_ADDR             32769
#define HIP_PARAM_DSA_SIGN_DATA         32770 /* XX TODO: change to digest */
#define HIP_PARAM_HI                    32771
#define HIP_PARAM_DH_SHARED_KEY         32772
#define HIP_PARAM_UNIT_TEST             32773
/* End of HIPL private parameters. */

#define HIP_PARAM_HMAC            65245
#define HIP_PARAM_HIP_SIGNATURE2  65277

#define HIP_PARAM_HIP_SIGNATURE   65279
#define HIP_PARAM_MAX             65536 /* exclusive */

#define HIP_TRANSFORM_RESERVED          0
#define HIP_TRANSFORM_NULL              1
#define HIP_TRANSFORM_3DES              2
#define HIP_TRANSFORM_AES_128           3

#define HIP_TRANSFORM_HIP_MAX           3
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

#define HIP_PARAM_BIRTHDAY_LEN (sizeof(struct hip_birthday_cookie))
#define HIP_PARAM_SPI_LSI_LEN (sizeof(struct hip_spi_lsi))

#define HIP_DIRECTION_ENCRYPT         1
#define HIP_DIRECTION_DECRYPT         2

#define HIP_KEYMAT_INDEX_NBR_SIZE     1

#define HIP_VERIFY_PUZZLE             0
#define HIP_SOLVE_PUZZLE              1

#define HIP_PARAM_ENCRYPTED_IV_LEN    8

#define HIP_DSA_SIGNATURE_LEN         41

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

#if 0
struct hip_built_r1 {
	struct hip_built_r1    *next;      // Next in list 
	struct hip_common      *r1;         // Pointer to the kmalloced packet

	/* uint32_t last_send; Time after which this R1-data must
	   not be sent. */
	/* timer    del_timer; Timer which releases this
	   structure on expiry. */
};
#endif /* 0 */

typedef uint8_t hip_hdr_type_t;
typedef uint8_t hip_hdr_len_t;
typedef uint16_t hip_hdr_err_t;

/*
 * Localhost Host Identity. Used only internally in the implementation.
 * Used for wrapping anonymous bit with the corresponding HIT.
 */
struct hip_lhi
{
	uint16_t           anonymous; /* Is this an anonymous HI */
	struct in6_addr    hit;
} __attribute__ ((packed));

typedef uint16_t hip_tlv_type_t;
typedef uint16_t hip_tlv_len_t;

/*
 * Use accessor functions defined in hip_build.h, do not access members
 * directly to avoid hassle with byte ordering and length conversion.
 */ 
struct hip_tlv_common {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
} __attribute__ ((packed));

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


/*
 * Used in executing a unit test case in a test suite in the kernel module.
 */
struct hip_unit_test {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
	uint16_t           suiteid;
	uint16_t           caseid;
} __attribute__ ((packed));

struct hip_spi_lsi {
	hip_tlv_type_t      type;
	hip_tlv_len_t      length;

	uint32_t      reserved;

	uint32_t      spi;
	uint32_t      lsi;
} __attribute__ ((packed));


struct hip_birthday_cookie {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;
	
	uint32_t     reserved;

	uint64_t     birthday;
	uint64_t     val_i;
	uint64_t     val_jk;
} __attribute__ ((packed));

struct hip_dh_fixed {
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

	hip_transform_suite_t suite_id[HIP_TRANSFORM_ESP_MAX];
} __attribute__ ((packed));

struct hip_auth_transform {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint8_t      transform_id;
	uint16_t     transform_length;

	/* fixed part ends */
} __attribute__ ((packed));

struct hip_any_transform {
	hip_tlv_type_t        type;
	hip_tlv_len_t         length;
		/* XX TODO: replace with MAX(HIP, ESP) */
	hip_transform_suite_t suite_id[HIP_TRANSFORM_HIP_MAX +
				       HIP_TRANSFORM_ESP_MAX];
} __attribute__ ((packed));

struct hip_host_id {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;

	uint16_t     flags;
	uint8_t      protocol;
	uint8_t      algorithm;

	/* fixed part ends */
} __attribute__ ((packed));

struct hip_host_id_fqdn {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;

	uint16_t     hi_length;
	uint16_t     fqdn_length;

	uint16_t     flags;
	uint8_t      protocol;
	uint8_t      algorithm;

	/* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;
        uint32_t     reserved;
	uint8_t      iv[8];
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

struct hip_nes_info {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint16_t keymat_index;
	uint16_t nes_id;
	uint32_t old_spi;
	uint32_t new_spi;
} __attribute__ ((packed));


struct hip_rea_info_addr_item {
	uint32_t lifetime;
	uint32_t reserved;
	struct in6_addr address;
}  __attribute__ ((packed));

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
	/* XX TODO */
} __attribute__ ((packed));

#ifdef __KERNEL__

#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */

/* Both for storing peer host ids and localhost host ids */
#define HIP_HOST_ID_MAX                16

struct hip_crypto_key {
	char key[HIP_MAX_KEY_LEN];
};

struct hip_packet
{
	/* Pointers to all possible TLVs in the packet */
	/* todo: does not work with multiple TLVs of same type */
	struct hip_common *common; /* kmallocated, remember to free */
	struct hip_spi_lsi *spi_lsi;
	struct hip_birthday_cookie *bc;
	struct hip_dh_fixed *dhf;
	struct hip_dh *dh;
	struct hip_host_id *host_id;
	struct hip_host_id_fqdn *host_id_fqdn;
	struct hip_encrypted *enc;
	struct hip_sig *hsig;
	struct hip_sig2 *hsig2;
	struct hip_hmac *hmac;

	struct hip_hip_transform *hip_transform;
	struct hip_esp_transform *esp_transform;
	struct hip_cert *cert;
	struct hip_rea_info *rea;
	struct hip_ac_info *ac; /* mm-01: to be removed */
	struct hip_fa_info *fa; /* mm-01: to be removed */
};

struct hip_packet_dh_sig
{
	struct hip_common *common; 
	struct hip_dh_fixed *dhf;
	struct hip_host_id *host_id;
	struct hip_sig2 *hsig2;
};

struct hip_context
{
	struct sk_buff *skb_in;         /* received skbuff */
	struct hip_common *input;       /* received packet */
	struct hip_common *output;      /* packet to be built and sent */

	struct hip_crypto_key hip_i;
	struct hip_crypto_key hip_r;
	struct hip_crypto_key hip_espi;
	struct hip_crypto_key hip_espr;
	struct hip_crypto_key hip_authi;
	struct hip_crypto_key hip_authr;
	struct hip_crypto_key hip_hmaci;
	struct hip_crypto_key hip_hmacr;
};

struct hip_context_dh_sig
{
	struct hip_common *out_packet;                 /* kmalloced */
	struct hip_packet_dh_sig hip_out; /* packet to be built and sent */
};

struct hip_context_rea_sig
{
	struct hip_common *out_packet;                 /* kmalloced */
	struct hip_sdb_state *entry;
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
	struct list_head     next;
//	struct hip_sdb_state *next;

	int                  state;

	/* Controls received from the peer */
	uint16_t             peer_controls;

	struct in6_addr      hit_our;  /* The HIT we use with this host */
	struct in6_addr      hit_peer;       /* Peer's HIT */
	struct list_head     peer_addr_list; /* Peer's IPv6 addresses */

	uint32_t             spi_peer;
	uint32_t             spi_our;
	uint32_t             lsi_peer;
	uint32_t             lsi_our;

	int                  esp_transform;
//	int                  auth_transform;

	uint64_t             birthday;

	/* The initiator computes the keys when it receives R1.
	 * The keys are needed only when R2 is received. We store them
	 * here in the mean time.
	 */
	struct hip_crypto_key esp_our; //espi_key;
	struct hip_crypto_key esp_peer; //spr_key;
	struct hip_crypto_key auth_our; //authi_key;
	struct hip_crypto_key auth_peer; //authr_key;
	struct hip_crypto_key hmac_our;
	struct hip_crypto_key hmac_peer;

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


#define HIP_UNIT_ERR_LOG_MSG_MAX_LEN 200

#endif /* __KERNEL__ */

/* Some default settings for HIPL */
#define HIP_DEFAULT_HIP_ENCR         HIP_ENCR_3DES   /* HIP transform in R1 */
#define HIP_DEFAULT_ESP_ENCR         HIP_ENCR_3DES   /* ESP transform in R1 */
#define HIP_DEFAULT_AUTH             HIP_AUTH_SHA    /* AUTH transform in R1 */

#endif /* _NET_HIP */

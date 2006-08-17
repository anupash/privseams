#ifndef _HIP_PROTODEFS
#define _HIP_PROTODEFS

/*
 * HIP header and parameter related constants and structures.
 *
 */


#define HIP_HIT_TYPE_MASK_HAA   0x80
#define HIP_HIT_TYPE_MASK_120   0x11
#define HIP_HIT_PREFIX          0x1100
#define HIP_HIT_PREFIX_LEN      8     /* bits */
#define HIP_HIT_FULL_PREFIX_STR "/128"
#define HIP_HIT_PREFIX_STR      "/8"
#define HIP_KHI_CONTEXT_ID_INIT { 0xF0,0xEF,0xF0,0x2F,0xBF,0xF4,0x3D,0x0F, \
                                  0xE7,0x93,0x0C,0x3C,0x6E,0x61,0x74,0xEA }

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

#define HIP_AH_SHA_LEN                 20

/* Both for storing peer host ids and localhost host ids */
#define HIP_HOST_ID_MAX                16
#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */


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


struct hip_crypto_key {
	char key[HIP_MAX_KEY_LEN];
};

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


/*
 * Localhost Host Identity. Used only internally in the implementation.
 * Used for wrapping anonymous bit with the corresponding HIT.
 */
struct hip_lhi
{
	uint16_t           anonymous; /* Is this an anonymous HI */
	struct in6_addr    hit;
} __attribute__ ((packed));


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
 * Use accessor functions defined in hip_build.h, do not access members
 * directly to avoid hassle with byte ordering and length conversion.
 */ 
struct hip_tlv_common {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
} __attribute__ ((packed));


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


#endif /* _HIP_PROTODEFS */


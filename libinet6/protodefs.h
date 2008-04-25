/** @file
 * This file defines a Host Identity Protocol (HIP) header and parameter
 * related constants and structures.
 */
#ifndef _HIP_PROTODEFS
#define _HIP_PROTODEFS

#define HIP_MAX_PACKET 2048

/** @addtogroup hip_msg
 * @{
 */
#define HIP_I1                  1
#define HIP_R1                  2
#define HIP_I2                  3
#define HIP_R2                  4
#define HIP_CER                 5
#define HIP_BOS                 11 /* removed from ietf-hip-base-01 */
#define HIP_UPDATE              16
#define HIP_NOTIFY              17
#define HIP_CLOSE               18
#define HIP_CLOSE_ACK           19
#define HIP_PSIG                20 /* lightweight HIP pre signature */
#define HIP_TRIG                21 /* lightweight HIP signature trigger*/
#define HIP_PAYLOAD             64
#define HIP_AGENT_PING          70
#define HIP_AGENT_PING_REPLY    71
#define HIP_AGENT_QUIT          72
#define HIP_ADD_DB_HI           73
#define HIP_I1_REJECT           74
#define HIP_UPDATE_HIU          75
#define HIP_FIREWALL_PING       80
#define HIP_FIREWALL_PING_REPLY 81
#define HIP_FIREWALL_QUIT       82
#define HIP_ADD_ESCROW_DATA     83
#define HIP_DELETE_ESCROW_DATA  84
#define HIP_SET_ESCROW_ACTIVE   85
#define HIP_SET_ESCROW_INACTIVE 86
#define HIP_NAT_ON              87
#define HIP_NAT_OFF             88
#define HIP_DAEMON_QUIT         127
/* @} */

#define HIP_HIT_TYPE_HASH100    1
#define HIP_HIT_TYPE_HAA_HASH   2
#define HIP_HIT_TYPE_MASK_HAA   0x00000080 /**< depracated -miika */
#define HIP_HIT_TYPE_MASK_100   0x20010010
#define HIP_HIT_TYPE_MASK_CLEAR 0x0000000f
#define HIP_HIT_TYPE_MASK_INV   0xfffffff0
#define HIP_HIT_PREFIX          HIP_HIT_TYPE_MASK_100
#define HIP_HIT_PREFIX_LEN      28     /* bits */
#define HIP_HIT_FULL_PREFIX_STR "/128"
#define HIP_HIT_PREFIX_STR      "/28"
#define HIP_KHI_CONTEXT_ID_INIT { 0xF0,0xEF,0xF0,0x2F,0xBF,0xF4,0x3D,0x0F, \
                                  0xE7,0x93,0x0C,0x3C,0x6E,0x61,0x74,0xEA }

/** @addtogroup hip_param_type_numbers
 * @{ 
 */
#define HIP_PARAM_MIN                  -1

#define HIP_PARAM_ESP_INFO             65
#define HIP_PARAM_R1_COUNTER           128
#define HIP_PARAM_LOCATOR              193
#define HIP_PARAM_HASH_CHAIN_VALUE     221
#define HIP_PARAM_HASH_CHAIN_ANCHORS   222
#define HIP_PARAM_HASH_CHAIN_PSIG      223
#define HIP_PARAM_PUZZLE               257
#define HIP_PARAM_SOLUTION             321
#define HIP_PARAM_SEQ                  385
#define HIP_PARAM_ACK                  449
#define HIP_PARAM_DIFFIE_HELLMAN       513
#define HIP_PARAM_HIP_TRANSFORM        577
#define HIP_PARAM_ENCRYPTED            641
#define HIP_PARAM_HOST_ID              705
#define HIP_PARAM_CERT                 768
#define HIP_PARAM_NOTIFICATION         832
#define HIP_PARAM_ECHO_REQUEST_SIGN    897
#define HIP_PARAM_ECHO_RESPONSE_SIGN   961
#define HIP_PARAM_ESP_TRANSFORM        4095

/* Range 32768 - 49141 can be used for HIPL private parameters i.e. to
   parameters passed from hipconf to hipdaemon. */
#define HIP_PARAM_HIT                   32768
#define HIP_PARAM_IPV6_ADDR             32769
#define HIP_PARAM_DSA_SIGN_DATA         32770 /**< @todo change to digest */
#define HIP_PARAM_HI                    32771
#define HIP_PARAM_DH_SHARED_KEY         32772
#define HIP_PARAM_UNIT_TEST             32773
#define HIP_PARAM_EID_SOCKADDR          32774
#define HIP_PARAM_EID_ENDPOINT          32775 /**< Pass endpoint_hip structures into kernel */
#define HIP_PARAM_EID_IFACE             32776
#define HIP_PARAM_EID_ADDR              32777
#define HIP_PARAM_UINT                  32778 /**< Unsigned integer */
#define HIP_PARAM_KEYS                  32779
#define HIP_PSEUDO_HIT                  32780 
#define HIP_PARAM_REG_INFO		32781
#define HIP_PARAM_REG_REQUEST		32782
#define HIP_PARAM_REG_RESPONSE		32783
#define HIP_PARAM_REG_FAILED		32784
#define HIP_PARAM_BLIND_NONCE           32785 /**< Pass blind nonce */
#define HIP_PARAM_OPENDHT_GW_INFO       32786
#define HIP_PARAM_ENCAPS_MSG		32787
#define HIP_PARAM_PORTPAIR		32788
#define HIP_PARAM_SRC_ADDR		32789
#define HIP_PARAM_DST_ADDR		32790
#define HIP_PARAM_AGENT_REJECT	        32791
#define HIP_PARAM_HA_INFO               32792
#define HIP_PARAM_OPENDHT_SET           32793
#define HIP_PARAM_INT                   32794
#define HIP_PARAM_SRC_TCP_PORT		32795
#define HIP_PARAM_DST_TCP_PORT		32796
#define HIP_PARAM_IP_HEADER		32797
#define HIP_PARAM_PACKET_SIZE		32798
#define HIP_PARAM_TRAFFIC_TYPE		32799
#define HIP_PARAM_ADD_HIT		32800
#define HIP_PARAM_ADD_OPTION		32801
#define HIP_PARAM_PEER_HIT		32802

/* End of HIPL private parameters. */

#define HIP_PARAM_HMAC                 61505
#define HIP_PARAM_HMAC2                61569
#define HIP_PARAM_HIP_SIGNATURE2       61633
#define HIP_PARAM_HIP_SIGNATURE        61697
#define HIP_PARAM_ECHO_RESPONSE        63425
#define HIP_PARAM_ECHO_REQUEST         63661
#define HIP_PARAM_RELAY_FROM           63998
#define HIP_PARAM_RELAY_TO             64002
#define HIP_PARAM_TO_PEER              64006
#define HIP_PARAM_FROM_PEER            64008
#define HIP_PARAM_REG_FROM             64010
#define HIP_PARAM_FROM                 65498
#define HIP_PARAM_RVS_HMAC             65500
#define HIP_PARAM_VIA_RVS              65502
#define HIP_PARAM_RELAY_HMAC           65520

#define HIP_PARAM_MAX                  65536
/* @} */

/** @addtogroup notification
 * @{ 
 */
#define HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE 1
#define HIP_NTF_INVALID_SYNTAX                      7
#define HIP_NTF_NO_DH_PROPOSAL_CHOSEN               14
#define HIP_NTF_INVALID_DH_CHOSEN                   15
#define HIP_NTF_NO_HIP_PROPOSAL_CHOSEN              16
#define HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN        17
#define HIP_NTF_AUTHENTICATION_FAILED               24
#define HIP_NTF_CHECKSUM_FAILED                     26
#define HIP_NTF_HMAC_FAILED                         28
#define HIP_NTF_ENCRYPTION_FAILED                   32
#define HIP_NTF_INVALID_HIT                         40
#define HIP_NTF_BLOCKED_BY_POLICY                   42
#define HIP_NTF_SERVER_BUSY_PLEASE_RETRY            44
#define HIP_NTF_I2_ACKNOWLEDGEMENT                  46
/* @} */

#define HIP_HIP_RESERVED                0
#define HIP_HIP_AES_SHA1                1
#define HIP_HIP_3DES_SHA1               2
#define HIP_HIP_3DES_MD5                3
#define HIP_HIP_BLOWFISH_SHA1           4
#define HIP_HIP_NULL_SHA1               5
#define HIP_HIP_NULL_MD5                6

#define HIP_TRANSFORM_HIP_MAX           6
#define HIP_TRANSFORM_ESP_MAX           6
#define HIP_LOWER_TRANSFORM_TYPE 2048
#define HIP_UPPER_TRANSFORM_TYPE 4095

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
#define HIP_HI_DEFAULT_ALGO           HIP_HI_DSA

/** @todo Kludge: currently set to DSA until bug id 175 is resolved!
    Should be RSA. */
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

#define HIP_AH_SHA_LEN                 20

#define ENOTHIT                     666

/* Domain Identifiers (to be used in HOST_ID TLV) */
#define HIP_DI_NONE                   0
#define HIP_DI_FQDN                   1
#define HIP_DI_NAI                    2

#define HIP_HOST_ID_HOSTNAME_LEN_MAX 64
#define HIP_HOST_ID_RR_DSA_MAX_T_VAL           8
#define HIP_HOST_ID_RR_T_SIZE                  1
#define HIP_HOST_ID_RR_Q_SIZE                  20
#define HIP_HOST_ID_RR_P_BASE_SIZE             20
#define HIP_HOST_ID_RR_G_BASE_SIZE             20
#define HIP_HOST_ID_RR_Y_BASE_SIZE             20
#define HIP_HOST_ID_RR_DSA_PRIV_KEY_SIZE       20

/* Both for storing peer host ids and localhost host ids */
#define HIP_HOST_ID_MAX                16
#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */

#define HIP_VER_RES                 0x01     /* Version 1, reserved 0 */
#define HIP_VER_MASK                0xF0
#define HIP_RES_MASK                0x0F 

/**
 * @addtogroup hip_ha_controls
 * @{
 */
/* REMEMBER TO UPDATE BITMAP IN DOC/DOXYGEN.H WHEN YOU ADD/CHANGE THESE! */
#define HIP_HA_CTRL_NONE                 0x0000

#define HIP_HA_CTRL_LOCAL_REQ_ESCROW     0x2000
#define HIP_HA_CTRL_LOCAL_REQ_RELAY      0x4000
#define HIP_HA_CTRL_LOCAL_REQ_RVS        0x8000

#define HIP_HA_CTRL_PEER_ESCROW_CAPABLE  0x2000 
#define HIP_HA_CTRL_PEER_RELAY_CAPABLE   0x4000 
#define HIP_HA_CTRL_PEER_RVS_CAPABLE     0x8000
/* @} */

/** @addtogroup hip_packet_controls
 * @{ 
 */
#define HIP_PACKET_CTRL_ANON             0x0001 /**< HIP packet Controls value */
#define HIP_PACKET_CTRL_BLIND	         0x0004 /**< HIP packet Controls value */
/* @} */

/** @addtogroup hip_services
 * @{ 
 */
#define HIP_SERVICE_RENDEZVOUS	         1
#define HIP_SERVICE_ESCROW	         201
#define HIP_SERVICE_RELAY            	 202

/* IMPORTANT! This must be the sum of above services. */
#define HIP_TOTAL_EXISTING_SERVICES      3
/* @} */

/* Registration failure types as specified in draft-ietf-hip-registration-02.
   Numbers 0-200 are reserved by IANA.
   Numbers 201 - 255 are reserved by IANA for private use. */
#define HIP_REG_INSUFFICIENT_CREDENTIALS 0
#define HIP_REG_TYPE_UNAVAILABLE         1

/* Returns length of TLV option (contents) with padding. */
#define HIP_LEN_PAD(len) \
    ((((len) & 0x07) == 0) ? (len) : ((((len) >> 3) << 3) + 8))

typedef uint8_t hip_hdr_type_t;
typedef uint8_t hip_hdr_len_t;
typedef uint16_t se_family_t;
typedef uint16_t se_length_t;
typedef uint16_t se_hip_flags_t;
typedef uint16_t hip_hdr_err_t;
typedef uint16_t hip_tlv_type_t;
typedef uint16_t hip_tlv_len_t;
typedef uint16_t hip_transform_suite_t;
typedef uint16_t hip_eid_iface_type_t;
typedef uint16_t hip_controls_t;
typedef uint32_t sa_eid_t;
typedef struct in6_addr hip_hit_t;
typedef struct in6_addr in6_addr_t;
typedef struct in_addr hip_lsi_t;
typedef struct hip_hadb_state hip_ha_t;
typedef struct hip_hadb_rcv_func_set hip_rcv_func_set_t;
typedef struct hip_hadb_handle_func_set hip_handle_func_set_t;
typedef struct hip_hadb_update_func_set hip_update_func_set_t;
typedef struct hip_hadb_misc_func_set hip_misc_func_set_t;
typedef struct hip_hadb_xmit_func_set hip_xmit_func_set_t;
typedef struct hip_hadb_input_filter_func_set hip_input_filter_func_set_t;
typedef struct hip_hadb_output_filter_func_set hip_output_filter_func_set_t;
typedef struct hip_common hip_common_t;
typedef struct hip_tlv_common hip_tlv_common_t;

struct hip_crypto_key {
	char key[HIP_MAX_KEY_LEN];
};

typedef struct hip_crypto_key hip_crypto_key_t;

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


/**
 * Localhost Host Identity. Used only internally in the implementation.
 * Used for wrapping anonymous bit with the corresponding HIT.
 */
struct hip_lhi
{
	uint16_t           anonymous; /**< Is this an anonymous HI */
	struct in6_addr    hit;
	uint16_t           algo; /**< HIP_HI_RSA or HIP_HI_DSA */
} __attribute__ ((packed));


struct hip_keymat_keymat
{
	size_t offset;    /**< Offset into the key material */
	size_t keymatlen; /**< Length of the key material */
	void *keymatdst;  /**< Pointer to beginning of key material */
};

/**
 * Used in executing a unit test case in a test suite in the kernel module.
 */
struct hip_unit_test {
	hip_tlv_type_t     type;
	hip_tlv_len_t      length;
	uint16_t           suiteid;
	uint16_t           caseid;
} __attribute__ ((packed));

/**
 * Fixed start of this struct must match to struct hip_peer_addr_list_item
 * for the part of address item. It is used in hip_update_locator_match().
 * @todo Maybe fix this in some better way?
 */
struct hip_locator_info_addr_item {
        uint8_t traffic_type;
        uint8_t locator_type;
        uint8_t locator_length;
        uint8_t reserved;  /**< last bit is P (prefered) */
	uint32_t lifetime;
	struct in6_addr address;
	/* end of fixed part - locator of arbitrary length follows but 
	   currently support only IPv6 */
	int state; /**<State of our addresses, possible states are:
		      WAITING_ECHO_REQUEST, ACTIVE */

}  __attribute__ ((packed));

/** Structure describing an endpoint. This structure is used by the resolver in
 * the userspace, so it is not length-padded like HIP parameters. All of the
 * members are in network byte order.
 */
struct endpoint {
	se_family_t   family;    /**< PF_HIP, PF_XX */
	se_length_t   length;    /**< length of the whole endpoint in octets */
};

/**
 * @note not padded
 */
struct endpoint_hip {
	se_family_t         family; /**< PF_HIP */
	se_length_t         length; /**< length of the whole endpoint in octets */
	se_hip_flags_t      flags;  /**< e.g. ANON or HIT */
	uint8_t             algo;
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

/**
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
	struct in6_addr hits;  /**< Sender HIT   */
	struct in6_addr hitr;  /**< Receiver HIT */
} __attribute__ ((packed));

/**
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

/** @addtogroup hip_tlv
 * @{ 
 */
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

struct hip_dh_public_value {
	uint8_t           group_id;  
	uint16_t          pub_len;
	/* fixed part ends */
        uint8_t           public_value[0];
} __attribute__ ((packed));

struct hip_diffie_hellman {
	hip_tlv_type_t    type;
	hip_tlv_len_t     length;
        struct hip_dh_public_value  pub_val;
} __attribute__ ((packed));

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

/** @todo hip and esp transform are not symmetric (reserved) */
struct hip_any_transform {
	hip_tlv_type_t        type;
	hip_tlv_len_t         length;
	/** @todo replace with MAX(HIP, ESP) */
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
	uint8_t      signature[0]; /**< variable length */
	/* fixed part end */
} __attribute__ ((packed));

struct hip_sig2 {
	hip_tlv_type_t     type;
	hip_tlv_len_t     length;
	uint8_t      algorithm;
	uint8_t      signature[0]; /**< variable length */
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
	uint32_t peer_update_id; /**< n items */
} __attribute__ ((packed));

struct hip_notification {
	hip_tlv_type_t type;
	hip_tlv_len_t length;
	uint16_t reserved;
	uint16_t msgtype;
	uint8_t data[0]; /**< A pointer to the notification data */
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

/** draft-ietf-hip-rvs-05 */
struct hip_rvs_hmac {
     hip_tlv_type_t type; /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t hmac_data[HIP_AH_SHA_LEN]; /**< Computed over the HIP packet,
					   excluding @c RVS_HMAC
					   and any following parameters. */
} __attribute__ ((packed));

/** draft-ietf-hip-rvs-05 */
struct hip_from {
     hip_tlv_type_t type;  /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t address[16]; /**< IPv6 address */
} __attribute__ ((packed));

/** draft-ietf-hip-rvs-05 */
struct hip_via_rvs {
     hip_tlv_type_t type;  /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t address[0]; /**< Rendezvous server addresses */
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
struct hip_relay_from {
     hip_tlv_type_t type; /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t address[16]; /**< IPv6 address */
     in_port_t port; /**< Port number. */
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
struct hip_relay_to {
     hip_tlv_type_t type; /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t address[16]; /**< IPv6 address */
     in_port_t port; /**< Port number. */
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
struct hip_relay_via {
     hip_tlv_type_t type; /**< Type code for the parameter. */
     hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
     uint8_t address[16]; /**< IPv6 address */
     in_port_t port; /**< Port number. */
} __attribute__ ((packed));

/** 
 * draft-ietf-hip-nat-traversal-01
 * @note obsolete.
 */
struct hip_relay_to_old {
	hip_tlv_type_t type; /**< Type code for the parameter. */
	hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
	uint8_t address_and_port[0]; /**< Rendezvous server addresses and ports. */
} __attribute__ ((packed));

struct hip_eid_endpoint {
	hip_tlv_type_t      type;
	hip_tlv_len_t       length;
	struct endpoint_hip endpoint;
} __attribute__ ((packed));

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

struct hip_reg_info {
	hip_tlv_type_t type; /**< Type code for the parameter. */
	hip_tlv_len_t  length; /**< Length of the parameter contents in bytes. */
	uint8_t        min_lifetime;
	uint8_t        max_lifetime;
	uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_request {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t        lifetime;
	uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_response {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t        lifetime;
	uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_failed {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint8_t       failure_type;
} __attribute__ ((packed));

struct hip_keys {
	hip_tlv_type_t 	type;
	hip_tlv_len_t 	length;
	uint16_t 	operation;
	uint16_t 	alg_id;
	uint8_t 	address[16];
	uint8_t 	hit[16];
        uint8_t         peer_hit[16];
	uint32_t 	spi;
	uint32_t 	spi_old;
	uint16_t 	key_len;
	struct hip_crypto_key enc;
} __attribute__ ((packed));

struct hip_blind_nonce {
	hip_tlv_type_t type;
	hip_tlv_len_t  length;
	uint16_t       nonce;
} __attribute__ ((packed));

struct hip_opendht_gw_info {
	hip_tlv_type_t 	type;
	hip_tlv_len_t 	length;
	struct in6_addr addr;
	uint32_t        ttl;
	uint16_t        port;
} __attribute__ ((packed));

struct hip_opendht_set {
	hip_tlv_type_t 	type;
	hip_tlv_len_t 	length;
        char name[256];
} __attribute__ ((packed));

/* @} */

#endif /* _HIP_PROTODEFS */


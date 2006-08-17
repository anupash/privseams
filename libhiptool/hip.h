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
#include <sys/un.h> // for sockaddr_un

/* Workaround for kernels before 2.6.15.3. */
#ifndef IPV6_2292PKTINFO
#  define IPV6_2292PKTINFO 2
#endif

#include "protodefs.h"
#include "utils.h"
#include "state.h"
#include "icomm.h"
#include "ife.h"


#define HIP_NAT_UDP_PORT 50500 /* For NAT traversal */
#define HIP_NAT_UDP_DATA_PORT 54500 /* For data traffic*/
#define UDP_ENCAP 100 /* For setting socket to listen for beet-udp packets*/
#define UDP_ENCAP_ESPINUDP 2 
#define UDP_ENCAP_ESPINUDP_NONIKE 1 


#define NETLINK_HIP             32   /* Host Identity Protocol signalling messages */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP             253 /* Also in libinet6/include/netinet/in.h */
#endif

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


#define HIP_DAEMONADDR_PATH						"/tmp/hip_daemonaddr_path.tmp"
#define HIP_AGENTADDR_PATH						"/tmp/hip_agentaddr_path.tmp"
#define HIP_USERADDR_PATH						"/tmp/hip_useraddr_path.tmp"

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

/* HIP_IFCS takes a pointer and an command to execute.
   it executes the command exec if cond != NULL */ 
#define HIP_IFCS(condition, consequence)\
	 if( condition ) {	\
	 	consequence ; 						\
	 } else {							\
	 	HIP_ERROR("No state information found.\n");		\
	 }

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

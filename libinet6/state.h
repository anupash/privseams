/** @file
 * This file defines Host Identity Protocol (HIP) header and parameter related
 * constants and structures.
 *
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef _HIP_STATE
#define _HIP_STATE

#include "hashtable.h"

#define HIP_HIT_KNOWN 1
#define HIP_HIT_ANON  2

#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
#define HIP_HI_REUSE_UID                   4
#define HIP_HI_REUSE_GID                   8
#define HIP_HI_REUSE_ANY                  16
/* Other flags: keep them to the power of two! */

/** @addtogroup hip_ha_state
 * @{
 */
/* When adding new states update debug.h hip_state_str(). Doxygen comments to
   these states are available at doc/doxygen.h */
#define HIP_STATE_NONE                   0
#define HIP_STATE_UNASSOCIATED           1  /**< ex-E0 */
#define HIP_STATE_I1_SENT                2  /**< ex-E1 */
#define HIP_STATE_I2_SENT                3  /**< ex-E2 */
#define HIP_STATE_R2_SENT                4
#define HIP_STATE_ESTABLISHED            5  /**< ex-E3 */
#define HIP_STATE_FAILED                 7
#define HIP_STATE_CLOSING                8
#define HIP_STATE_CLOSED                 9
#define HIP_STATE_FILTERING_I1           10
#define HIP_STATE_FILTERING_R2           11
#define HIP_STATE_FILTERED_I1            12
#define HIP_STATE_FILTERED_R2            13
#define HIP_STATE_FILTERING_I2           14
#define HIP_STATE_FILTERED_I2            15
/* @} */

#define HIP_UPDATE_STATE_REKEYING        1 /**< @todo REMOVE */
#define HIP_UPDATE_STATE_DEPRECATING     2

#define PEER_ADDR_STATE_UNVERIFIED       1
#define PEER_ADDR_STATE_ACTIVE           2
#define PEER_ADDR_STATE_DEPRECATED       3

#define ADDR_STATE_ACTIVE                1
#define ADDR_STATE_WAITING_ECHO_REQ      2

#define HIP_LOCATOR_TRAFFIC_TYPE_DUAL    0
#define HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL  1
#define HIP_LOCATOR_TRAFFIC_TYPE_DATA    2

#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1

#define SEND_UPDATE_ESP_INFO             (1 << 0)
#define SEND_UPDATE_LOCATOR              (1 << 1)

#define HIP_SPI_DIRECTION_OUT            1
#define HIP_SPI_DIRECTION_IN             2

#define HIP_ESCROW_OPERATION_ADD         1
#define HIP_ESCROW_OPERATION_MODIFY      2
#define HIP_ESCROW_OPERATION_DELETE      3

#define HIP_DEFAULT_AUTH                 HIP_AUTH_SHA /**< AUTH transform in R1 */
/**
 * Default rendezvous association lifetime in seconds. The lifetime should be
 * calculated using formula <code>2^((lifetime - 64)/8)</code> as instructed in
 * draft-ietf-hip-registration-02. But since we are just in the test phase of
 * HIP, we settle for a constant value of 600 seconds. Lauri 23.01.2008.
 */
#define HIP_DEFAULT_RVA_LIFETIME         600          

/**
 * HIP host association state.
 * 
 * @todo remove HIP_HASTATE_SPIOK
 */
typedef enum { 
	HIP_HASTATE_INVALID = 0,
	HIP_HASTATE_SPIOK = 1,
	HIP_HASTATE_HITOK = 2,
	HIP_HASTATE_VALID = 3
} hip_hastate_t;

/** A typedefinition for a functionpointer to a transmitfunction introduced in
    @c hip_xmit_func_set_t. */
typedef int (*hip_xmit_func_t)(struct in6_addr *, struct in6_addr *, in_port_t,
			       in_port_t, struct hip_common*, hip_ha_t *, int);

/**
 * A data structure for storing the source and destination ports of an incoming
 * packet. 
 */
typedef struct hip_stateless_info 
{
	in_port_t src_port; /**< The source port of an incoming packet. */
	in_port_t dst_port; /**< The destination port of an incoming packet. */
#ifdef CONFIG_HIP_HI3
	int hi3_in_use; // varibale says is the received message sent through i3 or not
#endif
} hip_portpair_t;

/**
 * A data structure for handling retransmission. Used inside host association
 * database entries.
 */
typedef struct hip_msg_retrans{
	int count;
	time_t last_transmit;
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct hip_common *buf;
} hip_msg_retrans_t;

/** 
 * A binder structure for storing an IPv6 address and transport layer port
 * number. This structure is used in hip_build_param_relay_to_old().
 * 
 * @note This has to be packed since it is used in building @c RELAY_FROM and
 *       @c RELAY_TO parameters.
 * @note obsolete
 */
struct hip_in6_addr_port
{
	struct in6_addr sin6_addr; /**< IPv6 address. */
	in_port_t       sin6_port; /**< Transport layer port number. */
} __attribute__ ((packed));

struct hip_context
{
	//struct sk_buff *skb_in;         /* received skbuff */
	struct hip_common *input;       /**< Received packet. */
	struct hip_common *output;      /**< Packet to be built and sent. */
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

	uint16_t current_keymat_index; /**< The byte offset index in draft
					  chapter HIP KEYMAT */
	unsigned char current_keymat_K[HIP_AH_SHA_LEN];
	uint8_t keymat_calc_index; /**< The one byte index number used
				      during the keymat calculation. */
	uint16_t keymat_index; /**< KEYMAT offset. */
	uint16_t esp_keymat_index; /**< A pointer to the esp keymat index. */
};

/*
 * Fixed start of this struct must match to struct hip_locator_info_addr_item
 * for the part of address item. It is used in hip_update_locator_match().
 */
struct hip_peer_addr_list_item
{
//	hip_list_t list;
	uint32_t padding;
	unsigned long    hash_key;
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
//	hip_list_t list;
	spinlock_t       lock;
	atomic_t         refcnt;
	hip_hit_t        hit_our;
	hip_hit_t        hit_peer;
	uint32_t         spi; /* this SPI spi belongs to the HIT hit */
};

struct hip_spi_in_item
{
//	hip_list_t list;
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
//	hip_list_t list;
	uint32_t         spi;
	uint32_t         new_spi;   /* spi is changed to this when rekeying */
	uint32_t         seq_update_id; /* USELESS, IF SEQ ID WILL BE RELATED TO ADDRESS ITEMS,
					 * NOT OUTBOUND SPIS *//* the Update ID in SEQ parameter these SPI are related to */

	HIP_HASHTABLE *peer_addr_list; /* Peer's IPv6 addresses */
	struct in6_addr  preferred_address; /* check */
};

/* this struct is here instead of hidb.h to avoid some weird compilation
   warnings */
struct hip_host_id_entry {
	/* this needs to be first (list_for_each_entry, list 
	   head being of different type) */
	//hip_list_t next; 
	struct hip_lhi lhi;
	hip_lsi_t lsi;
	/* struct in6_addr ipv6_addr[MAXIP]; */
	struct hip_host_id *host_id; /* allocated dynamically */
	struct hip_r1entry *r1; /* precreated R1s */
	struct hip_r1entry *blindr1; /* pre-created R1s for blind*/
	/* Handler to call after insert with an argument, return 0 if OK*/
	int (*insert)(struct hip_host_id_entry *, void **arg);
	/* Handler to call before remove with an argument, return 0 if OK*/
	int (*remove)(struct hip_host_id_entry *, void **arg);
	void *arg;
};

/** A data structure defining host association database state i.e.\ a HIP
    association between two hosts. Each successful base exchange between two
    different hosts leads to a new @c hip_hadb_state with @c state set to
    @c HIP_STATE_ESTABLISHED. */
struct hip_hadb_state
{	
        /** Our Host Identity Tag (HIT). */
	hip_hit_t                    hit_our;
	/** Peer Host Identity Tag (HIT). */
	hip_hit_t                    hit_peer;
	/** Information about the usage of the host association. When zero, the
	    host association can be freed. */
	hip_hastate_t                hastate; 
	/** The state of this host association. @see hip_ha_state */ 
	int                          state;
	/** This guarantees that retransmissions work properly also in
	    non-established state.*/
	int                          retrans_state;
	/** A kludge to get the UPDATE retransmission to work.
	    @todo Remove this kludge. */
	int                          update_state;
	/** Our control values related to this host association.
	    @see hip_ha_controls */ 
	hip_controls_t               local_controls;
	/** Peer control values related to this host association.
	    @see hip_ha_controls */ 
	hip_controls_t               peer_controls;
	/** ? @todo Define. */
	int                          is_loopback;
	/** Security Parameter Indices (SPI) for incoming Security Associations
	    (SA). A SPI is an identification tag added to the packet header
	    while using IPsec for tunneling IP traffic.
	    @see hip_spi_in_item. */
	HIP_HASHTABLE                *spis_in;
	/** Security Parameter Indices (SPI) for outbound Security Associations
	    (SA). A SPI is an identification tag added to the packet header
	    while using IPsec for tunneling IP traffic.
	    @see hip_spi_in_item. */
	HIP_HASHTABLE                *spis_out;
	/** Default SPI for outbound SAs. */
	uint32_t                     default_spi_out;
	/** Preferred peer IP address to use when sending data to peer. */
	struct in6_addr              preferred_address;
	/** Our IP address. */
	struct in6_addr              local_address;
	/** Peer's Local Scope Identifier (LSI). A Local Scope Identifier is a
	    32-bit localized representation for a Host Identity.*/
       	hip_lsi_t                    lsi_peer;
	/** Our Local Scope Identifier (LSI). A Local Scope Identifier is a
	    32-bit localized representation for a Host Identity.*/
	hip_lsi_t                    lsi_our;
	/** ? @todo Define. */
	int                          esp_transform;
	/** ? @todo Define. */
	int                          hip_transform;
	/** Something to do with the birthday paradox? @todo Define. */
	uint64_t                     birthday;
	/** A pointer to the Diffie-Hellman shared key. */
	char                         *dh_shared_key;
	/** The length of the Diffie-Hellman shared key. */ 
	size_t                       dh_shared_key_len;
	/** A boolean value indicating whether there is a NAT between this host
	    and the peer. */
	uint8_t	                     nat_mode;
	 /** NAT mangled port (source port of I2 packet). */
	in_port_t	             peer_udp_port;
	/** Non-zero if the escrow service is in use. */ 
	int                          escrow_used;
	struct in6_addr	             escrow_server_hit; /**< Escrow server HIT. */ 
	/* The Initiator computes the keys when it receives R1. The keys are
	   needed only when R2 is received. We store them here in the mean
	   time. */
	/** For outgoing HIP packets. */
	struct hip_crypto_key        hip_enc_out;
	/** For outgoing HIP packets. */
	struct hip_crypto_key        hip_hmac_out;
	/** For outgoing ESP packets. */
	struct hip_crypto_key        esp_out;
	/** For outgoing ESP packets. */
	struct hip_crypto_key        auth_out;
	/** For incoming HIP packets. */
	struct hip_crypto_key        hip_enc_in;
	/** For incoming HIP packets. */
	struct hip_crypto_key        hip_hmac_in;
	/** For incoming ESP packets. */
	struct hip_crypto_key        esp_in;
	/** For incoming ESP packets. */
	struct hip_crypto_key        auth_in;
	/** The byte offset index in draft chapter HIP KEYMAT. */
	uint16_t                     current_keymat_index;
	/** The one byte index number used during the keymat calculation. */
	uint8_t                      keymat_calc_index;
	/** For @c esp_info. */
	uint16_t                     esp_keymat_index;
	/* Last Kn, where n is @c keymat_calc_index. */
	unsigned char                current_keymat_K[HIP_AH_SHA_LEN];
	/** Stored outgoing UPDATE ID counter. */
	uint32_t                     update_id_out;
	/** Stored incoming UPDATE ID counter. */
	uint32_t                     update_id_in;
	/** Our public host identity. */
	struct hip_host_id           *our_pub;
	/** Our private host identity. */	
	struct hip_host_id           *our_priv;
        /** A function pointer to a function that signs our host identity. */
	int                          (*sign)(struct hip_host_id *, struct hip_common *);
	/** Peer's public host identity. */
	struct hip_host_id           *peer_pub;
	/** A function pointer to a function that verifies peer's host identity. */
	int                          (*verify)(struct hip_host_id *, struct hip_common *);
	/** For retransmission. */
	uint64_t                     puzzle_solution;
	/** 1, if hadb_state uses BLIND protocol. */
	uint16_t	             blind;
	/** The HIT we use with this host when BLIND is in use. */
	hip_hit_t                    hit_our_blind;
	/** The HIT the peer uses when BLIND is in use. */
	hip_hit_t                    hit_peer_blind;
	/** BLIND nonce. */
	uint16_t                     blind_nonce_i;
	/** LOCATOR parameter. Just tmp save if sent in R1 no @c esp_info so
	    keeping it here 'till the hip_update_locator_parameter can be done.
	    @todo Remove this kludge. */
	struct hip_locator           *locator;
 	/** For retransmission. */
	uint64_t                     puzzle_i;
	/** For base exchange or CLOSE. @b Not for UPDATE. */
	char                         echo_data[4];
	/** For storing retransmission related data. */
	hip_msg_retrans_t            hip_msg_retrans;
	/** Receive function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_rcv_function_set() instead. */
	hip_rcv_func_set_t           *hadb_rcv_func;
	/** Handle function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_handle_func_set_t        *hadb_handle_func;
	/** Miscellaneous function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_misc_func_set_t          *hadb_misc_func;	
	/** Update function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_update_func_set_t        *hadb_update_func;	
	/** Transmission function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_xmit_func_set_t          *hadb_xmit_func;
	/** Input filter function set. Input filter used in the GUI agent.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_input_filter_function_set() instead. */
	hip_input_filter_func_set_t  *hadb_input_filter_func;
	/** Output filter function set. Output filter used in the GUI agent.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_output_filter_function_set() instead. */
	hip_output_filter_func_set_t *hadb_output_filter_func;
	/** True when agent is prompting user and fall back is disabled. */
	int                          hip_opp_fallback_disable; 
#ifdef CONFIG_HIP_HI3
	/** If the state for hi3, then this flag is 1, otherwise it is zero. */
	int                          is_hi3_state ;
#endif
#ifdef CONFIG_HIP_OPPTCP
	/** ? @todo Define. */
	int                          hip_is_opptcp_on;
#endif
};

/** A data structure defining host association information that is sent
    to the userspace */
struct hip_hadb_user_info_state
{
	hip_hit_t            hit_our;
	hip_hit_t            hit_peer;
	struct in6_addr      ip_our;
	struct in6_addr      ip_peer;
	int                  state;
};

/** @addtogroup hadb_func
 * @{
 */
struct hip_hadb_rcv_func_set {
	int (*hip_receive_i1)(struct hip_common *,
			      struct in6_addr *, 
			      struct in6_addr *,
			      hip_ha_t*,
			      hip_portpair_t *);

	int (*hip_receive_r1)(struct hip_common *,
				 struct in6_addr *, 
				 struct in6_addr *,
				 hip_ha_t*,
			      hip_portpair_t *);
				 
	/* as there is possibly no state established when i2
	messages are received, the hip_handle_i2 function pointer
	is not executed during the establishment of a new connection*/
	int (*hip_receive_i2)(struct hip_common *,
				 struct in6_addr *, 
				 struct in6_addr *,
				 hip_ha_t*,
			     hip_portpair_t *);
				 
	int (*hip_receive_r2)(struct hip_common *,
				 struct in6_addr *,
				 struct in6_addr *,
				 hip_ha_t*,
			     hip_portpair_t *);
				 
	int (*hip_receive_update)(struct hip_common *,
				  struct in6_addr *,
				  struct in6_addr *,
				  hip_ha_t*,
				  hip_portpair_t *);
				     
	int (*hip_receive_notify)(const struct hip_common *,
				  const struct in6_addr *,
				  const struct in6_addr *,
				  hip_ha_t*);
  
	int (*hip_receive_bos)(struct hip_common *,
			       struct in6_addr *,
			       struct in6_addr *,
			       hip_ha_t*,
			       hip_portpair_t *);
				     
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
			     hip_portpair_t *);

	int (*hip_handle_r1)(struct hip_common *r1,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *);
			     
	/* as there is possibly no state established when i2
	   messages are received, the hip_handle_i2 function pointer
	   is not executed during the establishment of a new connection*/
	int (*hip_handle_i2)(struct hip_common *i2,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *ha,
			     hip_portpair_t *i2_info);
			     
	int (*hip_handle_r2)(struct hip_common *r2,
			     struct in6_addr *r2_saddr,
			     struct in6_addr *r2_daddr,
			     hip_ha_t *ha,
			     hip_portpair_t *r2_info);
	int (*hip_handle_bos)(struct hip_common *bos,
			      struct in6_addr *r2_saddr,
			      struct in6_addr *r2_daddr,
			      hip_ha_t *ha,
			      hip_portpair_t *);
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
					       struct hip_esp_info *esp_info,
					       struct hip_seq *seq);

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
					     hip_portpair_t *);
	int (*hip_handle_update_rekeying)(hip_ha_t *entry,
					  struct hip_common *msg,
					  struct in6_addr *src_ip);

	int (*hip_update_send_addr_verify)(hip_ha_t *entry,
					   struct hip_common *msg,
					   struct in6_addr *src_ip,
					   uint32_t spi);

	int (*hip_update_send_echo)(hip_ha_t *entry,
			            uint32_t spi_out,
				    struct hip_peer_addr_list_item *addr);
};

struct hip_hadb_misc_func_set{ 
	uint64_t (*hip_solve_puzzle)(void *puzzle,
				  struct hip_common *hdr,
				  int mode);  
	int (*hip_produce_keying_material)(struct hip_common *msg,
					   struct hip_context *ctx,
					   uint64_t I,
					   uint64_t J,
					   struct hip_dh_public_value **);
	int (*hip_create_i2)(struct hip_context *ctx, uint64_t solved_puzzle, 
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *,
			     struct hip_dh_public_value *);
	int (*hip_create_r2)(struct hip_context *ctx,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *);
	void (*hip_build_network_hdr)(struct hip_common *msg, uint8_t type_hdr,
				      uint16_t control,
				      const struct in6_addr *hit_sender,
				      const struct in6_addr *hit_receiver);
};

/** A data structure containing function pointers to functions used for sending
    data on wire. */
struct hip_hadb_xmit_func_set{
	/** A function pointer for sending packet on wire. */
	int (*hip_send_pkt)(struct in6_addr *local_addr,
			    struct in6_addr *peer_addr,
			    in_port_t src_port, in_port_t dst_port,
			    struct hip_common* msg, hip_ha_t *entry,
			    int retransmit);
};

struct hip_hadb_input_filter_func_set { 
	int (*hip_input_filter)(struct hip_common *msg);
};

struct hip_hadb_output_filter_func_set { 
	int (*hip_output_filter)(struct hip_common *msg);
};

/* @} */

#endif /* _HIP_STATE */


#ifndef _HIP_STATE
#define _HIP_STATE

/*
 * HIP header and parameter related constants and structures.
 *
 */


/* todo: remove HIP_HASTATE_SPIOK */
typedef enum { HIP_HASTATE_INVALID=0, HIP_HASTATE_SPIOK=1,
	       HIP_HASTATE_HITOK=2, HIP_HASTATE_VALID=3 } hip_hastate_t;

/*
 * hip stateless info: Used to send parameters 
 * across function calls carrying stateless info
 */
struct hip_stateless_info 
{
	uint32_t src_port;
	uint32_t dst_port;
};

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


#endif /* _HIP_STATE */


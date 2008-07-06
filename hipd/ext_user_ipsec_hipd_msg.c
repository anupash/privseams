#include "ext_user_ipsec_hipd_msg.h"

// TODO extend to allow switching back to kernel-mode
int hip_userspace_ipsec_activate(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	int err = 0, activate = 0;
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_INT);
	activate = *((int *)hip_get_param_contents_direct(param));
	
	// set global variable
	hip_use_userspace_ipsec = activate;
	HIP_DEBUG("userspace ipsec activate: %i \n", activate);
	
	/* remove the policies from the kernel-mode IPsec, otherwise app-packets
	 * will be captured and processed by the kernel */
	HIP_DEBUG("flushing all ipsec policies...\n");
	default_ipsec_func_set.hip_flush_all_policy();
	HIP_DEBUG("flushing all ipsec SAs...\n");
	default_ipsec_func_set.hip_flush_all_sa();
	
	/* we have to modify the ipsec function pointers to call the ones
	 * located in userspace from now on */
	HIP_DEBUG("re-initializing the hadb...\n");
	hip_uninit_hadb();
	hip_init_hadb();
	
  out_err:
	return err;
}

struct hip_common * create_add_sa_msg(struct in6_addr *saddr, 
							    struct in6_addr *daddr,
							    struct in6_addr *src_hit, 
							    struct in6_addr *dst_hit,
							    uint32_t *spi, int ealg,
							    struct hip_crypto_key *enckey,
							    struct hip_crypto_key *authkey,
							    int retransmission,
							    int direction, int update,
							    hip_ha_t *entry)
{
	struct hip_common *msg = NULL;
	int err = 0;
	socklen_t alen;
	unsigned char *hchain_anchor = NULL;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
			 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_ADD_SA, 0), -1, 
		 "build hdr failed\n");
	
	HIP_DEBUG_IN6ADDR("Source IP address: ", saddr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)saddr,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n"); 
	
	HIP_DEBUG_IN6ADDR("Destination IP address : ", daddr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)daddr,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG_HIT("Source HIT: ", src_hit);
	HIP_IFEL(hip_build_param_contents(msg, (void *)src_hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n"); 

	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);
	HIP_IFEL(hip_build_param_contents(msg, (void *)dst_hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n");

	if (!retransmission || *spi == 0) {
		*spi = hip_userspace_ipsec_acquire_spi((hip_hit_t *) src_hit, 
						       (hip_hit_t *) dst_hit);
		
		HIP_DEBUG("getting random spi value: %x\n", *spi);
	}	
	
	HIP_DEBUG("the spi value is : %x \n", *spi);
	HIP_IFEL(hip_build_param_contents(msg, (void *)spi, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG("the nat_mode value is %u \n", entry->nat_mode);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->nat_mode, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");

	HIP_DEBUG("the local_port value is %u \n", entry->peer_udp_port);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->local_udp_port, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG("the peer_port value is %u \n", entry->peer_udp_port);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->peer_udp_port, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG("esp protection extension transform is %u \n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
					  HIP_PARAM_UINT, sizeof(uint8_t)), -1,
					  "build param contents failed\n");
	
	// only transmit the anchor to the firewall, if the esp extension is used
	if (entry->esp_prot_transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		// choose the anchor depending on the direction
		if (direction == HIP_SPI_DIRECTION_IN)
			hchain_anchor = entry->esp_peer_anchor;
		else
			hchain_anchor = entry->esp_local_anchor;
		
	    HIP_HEXDUMP("the esp protection anchor is ", hchain_anchor,
	    		esp_prot_transforms[entry->esp_prot_transform]);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&hchain_anchor, HIP_PARAM_HCHAIN_ANCHOR,
						  esp_prot_transforms[entry->esp_prot_transform]), -1,
						  "build param contents failed\n");
	}

	HIP_HEXDUMP("crypto key :", enckey, sizeof(struct hip_crypto_key));
	HIP_IFEL(hip_build_param_contents(msg,
					  (struct hip_crypto_key *)enckey,
					  HIP_PARAM_KEYS,
					  sizeof(struct hip_crypto_key)), -1,
					  "build param contents failed\n"); 
	
	HIP_HEXDUMP("authen key :", authkey, sizeof(struct hip_crypto_key));
	HIP_IFEL(hip_build_param_contents(msg,
					  (struct hip_crypto_key *)authkey,
					  HIP_PARAM_KEYS,
					  sizeof(struct hip_crypto_key)), -1,
					  "build param contents failed\n"); 
	
	HIP_DEBUG("ealg value is %d \n", ealg);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&ealg, HIP_PARAM_INT,
					  sizeof(int)), -1,
					  "build param contents failed\n");
	
	
	HIP_DEBUG("retransmission value is %d \n", retransmission);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&retransmission,
					  HIP_PARAM_INT, sizeof(int)), -1,
					  "build param contents failed\n");  
	
	HIP_DEBUG("the direction value is %d \n", direction);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&direction,
					  HIP_PARAM_INT,
					  sizeof(int)), -1,
					  "build param contents failed\n"); 
	
	HIP_DEBUG("the update value is %d \n", update);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&update, HIP_PARAM_INT,
					  sizeof(int)), -1,
					  "build param contents failed\n");
	
  out_err:
  	if (err)
  	{
  		if (msg)
  			free(msg);
  		msg = NULL;
  	}
  	
  	return msg;
}
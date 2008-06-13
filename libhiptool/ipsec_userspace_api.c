#include "ipsec_userspace_api.h"

int hip_firewall_sock_fd = -1;

/* hipd sends a packet to the firewall making it add a new sa entry
 * 
 * this function is called by hip daemon */
uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr, 
				    struct in6_addr *daddr,
				    struct in6_addr *src_hit, 
				    struct in6_addr *dst_hit,
				    uint32_t *spi, int ealg,
				    struct hip_crypto_key *enckey,
				    struct hip_crypto_key *authkey,
				    int already_acquired,
				    int direction, int update,
				    int sport, int dport  ) {
	
	struct hip_common *msg;
	struct sockaddr_in6 hip_firewall_addr; 
	struct in6_addr loopback = in6addr_loopback;
	int err = 0;
	int n;
	socklen_t alen;
	
	
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

	if (!already_acquired || *spi == 0) {
		*spi = hip_userspace_ipsec_acquire_spi((hip_hit_t *) src_hit, 
						       (hip_hit_t *) dst_hit);
		
		HIP_DEBUG("getting random spi value: %x\n", *spi);
	}	
	
	HIP_DEBUG("the spi value is : %x \n", *spi);
	HIP_IFEL(hip_build_param_contents(msg, (void *)spi, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n"); 

	HIP_DEBUG("the sport vaule is %d \n", sport);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&sport, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG("the dport value is %d \n", dport);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&dport, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");  

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
	
	HIP_DEBUG("ealg  value is %d \n", ealg);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&ealg, HIP_PARAM_INT,
					  sizeof(int)), -1,
					  "build param contents failed\n");  
	
	HIP_DEBUG("already_acquired value is %d \n", already_acquired);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&already_acquired,
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
	
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	ipv6_addr_copy(&(hip_firewall_addr.sin6_addr.s6_addr), &loopback);  
     
	HIP_DEBUG_IN6ADDR("sending message to loopback: ", 
			  hip_firewall_addr.sin6_addr.s6_addr);
	
	n = sendto(hip_firewall_sock_fd, msg, hip_get_msg_total_len(msg), 0,
		   &hip_firewall_addr, sizeof(hip_firewall_addr));
	if (n < 0)
	{
		HIP_ERROR("Sendto firewall failed.\n");
		err = -1;
		goto out_err;
	}
	else HIP_DEBUG("hipd ipsec_add_sa --> Sendto firewall OK.\n");
	
 out_err:
	return err;	 
}

int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit,
					  hip_hit_t *dst_hit,
					  struct in6_addr *src_addr,
					  struct in6_addr *dst_addr, u8 proto,
					  int use_full_prefix, int update) {
	/* XX FIXME: TAO */
	return 0;
}

void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit,
					    hip_hit_t *dst_hit, u8 proto,
					    int use_full_prefix) {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_policy() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_sa() {
	/* XX FIXME: TAO */
}

uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit,
					 hip_hit_t *dsthit) {
	return hip_acquire_spi(srchit, dsthit);
}

void hip_userspace_ipsec_delete_default_prefix_sp_pair() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_setup_default_sp_prefix_pair() {
	/* XX FIXME: TAO */
	return 0;
}

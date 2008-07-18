/**
 * @author René Hummen
 */

//#include <sys/socket.h>		/* socket() */
//#include <sys/time.h>		/* timeval */
#include "user_ipsec.h"
//#include "ife.h"
//#include "misc.h"			/* hip conversion functions */

//#define ESP_PACKET_SIZE 2500
// this is the maximum buffer-size needed for an userspace ipsec esp packet
#define MAX_ESP_PADDING 255
#define ESP_PACKET_SIZE (HIP_MAX_PACKET + sizeof(struct udphdr) \
		+ sizeof(struct hip_esp) + MAX_ESP_PADDING + sizeof(struct hip_esp_tail) \
		+ EVP_MAX_MD_SIZE)

// not implemented yet
#define DEFAULT_LIFETIME 0

// this is the ESP packet we are about to build
unsigned char *esp_packet = NULL;
// the original packet before ESP encryption
unsigned char *decrypted_packet = NULL;
// sockets in order to re-insert the esp packet into the stack
int raw_sock_v4 = 0, raw_sock_v6 = 0;
int is_init = 0;

/* this will initialize the esp_packet buffer and the sockets,
 * they are not set yet */
int userspace_ipsec_init()
{
	int on = 1, err = 0;

	HIP_DEBUG("\n");

	if (!is_init)
	{
		// init sadb
		HIP_IFEL(hip_sadb_init(), -1, "failed to init sadb\n");

		HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);
		// allocate memory for the packet buffers
		HIP_IFE(!(esp_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);
		HIP_IFE(!(decrypted_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);

		// open IPv4 raw socket
		raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (raw_sock_v4 < 0)
		{
			HIP_DEBUG("*** ipv4_raw_socket socket() error for raw socket\n");

			err = -1;
			goto out_err;
		}
		// this option allows us to add the IP header ourselves
		if (setsockopt(raw_sock_v4, IPPROTO_IP, IP_HDRINCL, (char *)&on,
					sizeof(on)) < 0)
		{
			HIP_DEBUG("*** setsockopt() error for IPv4 raw socket\n");

			err = 1;
			goto out_err;
		}

		// open IPv6 raw socket, no options needed here
		raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (raw_sock_v6 < 0) {
			HIP_DEBUG("*** ipv6_raw_socket socket() error for raw socket\n");

			err = 1;
			goto out_err;
		}
		// this option allows us to add the IP header ourselves
		if (setsockopt(raw_sock_v6, IPPROTO_IPV6, IP_HDRINCL, (char *)&on,
					sizeof(on)) < 0)
		{
			HIP_DEBUG("*** setsockopt() error for IPv6 raw socket\n");

			err = 1;
			goto out_err;
		}

		is_init = 1;

		HIP_DEBUG("userspace IPsec successfully initialised\n");
	}

  out_err:
  	return err;
}

hip_hit_t *hip_fw_get_default_hit(void) {
	if (ipv6_addr_is_null(&default_hit)) {
		_HIP_DEBUG("Querying hipd for default hit\n");
		if (hip_query_default_local_hit_from_hipd(&default_hit))
			return NULL;
	}
	return &default_hit;
}

/* Get default HIT*/
int hip_query_default_local_hit_from_hipd(hip_hit_t *hit)
{

	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_tlv_common *param = NULL;
	hip_hit_t *defhit  = NULL;
	struct endpoint_hip *endp = NULL;

	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		 "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
		 "send/recv daemon info\n");

	HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1);
	defhit = hip_get_param_contents_direct(param);
	ipv6_addr_copy(hit, defhit);

out_err:
	return err;

}

/* prepares the environment for esp encryption */
int hip_fw_userspace_ipsec_output(hip_fw_context_t *ctx)
{
	// entry matching the peer HIT
	hip_sa_entry_t *entry = NULL;
	// the routable addresses as used in HIPL
	struct in6_addr preferred_local_addr;
	struct in6_addr preferred_peer_addr;
	struct sockaddr_storage preferred_peer_sockaddr;
	struct timeval now;
	int esp_packet_len = 0;
	int out_ip_version = 0;
	int err = 0;

	/* we should only get HIT addresses here
	 * LSI have been handled by LSI module before and converted to HITs */
	HIP_ASSERT(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst));

	HIP_DEBUG("original packet length: %u \n", ctx->ipq_packet->data_len);
	HIP_HEXDUMP("original packet :", ctx->ipq_packet->payload, ctx->ipq_packet->data_len);

	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;
	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ntohs(ip6_hdr->ip6_plen));
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);

	HIP_DEBUG_HIT("src_hit", &ctx->src);
	HIP_DEBUG_HIT("dst_hit", &ctx->dst);

	// re-use allocated esp_packet memory space
	memset(esp_packet, 0, ESP_PACKET_SIZE);
	gettimeofday(&now, NULL);

	// SAs directing outwards are indexed with local and peer HIT
	entry = hip_sa_entry_find_outbound(&ctx->src, &ctx->dst);

	// create new SA entry, if none exists yet
	if (entry == NULL)
	{
		HIP_DEBUG("triggering BEX...\n");

		/* no SADB entry -> trigger base exchange providing destination hit only */
		HIP_IFEL(hip_trigger_bex(&ctx->src, &ctx->dst, NULL, NULL, NULL, NULL), -1,
			 "trigger bex\n");

		// as we don't buffer the packet right now, we have to drop it
		// due to not routable addresses
		err = 1;

		// don't process this message any further
		goto out_err;
	}

	HIP_DEBUG("matching SA entry found\n");

	/* get preferred routable addresses */
	// TODO add multihoming support -> look up preferred address here
	memcpy(&preferred_local_addr, entry->src_addr, sizeof(struct in6_addr));
	memcpy(&preferred_peer_addr, entry->dst_addr, sizeof(struct in6_addr));

	HIP_DEBUG_HIT("preferred_local_addr", &preferred_local_addr);
	HIP_DEBUG_HIT("preferred_peer_addr", &preferred_peer_addr);

	// check preferred addresses for the address type of the output
	if (IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
			&& IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv4\n");
		out_ip_version = 4;
	} else if (!IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
			&& !IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv6\n");
		out_ip_version = 6;
	} else
	{
		HIP_ERROR("bad address combination\n");

		err = -1;
		goto out_err;
	}

	// encrypt transport layer and create new packet
	HIP_IFEL(hip_beet_mode_output(ctx, entry, &preferred_local_addr, &preferred_peer_addr,
			esp_packet, &esp_packet_len), 1, "failed to create ESP packet");

	// create sockaddr for sendto
	hip_addr_to_sockaddr(&preferred_peer_addr, &preferred_peer_sockaddr);

	// reinsert the esp packet into the network stack
	if (out_ip_version == 4)
		err = sendto(raw_sock_v4, esp_packet, esp_packet_len, 0,
				(struct sockaddr *)&preferred_peer_sockaddr,
				hip_sockaddr_len(&preferred_peer_sockaddr));
	else
		err = sendto(raw_sock_v6, esp_packet, esp_packet_len, 0,
						(struct sockaddr *)&preferred_peer_sockaddr,
						hip_sockaddr_len(&preferred_peer_sockaddr));

	if (err < 0) {
		HIP_DEBUG("sendto() failed\n");
	} else
	{
		HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
		HIP_DEBUG("dropping original packet...\n");

		// update SA statistics for replay protection etc
		pthread_mutex_lock(&entry->rw_lock);
		entry->bytes += err;
		entry->usetime.tv_sec = now.tv_sec;
		entry->usetime.tv_usec = now.tv_usec;
		entry->usetime_ka.tv_sec = now.tv_sec;
		entry->usetime_ka.tv_usec = now.tv_usec;
		pthread_mutex_unlock(&entry->rw_lock);
	}

  out_err:
  	return err;
}

int hip_fw_userspace_ipsec_input(hip_fw_context_t *ctx)
{
	struct hip_esp *esp_hdr = NULL;
	struct hip_esp_ext *esp_exthdr = NULL;
	struct sockaddr_storage local_sockaddr;
	// entry matching the SPI
	hip_sa_entry_t *entry = NULL;
	// return entry
	hip_sa_entry_t *inverse_entry = NULL;
	struct in6_addr src_hit;
	struct in6_addr dst_hit;
	struct timeval now;
	int decrypted_packet_len = 0;
	uint32_t spi = 0;
	uint32_t seq_no = 0;
	uint32_t hash = 0;
	unsigned char *sent_hc_element = NULL;
	int err = 0;

	// we should only get ESP packets here
	HIP_ASSERT(ctx->packet_type == ESP_PACKET);

	// re-use allocated decrypted_packet memory space
	memset(decrypted_packet, 0, ESP_PACKET_SIZE);
	gettimeofday(&now, NULL);

	/* get ESP header of input packet
	 * UDP encapsulation is handled in firewall already */
	esp_hdr = ctx->transport_hdr.esp;
	spi = ntohl(esp_hdr->esp_spi);
	seq_no = ntohl(esp_hdr->esp_seq);

	// lookup corresponding SA entry by dst_addr and SPI
	HIP_IFEL(!(entry = hip_sa_entry_find_inbound(&ctx->dst, spi)), -1,
			"no SA entry found for dst_addr and SPI %u \n", spi);
	HIP_DEBUG("matching SA entry found\n");

	// do a partial consistency check of the entry
	HIP_ASSERT(entry->inner_src_addr && entry->inner_dst_addr);

	HIP_DEBUG_HIT("src hit: ", entry->inner_src_addr);
	HIP_DEBUG_HIT("dst hit: ", entry->inner_dst_addr);

	// TODO implement check with seq window
	// check for correct SEQ no.
	HIP_DEBUG("SEQ no. of entry: %u \n", entry->sequence);
	HIP_DEBUG("SEQ no. of incoming packet: %u \n", seq_no);
	//HIP_IFEL(entry->sequence != seq_no, -1, "ESP sequence numbers do not match\n");

	// verify the esp extension hash, if in use
	HIP_HEXDUMP("hash element: ", ((unsigned char *)esp_hdr) + sizeof(struct hip_esp), 8);
	HIP_IFEL(verify_esp_prot_hash(entry, ((unsigned char *)esp_hdr) + sizeof(struct hip_esp)),
			-1, "hash could NOT be verified\n");

// this is helpful for testing
#if 0
	// check if we have a SA entry to reply to
	HIP_DEBUG("checking for inverse entry\n");
	HIP_IFEL(!(inverse_entry = hip_sa_entry_find_outbound(entry->inner_dst_addr,
			entry->inner_src_addr)), -1,
			"corresponding sadb entry for outgoing packets not found\n");
#endif

	// decrypt the packet and create a new HIT-based one
	HIP_IFEL(hip_beet_mode_input(ctx, entry, decrypted_packet, &decrypted_packet_len), 1,
			"failed to recreate original packet\n");

	HIP_HEXDUMP("restored original packet: ", decrypted_packet, decrypted_packet_len);
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)decrypted_packet;
	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ip6_hdr->ip6_plen);
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);

	// create sockaddr for sendto
	hip_addr_to_sockaddr(entry->inner_dst_addr, &local_sockaddr);

	// re-insert the original HIT-based (-> IPv6) packet into the network stack
	err = sendto(raw_sock_v6, decrypted_packet, decrypted_packet_len, 0,
					(struct sockaddr *)&local_sockaddr,
					hip_sockaddr_len(&local_sockaddr));
	if (err < 0) {
		HIP_DEBUG("hip_esp_input(): sendto() failed\n");
	} else
	{
		HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
		HIP_DEBUG("dropping ESP packet...\n");

		pthread_mutex_lock(&entry->rw_lock);
		entry->bytes += err;
		entry->usetime.tv_sec = now.tv_sec;
		entry->usetime.tv_usec = now.tv_usec;
		entry->usetime_ka.tv_sec = now.tv_sec;
		entry->usetime_ka.tv_usec = now.tv_usec;
		pthread_mutex_unlock(&entry->rw_lock);
	}

  out_err:
  	return err;
}

int handle_sa_add_request(struct hip_common * msg,
			  struct hip_tlv_common *param)
{
	struct in6_addr *src_addr = NULL, *dst_addr = NULL;
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	uint32_t spi = 0;
	int ealg = 0, err = 0;
	struct hip_crypto_key *enckey = NULL, *authkey = NULL;
	int retransmission = 0, direction = 0, update = 0;
	uint16_t local_port = 0, peer_port = 0;
	uint8_t encap_mode = 0, esp_prot_transform = 0;
	unsigned char *esp_prot_anchor = NULL;
	unsigned char *e_key = NULL, *a_key = NULL;
	uint32_t e_keylen = 0, a_keylen = 0, e_type = 0, a_type = 0;

	// get all attributes from the message

	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
	src_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("Source IP address: ", src_addr);

	param = hip_get_next_param(msg, param);
	dst_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("Destination IP address : ", dst_addr);

	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source Hit: ", src_hit);

	param = hip_get_next_param(msg, param);
	dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_UINT);
	spi = *((uint32_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the spi value is : %u \n", spi);

	param = hip_get_next_param(msg, param);
	encap_mode = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the nat_mode value is %u \n", encap_mode);

	param = hip_get_next_param(msg, param);
	local_port = *((uint16_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the local_port value is %u \n", local_port);

	param = hip_get_next_param(msg, param);
	peer_port = *((uint16_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the peer_port value is %u \n", peer_port);

	param = hip_get_next_param(msg, param);
	esp_prot_transform = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection extension transform is %u \n", esp_prot_transform);

	// this parameter is only included, if the esp extension is used
	if (esp_prot_transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
		esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("the esp protection anchor is ", esp_prot_anchor,
			    esp_prot_transforms[esp_prot_transform]);
	} else
	{
		esp_prot_anchor = NULL;
	}

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_KEYS);
	enckey = (struct hip_crypto_key *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("crypto key :", enckey, sizeof(struct hip_crypto_key));

	param = hip_get_next_param(msg, param);
	authkey = (struct hip_crypto_key *)hip_get_param_contents_direct(param);
	HIP_HEXDUMP("authen key :", authkey, sizeof(struct hip_crypto_key));

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_INT);
	ealg = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("ealg value is %d \n", ealg);

	param =  hip_get_next_param(msg, param);
	retransmission = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("already_acquired value is %d \n", retransmission);

	param =  hip_get_next_param(msg, param);
	direction = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the direction value is %d \n", direction);

	param =  hip_get_next_param(msg, param);
	update = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the update value is %d \n", update);

	/******* MAP HIP ESP encryption INDEX to SADB encryption INDEX *******/

	// TODO move to user_ipsec_esp.c -> don't store in entry
	a_keylen = hip_auth_key_length_esp(ealg);
	e_keylen = hip_enc_key_length(ealg);

	// TODO store hip_crypto_keys -> do not convert
	e_key = (unsigned char *) enckey->key;
	a_key = (unsigned char *) authkey->key;

	HIP_HEXDUMP("auth key: ", a_key, a_keylen);
	HIP_HEXDUMP("enc key: ", e_key, e_keylen);

	HIP_IFEL(hip_sadb_add(direction, spi, BEET_MODE, src_addr, dst_addr,
			src_hit, dst_hit, encap_mode, local_port, peer_port, ealg,
			a_keylen, e_keylen, a_key, e_key, DEFAULT_LIFETIME,
			esp_prot_transform, esp_prot_anchor, retransmission, update), -1,
			"failed to add user_space IPsec security association\n");

#if 0
	if (dst_hit)
  		err = firewall_set_bex_state(src_hit, dst_hit, 1);
  	else
  		err = firewall_set_bex_state(src_hit, dst_hit, -1);
#endif

  out_err:
	return err;
}

#if 0
int hipl_userspace_ipsec_sadb_add_wrapper(struct in6_addr *saddr,
					      struct in6_addr *daddr,
					      struct in6_addr *src_hit,
					      struct in6_addr *dst_hit,
					      uint32_t spi, uint8_t nat_mode,
					      uint16_t local_port,
					      uint16_t peer_port,
					      uint8_t esp_prot_transform,
					      unsigned char *esp_prot_anchor,
					      int ealg, struct hip_crypto_key *enckey,
					      struct hip_crypto_key *authkey,
					      int already_acquired,
					      int direction, int update)
{
	uint16_t hit_magic = 0;
	uint8_t *ipsec_e_key = NULL;
	uint8_t *ipsec_a_key = NULL;
	uint32_t ipsec_e_keylen = 0;
	uint32_t ipsec_a_keylen = 0;
	/*HIT address,  inner addresses*/
	struct sockaddr_storage inner_src, inner_dst;
	struct sockaddr_storage src, dst; /* IP address*/
	uint32_t ipsec_e_type = 0; /* encryption type */
	uint32_t ipsec_a_type = 0; /* authentication type is equal to encryption type */
	int err = 0;

	/* MAP HIP ESP encryption INDEX to SADB encryption INDEX */
	switch(ealg) {
		case HIP_ESP_AES_SHA1:
			ipsec_e_type = SADB_X_EALG_AESCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
		case HIP_HIP_3DES_SHA1:
			ipsec_e_type = SADB_EALG_3DESCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
		case HIP_HIP_BLOWFISH_SHA1:
			ipsec_e_type = SADB_X_EALG_BLOWFISHCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
	}

	ipsec_a_keylen = hip_auth_key_length_esp(ealg);
	ipsec_e_keylen = hip_enc_key_length(ealg);

	ipsec_e_key = (uint8_t *) enckey->key;
	ipsec_a_key = (uint8_t *) authkey->key;

	HIP_HEXDUMP("auth key: ", ipsec_a_key, ipsec_a_keylen);
	HIP_HEXDUMP("enc key: ", ipsec_e_key, ipsec_e_keylen);

	HIP_DEBUG_HIT("source hit: ", src_hit);
	HIP_DEBUG_IN6ADDR("source ip: ", saddr);
	HIP_DEBUG_HIT("dest hit: ", dst_hit);
	HIP_DEBUG_IN6ADDR("dest ip: ", daddr);

	/* ip6/ip4 (in6_addr) address conversion to sockddr_storage */
	hip_addr_to_sockaddr(saddr, &src); /* source ip address conversion */
	hip_addr_to_sockaddr(daddr, &dst); /* destination ip address conversion */
	hip_addr_to_sockaddr(src_hit, &inner_src); /* source HIT conversion */
	hip_addr_to_sockaddr(dst_hit, &inner_dst); /* destination HIT conversion */

	/* looking at the usermode code, it may be that the lifetime is stored in
	 * the hip_sadb_entry but never used. It is supposed to be the value in
	 * seconds after which the SA expires but I don't think this is
	 * implemented. It is a preserved field from the kernel API, from the
	 * PFKEY messages.
	 *
	 * Here just give a value 100 to lifetime
	 * */
	HIP_IFEL(hip_sadb_add(TYPE_USERSPACE_IPSEC, IPSEC_MODE, (struct sockaddr *) &inner_src,
			(struct sockaddr *) &inner_dst, (struct sockaddr *) &src,
			(struct sockaddr *) &dst, local_port, peer_port, direction, spi, ipsec_e_key,
			ipsec_e_type, ipsec_e_keylen, ipsec_a_key, ipsec_a_type, ipsec_a_keylen, 100 ,
			hit_magic, nat_mode, esp_prot_transform, esp_prot_anchor), -1,
			"HIP user_space IPsec security association DB add is not successful\n");

	HIP_DEBUG(" HIP user space IPsec security sadb is done \n\n");

 out_err:

	return err;
}
#endif

int cast_sockaddr_to_in6_addr(struct sockaddr_storage *sockaddr, struct in6_addr *in6_addr)
{
	int err = 0;

	if (sockaddr->ss_family == AF_INET)
	{
		IPV4_TO_IPV6_MAP((struct in_addr *)hip_cast_sa_addr(sockaddr),
				in6_addr);

	} else if (sockaddr->ss_family == AF_INET6)
	{
		// unsafe casts can only be done with pointers
		*in6_addr = *((struct in6_addr *)hip_cast_sa_addr(sockaddr));

	} else
	{
		HIP_DEBUG("unable to find ip address type\n");

		err = 1;
		goto out_err;
	}

  out_err:
  	return err;
}

int send_userspace_ipsec_to_hipd(int active)
{
	int err = 0;
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_USERSPACE_IPSEC, 0), -1,
		 "build hdr failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)&active, HIP_PARAM_INT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");

	HIP_DEBUG("sending userspace ipsec activation to hipd...\n");
	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
	HIP_DEBUG("send_recv msg succeeded\n");

	HIP_DEBUG("userspace ipsec activated\n");

 out_err:
	if (msg)
		free(msg);
	return err;
}

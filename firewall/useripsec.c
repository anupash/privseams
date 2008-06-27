/** 
 * @author René Hummen
 */

#include "useripsec.h"
#include <sys/socket.h>		/* socket() */
#include "misc.h"			/* hip conversion functions */
#include "hip_esp.h"
#include "utils.h"
#include <sys/time.h>		/* timeval */
#include "hashchain_store.h"

#define ESP_PACKET_SIZE 2500
// this is the maximum buffer-size needed for an userspace ipsec esp packet
#if 0
#define MAX_ESP_PADDING 255
#define ESP_PACKET_SIZE (BUFSIZE + sizeof(struct udphdr) + sizeof(struct hip_esp) +
				MAX_ESP_PADDING + sizeof(struct hip_esp_tail) + EVP_MAX_MD_SIZE)
#endif
				
// this is the ESP packet we are about to build
unsigned char *esp_packet = NULL;
// the original packet before ESP encryption
unsigned char *decrypted_packet = NULL;
// sockets in order to re-insert the esp packet into the stack
int raw_sock_v4 = 0, raw_sock_v6 = 0;
int is_init = 0;

extern int hip_esp_protection_extension;

uint16_t checksum_magic(const struct in6_addr *initiator, const struct in6_addr *receiver);

/* this will initialize the esp_packet buffer and the sockets,
 * they are not set yet */
int userspace_ipsec_init()
{	
	int on = 1;
	int err = 0;
	
	HIP_DEBUG("\n");
	
	if (!is_init)
	{
		HIP_IFE(!(esp_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);
		HIP_IFE(!(decrypted_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);
		
		if (hip_esp_protection_extension)
		{
			HIP_IFEL(esp_prot_ext_init(), -1, "failed to init esp protection extension\n");
		}
		
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
	struct hip_tlv_common *current_param = NULL;
	hip_hit_t *defhit  = NULL;	
	struct endpoint_hip *endp=NULL;
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		 "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
		 "send/recv daemon info\n");
	
	while((current_param = hip_get_next_param(msg, current_param)) != NULL)
	{
		defhit = (in6_addr_t *)hip_get_param_contents_direct(current_param);
		//set_hit_prefix(defhit); // miika: what the heck?
		HIP_DEBUG_HIT("default hi is ",defhit);
	}

	ipv6_addr_copy(hit, defhit);

out_err:
	return err;

}

/* prepares the environment for esp encryption */
int hip_fw_userspace_ipsec_output(hip_fw_context_t *ctx)
{
	// peer HIT, sockaddr does not provide enough space for sockaddr_in6
	struct sockaddr_storage sockaddr_peer_hit;
	// entry matching the peer HIT
	hip_sadb_entry *entry = NULL;
	// the routable addresses as used in OpenHIP
	struct sockaddr_storage preferred_local_sockaddr;
	struct sockaddr_storage preferred_peer_sockaddr;
	// the routable addresses as used in HIPL
	struct in6_addr preferred_local_addr;
	struct in6_addr preferred_peer_addr;
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
	
	HIP_DEBUG_HIT("src_hit: ", &ctx->src);
	HIP_DEBUG_HIT("dst_hit: ", &ctx->dst);
	
	// re-use allocated esp_packet memory space
	memset(esp_packet, 0, ESP_PACKET_SIZE);
	gettimeofday(&now, NULL);
	
	// SAs directing outwards are indexed with the peer's HIT
	// FIXME this will only allow one connection to this peer HIT
	hip_addr_to_sockaddr(&ctx->dst, &sockaddr_peer_hit);
	
	entry = hip_sadb_lookup_addr((struct sockaddr *) &sockaddr_peer_hit);
	
	// create new SA entry, if none exists yet
	if (entry == NULL)
	{
			HIP_DEBUG("pfkey send acquire\n");
			
			// no SADB entry -> buffer triggering packet and send ACQUIRE
			// FIXME checks for SA entry again
			// TODO this will result in a SEGFAULT
			//if (buffer_packet(&sockaddr_peer_hit, ctx->ipq_packet->payload, ctx->ipq_packet->data_len))
				
				/* Trigger base exchange providing destination hit only */
				HIP_IFEL(hip_trigger_bex(NULL, &ctx->dst, NULL, NULL), -1,
					 "trigger bex\n");
				
			// as we don't buffer the packet right now, we have to drop it
			// due to not routable addresses
			err = 1;
			
			// don't process this message any further
			goto out_err;
	}
		
	HIP_DEBUG("matching SA entry found\n");
	
	// unbuffer buffered packets -> re-injects original packets
	//unbuffer_packets(entry);
	
	// get preferred routable addresses
	HIP_IFE(get_preferred_sockaddr(entry->src_addrs, &preferred_local_sockaddr), -1);
	HIP_IFE(get_preferred_sockaddr(entry->dst_addrs, &preferred_peer_sockaddr), -1);
	HIP_IFE(cast_sockaddr_to_in6_addr(&preferred_local_sockaddr, &preferred_local_addr), -1);
	HIP_IFE(cast_sockaddr_to_in6_addr(&preferred_peer_sockaddr, &preferred_peer_addr), -1);

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
	HIP_IFEL(hip_esp_output(ctx, entry, &preferred_local_addr, &preferred_peer_addr,
			esp_packet, &esp_packet_len), 1, "failed to create ESP packet");

	// reinsert the esp packet into the network stack
	// TODO check flags
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
	// entry matching the SPI
	hip_sadb_entry *entry = NULL;
	// return entry
	hip_sadb_entry *inverse_entry = NULL;
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
	
	HIP_IFEL(userspace_ipsec_init(), -1, "failed to initialize userspace ipsec\n");
	
	// re-use allocated decrypted_packet memory space
	memset(decrypted_packet, 0, ESP_PACKET_SIZE);
	gettimeofday(&now, NULL);

	/* get ESP header of input packet
	 * UDP encapsulation is handled in firewall already
	 * check if we are using the esp header extension */
	if (hip_esp_protection_extension)
	{
		esp_exthdr = (struct hip_esp_ext *)ctx->transport_hdr.esp;	
		spi = ntohl(esp_exthdr->esp_spi);
		seq_no = ntohl(esp_exthdr->esp_seq);
		hash = ntohl(esp_exthdr->hc_element);
	} else
	{
		esp_hdr = ctx->transport_hdr.esp;	
		spi = ntohl(esp_hdr->esp_spi);
		seq_no = ntohl(esp_hdr->esp_seq);
	}
	
	// lookup corresponding SA entry by SPI
	HIP_IFEL(!(entry = hip_sadb_lookup_spi(spi)), -1,
			"no SA entry found for SPI %u \n", spi);
	HIP_DEBUG("matching SA entry found\n");
	
	// do a partial consistency check of the entry
	HIP_ASSERT(entry->inner_src_addrs && entry->inner_dst_addrs);

	// TODO implement check with seq window
	// check for correct SEQ no.
	HIP_DEBUG("SEQ no. of entry: %u \n", entry->sequence);
	HIP_DEBUG("SEQ no. of incoming packet: %u \n", seq_no);
	//HIP_IFEL(entry->sequence != seq_no, -1, "ESP sequence numbers do not match\n");
	
	if (hip_esp_protection_extension)
	{
		HIP_IFEL(verify_esp_prot_hash(entry, &hash), -1, "hash could not be verified");
	}

	// check if we have a SA entry to reply to
	HIP_IFEL(!(inverse_entry = hip_sadb_lookup_addr(
		(struct sockaddr *)&entry->inner_src_addrs->addr)), 1,
		"corresponding sadb entry for outgoing packets not found\n");

// TODO check where we set the UDP dst port
#if 0
	/*HIP_DEBUG ( "DST_PORT = %u\n", 
	 * inverse_entry->dst_port);*/
	if (inverse_entry->dst_port == 0) {
		HIP_DEBUG ("ESP channel - Setting dst_port "
			"to %u\n",ntohs(udph->source));
		inverse_entry->dst_port = ntohs(udph->source);
	}
	// TODO handle else case
#endif
	
	// convert HITs to type used in hipl	
	HIP_IFE(cast_sockaddr_to_in6_addr(&entry->inner_src_addrs->addr, &src_hit), -1);
	HIP_IFE(cast_sockaddr_to_in6_addr(&entry->inner_dst_addrs->addr, &dst_hit), -1);
	
	HIP_DEBUG_HIT("src hit: ", &src_hit);
	HIP_DEBUG_HIT("dst hit: ", &dst_hit);
	
	// decrypt the packet and create a new HIT-based one
	HIP_IFEL(hip_esp_input(ctx, entry, &src_hit, &dst_hit,
			decrypted_packet, &decrypted_packet_len), 1,
			"failed to recreate original packet\n");
	
	HIP_HEXDUMP("restored original packet: ", decrypted_packet, decrypted_packet_len);
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)decrypted_packet;
	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ip6_hdr->ip6_plen);
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);
	
	// re-insert the original HIT-based (-> IPv6) packet into the network stack
	// TODO check flags
	err = sendto(raw_sock_v6, decrypted_packet, decrypted_packet_len, 0,
					(struct sockaddr *)&entry->inner_dst_addrs->addr,
					hip_sockaddr_len(&entry->inner_dst_addrs->addr));
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

int hipl_userspace_ipsec_sadb_add_wrapper(struct in6_addr *saddr,
					      struct in6_addr *daddr,
					      struct in6_addr *src_hit, 
					      struct in6_addr *dst_hit,
					      uint32_t *spi, uint8_t nat_mode,
					      uint16_t local_port,
					      uint16_t peer_port,
					      uint32_t hchain_anchor, int ealg,
					      struct hip_crypto_key *enckey,
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
	int encap_mode = 0; /* 0 - none, 1 - udp */
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
	
	/* hit_magic is the 16-bit sum of the bytes of both HITs. 
	 * the checksum is calculated as other Internet checksum, according to 
	 * the HIP spec this is the sum of 16-bit words from the input data a 
	 * 32-bit accumulator is used but the end result is folded into a 16-bit
	 * sum
	 */
	hit_magic = checksum_magic(src_hit, dst_hit);
	
	/* looking at the usermode code, it may be that the lifetime is stored in
	 * the hip_sadb_entry but never used. It is supposed to be the value in
	 * seconds after which the SA expires but I don't think this is
	 * implemented. It is a preserved field from the kernel API, from the
	 * PFKEY messages.
	 * 
	 * Here just give a value 100 to lifetime
	 * */
	err = hip_sadb_add(TYPE_USERSPACE_IPSEC, IPSEC_MODE, (struct sockaddr *) &inner_src,
			(struct sockaddr *) &inner_dst, (struct sockaddr *) &src, (struct sockaddr *) &dst,
			local_port, peer_port, direction, spi, ipsec_e_key, ipsec_e_type,
			ipsec_e_keylen, ipsec_a_key, ipsec_a_type, ipsec_a_keylen, 100 , hit_magic, nat_mode,
			hchain_anchor);
	
	// Tell firewall that HIT SRC + DST HAS A SECURITY ASSOCIATION
	HIP_DEBUG("HIP IPsec userspace SA add return value %d\n", err);

	if(err == -1)
	{
		
		HIP_ERROR("HIP user_space IPsec security association DB add is not successful\n");
		goto out_err;
		
	} 	
	HIP_DEBUG(" HIP user space IPsec security sadb is done \n\n");

 out_err:
	
	return err;
}

/*
 * * function checksum_magic()
 * *
 * * Calculates the hitMagic value given two HITs.
 * * Note that since this is simple addition, it doesn't matter
 * * which HIT is given first, and the one's complement is not
 * * taken.
 */
uint16_t checksum_magic(const struct in6_addr *initiator, const struct in6_addr *receiver)
{
	int count;
	unsigned long sum = 0;
	unsigned short *p; /* 16-bit */
	
	/* 
	 * * this checksum algorithm can be found 
	 * * in RFC 1071 section 4.1, pseudo-header
	 * * from RFC 2460
	 * */
	
	/* one's complement sum 16-bit words of data */
	/* sum initiator's HIT */
	count = HIT_SIZE;
	// TODO check if this is right
	p = (unsigned short *) initiator;
	
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	
	/* sum responder's HIT */
	count = HIT_SIZE;
	p = (unsigned short*) receiver;
	
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	
	HIP_DEBUG("hitMagic checksum over %d bytes: 0x%x\n",
		  2*HIT_SIZE, (uint16_t)sum);
	
	/* don't take the one's complement of the sum */
	return((uint16_t)sum);
}

// resolve HIT to routable addresses selecting the preferred ones
int get_preferred_sockaddr(sockaddr_list *addr_list, struct sockaddr_storage *preferred_addr)
{
	int err = 0;
	
	while (addr_list != NULL)
	{
		// TODO find preferred address and don't select first one in list
		//if (addr_list->preferred)
		//{
			HIP_DEBUG("found preferred addr\n");
			
			*preferred_addr = addr_list->addr;
			
			break;
		//}

		addr_list = addr_list->next;
	}
	
	if (addr_list == NULL)
	{
		HIP_DEBUG("unable to resolve HIT to preferred address\n");
		
		err = 1;
	}
	
  out_err:
  	return err;
}

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

int send_userspace_ipsec_to_hipd(int activate)
{
	int err = 0;
	struct hip_common *msg = NULL;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_USERSPACE_IPSEC, 0), -1, 
		 "build hdr failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)&activate, HIP_PARAM_INT,
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

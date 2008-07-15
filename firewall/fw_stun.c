#include "fw_stun.h"
extern int firewall_raw_sock_udp_v4;

int hip_fw_handle_stun_packet(hip_fw_context_t* ctx){
	int err= 0;
	// verdict zero drops the original so that you can send a new one
	// alloc new memory, copy the packet and add some zeroes (and hip header?)
	// changed ip and udp lengths and checksums accordingly
	// check handle_proxy_inbound_traffic() for examples
	// use raw_sock_v4 to send the packets
	
	HIP_DEBUG("hip_fw_handle_stun_packet\n");
	
	int  udp_len, new_udp_len, ip_len, new_ip_len;
	struct udphdr *new_udp_msg, *incoming_udp_msg;
	struct iphdr *new_ip_msg = NULL, *incoming_ip_msg;
	struct sockaddr_in dst,src; 

	memset(&dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));
	
	IPV6_TO_IPV4_MAP(&ctx->dst, &dst.sin_addr);
	IPV6_TO_IPV4_MAP(&ctx->src, &src.sin_addr);
	src.sin_family = AF_INET;
	dst.sin_family = AF_INET;
	
	udp_len = ntohs(ctx->udp_encap_hdr->len);
	ip_len = ctx->ip_hdr_len;
	
	
	incoming_ip_msg = (struct iphdr *) ctx->ip_hdr.ipv4;
	incoming_udp_msg = (struct udphdr *) ctx->udp_encap_hdr;
	
	
	
	new_udp_len = udp_len + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct hip_common);
	new_ip_len = ip_len + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct hip_common);
	
	HIP_IFEL(!(new_ip_msg = HIP_MALLOC(new_ip_len, 0), -1, "malloc\n");
	new_udp_msg = (struct udphdr *)(new_ip_msg +1);
	
	memset(new_ip_msg, 0, new_ip_len);
	//copy the ip and udp header into the new msg
	memcpy(new_ip_msg, incoming_ip_msg, sizeof(struct udphdr)+ sizeof(struct iphdr));
	// copy the stun into the end of the msg
	memcpy(((char *)new_ip_msg)+sizeof(struct udphdr)+ sizeof(struct iphdr)
			+HIP_UDP_ZERO_BYTES_LEN + sizeof(struct hip_common), 
			incoming_udp_msg +1, udp_len-sizeof(struct udphdr));
	
	new_udp_msg->len = htons(new_udp_len);
	new_ip_msg->tot_len = htons(new_ip_len);
//udp:checksum
	new_udp_msg->check = checksum_udp(new_udp_msg,&ctx->src,&ctx->dst);
//ip: checksum
	new_ip_msg->check = checksum_ip(new_ip_msg,new_ip_msg->ihl);
//send:
	HIP_IFEL(bind(firewall_raw_sock_udp_v4, (struct sockaddr *) &src, sizeof(src)),
			-1, "Binding to raw sock failed\n");
	HIP_IFEL((sendto(firewall_raw_sock_udp_v4,new_ip_msg,new_ip_len,0, &dst,sizeof(dst)) != new_ip_len),
			-1,"send udp failed");
	memset(&src, 0, sizeof(src));
	HIP_IFEL(bind(firewall_raw_sock_udp_v4, (struct sockaddr *) &src, sizeof(src)),
			-1, "Binding to raw sock failed\n");
	HIP_DEBUG("hip_fw_handle_stun_packet end\n");
out_err:
	if(new_ip_msg)
		HIP_FREE(new_ip_msg);
	return err;
}

/*
 * Checksumming is from Boeing's HIPD.
 */
#include "preinput.h"

/*
 * function checksum_packet() 
 *
 * Calculates the checksum of a HIP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 */
u16 checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	u16 checksum = 0;
	unsigned long sum = 0;
	int count = 0, length = 0;
	unsigned short *p = NULL; /* 16-bit */
	struct pseudo_header pseudoh;
	struct pseudo_header6 pseudoh6;
	u32 src_network, dst_network;
	struct in6_addr *src6, *dst6;
	struct hip_common *hiph = (struct hip_common *) data;
	
	if (src->sa_family == AF_INET) {
		/* IPv4 checksum based on UDP-- Section 6.1.2 */
		src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
		dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;
		
		memset(&pseudoh, 0, sizeof(struct pseudo_header));
		memcpy(&pseudoh.src_addr, &src_network, 4);
		memcpy(&pseudoh.dst_addr, &dst_network, 4);
		pseudoh.protocol = IPPROTO_HIP;
		length = (hiph->payload_len + 1) * 8;
		pseudoh.packet_length = htons(length);
		
		count = sizeof(struct pseudo_header); /* count always even number */
		p = (unsigned short*) &pseudoh;
	} else {
		/* IPv6 checksum based on IPv6 pseudo-header */
		src6 = &((struct sockaddr_in6*)src)->sin6_addr;
		dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;
		
		memset(&pseudoh6, 0, sizeof(struct pseudo_header6));
		memcpy(&pseudoh6.src_addr[0], src6, 16);
		memcpy(&pseudoh6.dst_addr[0], dst6, 16);
		length = (hiph->payload_len + 1) * 8;
		pseudoh6.packet_length = htonl(length);
		pseudoh6.next_hdr = IPPROTO_HIP;
                
		count = sizeof(struct pseudo_header6); /* count always even number */
		p = (unsigned short*) &pseudoh6;
	}
	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */
	
	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	/* one's complement sum 16-bit words of data */
	HIP_DEBUG("checksumming %d bytes of data.\n", length);
	count = length;
	p = (unsigned short*) data;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
	
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = ~sum;
	
	return(checksum);
}

int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst, int len)
{
	int err = 0;

        /* Currently no support for piggybacking */
        HIP_IFEL(len != hip_get_msg_total_len(hip_common), -EINVAL, 
		 "Invalid HIP packet length. Dropping\n");
        HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
		 "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
		 hip_common->payload_proto);
	HIP_IFEL(hip_common->ver_res & HIP_VER_MASK != HIP_VER_RES, -EPROTOTYPE,
		 "Invalid version in received packet. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a non-HIT in HIT-source. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hitr) && !ipv6_addr_any(&hip_common->hitr),
		 -EAFNOSUPPORT, "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
	HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a NULL in HIT-sender. Dropping\n");

        /*
         * XX FIXME: handle the RVS case better
         */
        if (ipv6_addr_any(&hip_common->hitr)) {
                /* Required for e.g. BOS */
                HIP_DEBUG("Received opportunistic HIT\n");
	} else {
#ifdef CONFIG_HIP_RVS
                HIP_DEBUG("Received HIT is ours or we are RVS\n");
#else
		HIP_IFEL(!hip_hadb_hit_is_our(&hip_common->hitr), -EFAULT,
			 "Receiver HIT is not ours\n");
#endif
	}

        HIP_IFEL(!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr), -ENOSYS,
		 "Dropping HIP packet. Loopback not supported.\n");

        /* Check checksum. */
	HIP_IFEL(checksum_packet((char*)hip_common, src, dst), -EBADMSG, 
		 "HIP checksum failed.\n");
	
out_err:
        return err;
}

/*
 * Checksumming is from Boeing's HIPD.
 */
#include "preinput.h"

#ifdef CONFIG_HIP_HI3
/*
 * function checksum_packet() 
 *
 * Calculates the checksum of a HIP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 */
u16 checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	u16 checksum;
	unsigned long sum = 0;
	int count, length;
	unsigned short *p; /* 16-bit */
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

static int hip_verify_network_header(struct hip_common *hip_common,
				     struct sockaddr *src, struct sockaddr *dst, int len)
{
	int err = 0;
        uint16_t csum;

        if (len != hip_get_msg_total_len(hip_common)) {
                HIP_ERROR("Invalid HIP packet length. Dropping\n");
                err = -EINVAL;
                goto out_err;
        }

        /* Currently no support for piggybacking */
        if (hip_common->payload_proto != IPPROTO_NONE) {
                HIP_ERROR("Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
                          hip_common->payload_proto);
                err = -EOPNOTSUPP;
                goto out_err;
        }

        if ((hip_common->ver_res & HIP_VER_MASK) != HIP_VER_RES) {
                HIP_ERROR("Invalid version in received packet. Dropping\n");
                err = -EPROTOTYPE;
                goto out_err;
        }
	if (!hip_is_hit(&hip_common->hits)) {
                HIP_ERROR("Received a non-HIT in HIT-source. Dropping\n");
                err = -EAFNOSUPPORT;
                goto out_err;
        }

        if (!hip_is_hit(&hip_common->hitr) &&
            !ipv6_addr_any(&hip_common->hitr)) {
                HIP_ERROR("Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
                err = -EAFNOSUPPORT;
                goto out_err;
        }
	
        if (ipv6_addr_any(&hip_common->hits)) {
                HIP_ERROR("Received a NULL in HIT-sender. Dropping\n");
                err = -EAFNOSUPPORT;
                goto out_err;
        }
        /*
         * XX FIXME: handle the RVS case better
         */
        if (ipv6_addr_any(&hip_common->hitr)) {
                /* Required for e.g. BOS */
                HIP_DEBUG("Received opportunistic HIT\n");
	}
#ifdef CONFIG_HIP_RVS
        else {
                HIP_DEBUG("Received HIT is ours or we are RVS\n");
	}
#else
	else if (!hip_hit_is_our(&hip_common->hitr)) {
		HIP_ERROR("Receiver HIT is not ours\n");
		err = -EFAULT;
		goto out_err;
	} else {
		_HIP_DEBUG("Receiver HIT is ours\n");
	}
#endif

        if (!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr)) {
		HIP_DEBUG("Dropping HIP packet. Loopback not supported.\n");
		err = -ENOSYS;
		goto out_err;
	}

        /* Check checksum. */
	if (checksum_packet((char*)hip_common, src, dst)) {
		HIP_ERROR("HIP checksum failed.\n");
		err = -EBADMSG;
	}
	
out_err:
        return err;
}
				     
static int addr_parse(char *buf, struct sockaddr_in6 *in6, int len, int *res) {
	struct hi3_ipv4_addr *h4 = (struct hi3_ipv4_addr *)buf;
	if (len < (h4->sin_family == AF_INET ? sizeof(struct hi3_ipv4_addr) : 
		   sizeof(struct hi3_ipv6_addr))) {
		HIP_ERROR("Received packet too small. Dropping\n");
		*res = 0;
		return 0;
	}

	if (h4->sin_family == AF_INET) {
		((struct sockaddr_in *)in6)->sin_addr = h4->sin_addr;
		((struct sockaddr_in *)in6)->sin_family = AF_INET;
		*res = AF_INET;
		return sizeof(struct hi3_ipv4_addr);

	} else if (h4->sin_family == AF_INET6) {
		in6->sin6_addr = ((struct hi3_ipv6_addr *)buf)->sin6_addr;
		in6->sin6_family = AF_INET6;
		*res = AF_INET6;
		return sizeof(struct hi3_ipv4_addr);
	} 

	HIP_ERROR("Illegal family. Dropping\n");
	return 0;
}

/**
 * This is the i3 callback to process received data.
 */
void hip_inbound(cl_trigger *t, void* data, void *fun_ctx) 
{
	cl_buf* clb = (cl_buf *)data;
	struct hip_common *hip_common;
	struct hip_work_order *hwo;
	struct sockaddr_in6 src, dst;
	struct hi3_ipv4_addr *h4;
	struct hi3_ipv6_addr *h6;
	int family, l;
	char *buf = clb->data;
	int len = clb->data_len;

	/* First check the hi3 address header */

	/* Source and destination address */
	l = addr_parse(buf, &src, len, &family);
	if (family == 0) goto out_err;
	len -= l;
	buf += l;

	l = addr_parse(buf, &dst, len, &family);
	if (family == 0) goto out_err;
	len -= l;
	buf += l;

	/* See if there is at least the HIP header in the packet */
        if (len < sizeof(struct hip_common)) {
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
	}
	
	hip_common = (struct hip_common*)buf;
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     hip_get_msg_total_len(hip_common));

        if (hip_verify_network_header(hip_common, 
				      (struct sockaddr *)&src, 
				      (struct sockaddr *)&dst,
				      len)) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
	}

	if (hip_check_network_msg(hip_common)) {
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("No memory, dropping packet\n");
		goto out_err;
	}

	hwo->destructor = hip_hwo_input_destructor;
	hwo->hdr.type = HIP_WO_TYPE_INCOMING;
	len = hip_get_msg_total_len(hip_common);
        hwo->msg = malloc(len);
	if (!hwo->msg) {
		HIP_ERROR("No memory, dropping packet\n");
		HIP_FREE(hwo);
		goto out_err;
	}
	
	memcpy(hwo->msg, hip_common, len);

	/* should we do some early state processing now?
	 * we could prevent further DoSsing by dropping
	 * illegal packets right now.
	 */
	
        /* We need to save the addresses because the actual input handlers
	   may need them later */
	memcpy(&hwo->hdr.src_addr, SA2IP(&src), SAIPLEN(&src));
	memcpy(&hwo->hdr.dst_addr, SA2IP(&dst), SAIPLEN(&dst));

        switch(hip_get_msg_type(hip_common)) {
	case HIP_I1:
		HIP_DEBUG("Received HIP I1 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_I1;
		break;
	case HIP_R1:
		HIP_DEBUG("Received HIP R1 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_R1;
		break;
	case HIP_I2:
		HIP_DEBUG("Received HIP I2 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_I2;
		break;
	case HIP_R2:
		HIP_DEBUG("Received HIP R2 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_R2;
		break;
	case HIP_UPDATE:
		HIP_DEBUG("Received HIP UPDATE packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_UPDATE;
		break;
	case HIP_NOTIFY:
		HIP_DEBUG("Received HIP NOTIFY packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_NOTIFY;
		break;
	case HIP_BOS:
		HIP_DEBUG("Received HIP BOS packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_BOS;
		break;
	default:
		HIP_ERROR("Received HIP packet of unknown/unimplemented type %d\n",
			  hip_common->type_hdr);
		HIP_FREE(hwo);
		return;
        }

        hip_insert_work_order_cpu(hwo, 0);

 out_err:
	cl_free_buf(clb);
}
#endif

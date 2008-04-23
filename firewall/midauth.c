/*
 * This code is GNU/GPL.
 *
 * According to draft-heer-hip-middle-auth-00 we SHOULD support IP-level 
 * fragmentation for IPv6 and MUST support IP-level fragmentation for IPv4.
 * Currently we do neither.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "ife.h"
#include "midauth.h"
#include "pisa.h"
#include <string.h>

static struct midauth_handlers handlers;

/**
 * Changes IPv4 header to match new length and updates the checksum.
 *
 * @param data a pointer to the IPv4 header
 * @param len new payload length
 */
static void update_ipv4_header (struct iphdr *ip, int len)
{
	unsigned short *w= (unsigned short *) ip;
	int hdrlen, checksum;

	ip->tot_len = htons(len);
	ip->check = 0;

	for (hdrlen = ip->ihl * 4, checksum = 0; hdrlen > 1; hdrlen -= 2)
		checksum += *w++;
	if (hdrlen == 1) {
		unsigned short padding = 0;
		*(unsigned char *)(&padding)=*(unsigned char *)w;
		checksum += padding;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	ip->check = ~checksum;
}

/**
 * Changes IPv6 header to match new length.
 *
 * @param ip a pointer to the IPv6 header
 * @param len new IPv6 packet length
 */
static void update_ipv6_header (struct ip6_hdr *ip, int len)
{
	ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
}

#define CHECKSUM_CARRY(x) \
(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/**
 * Changes UDP header for IPv4 to match new content and updates the checksum.
 *
 * @param ip a pointer to the IPv4 header, not the UDP header
 * @param len total length of the IPv4 packet
 */
static void update_udp_header(struct iphdr *ip, int len)
{
	unsigned long sum;
	u_int16_t *w = (u_int16_t *)((unsigned char*)ip + (ip->ihl * 4));
	u_int16_t protocol = ntohs(IPPROTO_UDP);
	int i;
	struct udphdr *udp = (struct udphdr *) w;

	len -= ip->ihl * 4;

	udp->check = 0;
	udp->len = htons(len);

	/* UDP header and data */
	sum = 0;
	while (len > 0) {
		sum += *w++;
		len -= 2;
	}
	if (len == 1) {
		unsigned short padding = 0;
		*(unsigned char *)(&padding)=*(unsigned char *)w;
		sum += padding;
	}

	/* add UDP pseudoheader */
	w = (u_int16_t *) &ip->saddr;
	for (i = 0; i < 4; w++, i++)
		sum += *w;
	sum += protocol;
	sum += udp->len;

	/* set the checksum */
	udp->check = (CHECKSUM_CARRY(sum));
}

/**
 * Calculate the new checksum for the HIP packet in IPv4. Note that UDP
 * encapsulated HIP packets don't have a checksum. Therefore don't call this
 * function for them.
 *
 * @param ip the modified IP packet
 */
static void update_hip_checksum_ipv4(struct iphdr *ip)
{
	struct sockaddr_in src, dst;
	struct hip_common *msg = (struct hip_common *)((char*)ip +
	                         (ip->ihl * 4));

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	src.sin_family = AF_INET;
	memcpy(&src.sin_addr, &ip->saddr, sizeof (u_int32_t));

	dst.sin_family = AF_INET;
	memcpy(&dst.sin_addr, &ip->daddr, sizeof (u_int32_t));

	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char*)msg,
	                                    (struct sockaddr *) &src,
	                                    (struct sockaddr *) &dst);
}

/**
 * Calculate the new checksum for the HIP packet in IPv6.
 *
 * @param ip the modified IP packet
 */
static void update_hip_checksum_ipv6(struct ip6_hdr *ip)
{
	struct sockaddr_in6 src, dst;
	struct hip_common *msg = (struct hip_common *)((char*)ip +
	                         sizeof(struct ip6_hdr));

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	src.sin6_family = AF_INET6;
	memcpy(&src.sin6_addr, &ip->ip6_src, sizeof (struct in6_addr));

	dst.sin6_family = AF_INET6;
	memcpy(&dst.sin6_addr, &ip->ip6_dst, sizeof (struct in6_addr));

	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char*)msg,
	                                    (struct sockaddr *) &src,
	                                    (struct sockaddr *) &dst);
}

/**
 * Take care of adapting all headers in front of the HIP payload to the new
 * content.
 *
 * @param p the modified midauth packet
 */
static void midauth_update_all_headers(struct midauth_packet *p)
{
	struct iphdr *ipv4 = NULL;
	struct ip6_hdr *ipv6 = NULL;

	/* Do not update the headers twice. It would break packet sizes */

	if (p->hdr_length_adapted)
		return;

	switch (p->ip_version) {
	case 4:
		ipv4 = (struct iphdr *) p->buffer;
		p->size += ipv4->ihl * 4;
		if (ipv4->protocol == IPPROTO_UDP) {
			p->size += sizeof(struct udphdr);
			update_udp_header(ipv4, p->size);
		} else {
			update_hip_checksum_ipv4(ipv4);
		}
		update_ipv4_header(ipv4, p->size);    
		break;
	case 6:
		ipv6 = (struct ip6_hdr *) p->buffer;
		p->size += sizeof(struct ip6_hdr);
		update_hip_checksum_ipv6(ipv6);
		update_ipv6_header(ipv6, p->size);
		break;
	default:
		HIP_ERROR("Unknown IP version. %i, expected 4 or 6.\n", 
		          p->ip_version);
		break;
	}

	p->hdr_length_adapted = 1;
}

int midauth_verify_solution_m(struct hip_common *hip,
                              struct hip_solution_m *s)
{
	int err = 0;
	struct hip_solution solution;

	solution.K = s->K;
	solution.reserved = s->reserved;
	solution.I = s->I;
	solution.J = s->J;

	HIP_IFEL(hip_solve_puzzle(&solution, hip, HIP_VERIFY_PUZZLE) == 0,
	         -1, "Solution is wrong\n");

out_err:
	return 0;
}

/**
 * Move the last HIP parameter to the correct position according to its
 * parameter type. Will probably break the packet if something is moved in
 * front of a signature.
 *
 * @param hip the HIP packet
 * @return 0 on success
 */
static int midauth_relocate_last_hip_parameter(struct hip_common *hip)
{
	int err = 0, len, total_len, offset;
	char buffer[HIP_MAX_PACKET], *ptr = (char *) hip;
	struct hip_tlv_common *i = NULL, *last = NULL;
	hip_tlv_type_t type;

	while((i = (struct hip_tlv_common *)hip_get_next_param(hip, i)))
		last = i;

	HIP_IFEL(last == NULL, -1, "Trying to relocate in an empty packet!\n");

	total_len = hip_get_msg_total_len(hip);
	len = hip_get_param_total_len(last);
	type = hip_get_param_type(last);

	HIP_IFEL(len > sizeof(buffer), -1,
	         "Last parameter's length exceeds HIP_MAX_PACKET\n");

	/* @todo check for signature parameter to avoid broken packets */

	memcpy(buffer, last, len);
	i = NULL;

	while ((i = (struct hip_tlv_common *)hip_get_next_param(hip, i))) {
		if (hip_get_param_type(i) > type) {
			offset = (char *)i - (char *)hip;

			memmove(ptr+offset+len, ptr+offset, total_len-offset-len);
			memcpy(ptr+offset, buffer, len);
			break;
		}
	}

out_err:
	return err;
}

static void midauth_copy_packet_data(struct midauth_packet *p)
{
	if (p->hip_copied)
		return;

	memcpy(p->buffer, p->original_message->payload,
	       p->original_message->data_len);
	p->hip_copied = 1;
	p->hip = (struct hip_common *)(((char*)p->buffer) + p->hdr_size);
}

int midauth_add_echo_request_m(struct midauth_packet *p, char *nonce)
{
	int err = 0;

	midauth_copy_packet_data(p);

	HIP_IFEL(hip_build_param_echo_m(p->hip, nonce, strlen(nonce), 1),
	         -1, "Failed to build echo_request_m parameter\n");
	HIP_IFEL(midauth_relocate_last_hip_parameter(p->hip), -1,
	         "Failed to relocate new echo_request_m parameter\n");

out_err:
	return err;
} 

int midauth_add_puzzle_m(struct midauth_packet *p, uint8_t val_K, uint8_t lifetime,
                         uint8_t *opaque, uint64_t random_i)
{
	int err = 0;

	midauth_copy_packet_data(p);

	HIP_IFEL(hip_build_param_puzzle_m(p->hip, val_K, lifetime, opaque, random_i),
	         -1, "Failed to build puzzle_m parameter\n");
	HIP_IFEL(midauth_relocate_last_hip_parameter(p->hip), -1,
	         "Failed to relocate new puzzle_m parameter\n");

out_err:
	return err;
}

/**
 * This is an example, how the functions can be employed to insert additional
 * parameters into a packet

static int filter_midauth_i2(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) +
	                         p->hdr_size);
	struct hip_solution_m *solution;
	char *nonce = "hello";

	solution = (struct hip_solution_m *)hip_get_param(hip, HIP_PARAM_SOLUTION_M);
	if (solution) {
		if (midauth_verify_solution_m(hip, solution) == 0)
			HIP_DEBUG("found correct hip_solution_m\n");
		else
			HIP_DEBUG("found wrong hip_solution_m\n");
	} else {
		HIP_DEBUG("found no hip_solution_m\n");
	}

	add_echo_request_m(hip, nonce);
	add_puzzle_m(hip, 1, 2, "i2i2i2", 0xAABBCCDDEEFFFFFFLL);

	p->size = hip_get_msg_total_len(hip);
	midauth_update_all_headers(p);

	return verdict;
}
*/

int midauth_handler_accept(struct midauth_packet *p)
{
	return NF_ACCEPT;
}

int midauth_handler_drop(struct midauth_packet *p)
{
	return NF_DROP;
}

/**
 * Distinguish the different UPDATE packets.
 *
 * @param p the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static midauth_handler filter_midauth_update(struct midauth_packet *p)
{
	if (hip_get_param(p->hip, HIP_PARAM_LOCATOR))
		return handlers.u1;
	if (hip_get_param(p->hip, HIP_PARAM_ECHO_REQUEST))
		return handlers.u2;
	if (hip_get_param(p->hip, HIP_PARAM_ECHO_RESPONSE))
		return handlers.u3;

	HIP_ERROR("Unknown UPDATE format, rejecting the request!\n");
	return midauth_handler_drop;
}

int filter_midauth(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	midauth_handler h = NULL;
	midauth_handler h_default = midauth_handler_accept;
	/* @todo change this default value to midauth_handler_drop to 
	 * disallow unknown message types */

	switch (p->hip->type_hdr) {
	case HIP_I1:
		h = handlers.i1;
		break;
	case HIP_R1:
		h = handlers.r1;
		break;
	case HIP_I2:
		h = handlers.i2;
		break;
	case HIP_R2:
		h = handlers.r2;
		break;
	case HIP_UPDATE:
		h = filter_midauth_update(p);
		break;
	default:
		HIP_DEBUG("filtering default message type\n");
		break;
	}

	if (!h) {
		h = h_default;
	}
	verdict = h(p);

	/* do not change packet when it is dropped */
	if (verdict != NF_ACCEPT) {
		p->size = 0;
		p->hip_copied = 0;
	}

	/* if packet was modified correct every necessary part */
	if (p->hip_copied) {
		p->size = hip_get_msg_total_len(p->hip);
		midauth_update_all_headers(p);
	}

	return verdict;
}

void midauth_init(void)
{
	pisa_init(&handlers);
}

#endif


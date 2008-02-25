/*
 * This code is GNU/GPL.
 *
 * According to draft-heer-hip-middle-auth-00 we SHOULD support IP-level 
 * fragmentation for IPv6 and MUST support IP-level fragmentation for IPv4.
 * Currently we do neither.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "midauth.h"
#include <string.h>

/**
 * Changes IPv4 header to match new length and updates the checksum.
 *
 * @param data a pointer to the IPv4 header
 * @param len new payload length
 */
static void update_ipv4_header (struct iphdr *ip, int len) {
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

#define CHECKSUM_CARRY(x) \
(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/**
 * Changes UDP header for IPv4 to match new content and updates the checksum.
 *
 * @param ip a pointer to the IPv4 header, not the UDP header
 * @param len total length of the IPv4 packet
 */
static void update_udp_header(struct iphdr *ip, int len) {
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
    if (len == 1) /* FIXME - TODO */
	HIP_ERROR("UDP Packet size is odd. Checksum will not be correct!\n");

    /* add UDP pseudoheader */
    w = (u_int16_t *) &ip->saddr;
    for (i = 0; i < 4; w++, i++) {
	sum += *w;
    }
    sum += protocol;
    sum += udp->len;

    /* set the checksum */
    udp->check = (CHECKSUM_CARRY(sum));
}

/**
 * Take care of adapting all headers in front of the HIP payload to the new
 * content. Call only once per packet, as it modifies the packet size to
 * include header length.
 *
 * @param p the modified midauth packet
 */
static void update_all_headers(struct midauth_packet *p) {
    struct iphdr *ipv4 = NULL;

    switch (p->ip_version) {
	case 4:
	    ipv4 = (struct iphdr *) p->buffer;
	    p->size += ipv4->ihl * 4;
	    if (ipv4->protocol == IPPROTO_UDP) {
		p->size += sizeof(struct udphdr);
		update_udp_header(ipv4, p->size);
	    }
	    update_ipv4_header(ipv4, p->size);    
	    break;
	case 6:
	    p->size += sizeof(struct ip6_hdr);
	    HIP_ERROR("Trying to modify the IPv6 packet. Not implemented yet!");
	    break;
	default:
	    HIP_ERROR("Unknown IP version. %i, expected 4 or 6.", p->ip_version);
	    break;
    }
}

/**
 * Check the correctness of a hip_solution_m
 *
 * @param hip the hip_common that contains the solution
 * @param s the solution to be checked
 * @return 0 if correct, nonzero otherwise
 */
static int midauth_verify_solution_m(struct hip_common *hip, struct hip_solution_m *s) {
    struct hip_solution solution;

    solution.K = s->K;
    solution.reserved = s->reserved;
    solution.I = s->I;
    solution.J = s->J;

    if (hip_solve_puzzle(&solution, hip, HIP_VERIFY_PUZZLE) == 0)
	return 1;

    return 0;
}

/**
 * Insert the nonce into the R1 packet.
 *
 * @param m the original packet
 * @param p the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static int filter_midauth_r1(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;
    struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) + p->hdr_size);
    char *nonce1 = "abcedfgh";
    char *nonce2 = "foobar";

    /* start with a copy of the original packet */

    memcpy(p->buffer, m->payload, m->data_len);

    /* beware: black magic & dragons ahead */

    hip_build_param_echo_m(hip, nonce1, strlen(nonce1), 1);
    hip_build_param_echo_m(hip, nonce2, strlen(nonce2), 1);
    hip_build_param_puzzle_m(hip, 1, 2, "hello!", 0xFF00FF00FF00FF00LL);
    hip_build_param_puzzle_m(hip, 3, 4, "byebye", 0xDEADBEEFDEADBEEFLL);

    /* no more dragons & black magic*/

    p->size = hip_get_msg_total_len(hip);
    update_all_headers(p);

    return verdict;
}

/**
 * Insert the nonce into the I2 packet, check the nonce from the R1 packet.
 *
 * @param m the original packet
 * @param p the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static int filter_midauth_i2(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;
    struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) + p->hdr_size);
    struct hip_solution_m *solution;
    char *nonce1 = "hello";
    char *nonce2 = "world";

    /* just copy it for testing */

    memcpy(p->buffer, m->payload, m->data_len);

    solution = (struct hip_solution_m *)hip_get_param(hip, HIP_PARAM_SOLUTION_M);
    if (solution)
    {
	if (midauth_verify_solution_m(hip, solution) == 0)
	    HIP_DEBUG("found correct hip_solution_m\n");
	else
	    HIP_DEBUG("found wrong hip_solution_m\n");
    } else
	HIP_DEBUG("found no hip_solution_m\n");

    hip_build_param_echo_m(hip, nonce1, strlen(nonce1), 1);
    hip_build_param_echo_m(hip, nonce2, strlen(nonce2), 1);
    hip_build_param_puzzle_m(hip, 1, 2, "i2i2i2", 0xAABBCCDDEEFFFFFFLL);
    hip_build_param_puzzle_m(hip, 3, 4, "I2I2I2", 0xABCDABCDABCDABCDLL);

    p->size = hip_get_msg_total_len(hip);
    update_all_headers(p);

    return verdict;
}

/**
 * Check the nonce from the R2 packet.
 *
 * @param m the original packet
 * @param p the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static int filter_midauth_r2(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;
    struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) + p->hdr_size);
    struct hip_solution_m *solution;

    /* don't copy here, packet will not be modified anyway */
    memcpy(p->buffer, m->payload, m->data_len);

    /* check for ECHO_REPLY_M and SOLUTION_M here */
    solution = (struct hip_solution_m *)hip_get_param(hip, HIP_PARAM_SOLUTION_M);
    if (solution)
    {
	if (midauth_verify_solution_m(hip, solution) == 0)
	    HIP_DEBUG("found correct hip_solution_m\n");
	else
	    HIP_DEBUG("found wrong hip_solution_m\n");
    } else
	HIP_DEBUG("found no hip_solution_m\n");


    return verdict;
}

int filter_midauth(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;

    p->size = 0; /* default: do not change packet */

    switch (p->hip_common->type_hdr) {
	case HIP_I1:
	    break;
	case HIP_R1:
	    verdict = filter_midauth_r1(m, p);
	    break;
	case HIP_I2:
	    verdict = filter_midauth_i2(m, p);
	    break;
	case HIP_R2:
	    verdict = filter_midauth_r2(m, p);
	    break;
	default:
	    HIP_DEBUG("filtering default message type\n");
	    break;
    }

    /* do not change packet when it is dropped */
    if (verdict != NF_ACCEPT)
	p->size = 0;

    return verdict;
}

#endif


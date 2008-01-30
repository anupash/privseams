/*
 * This code is GNU/GPL.
 */

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
 * Insert the nonce into the R1 packet.
 *
 * @param m the original packet
 * @param p the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static int filter_midauth_r1(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;
    struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) + p->hdr_size);
    char *nonce = "abcedfgh";
    struct hip_puzzle_m puzzle;

    /* start with a copy of the original packet */

    memcpy(p->buffer, m->payload, m->data_len);

    HIP_DEBUG("***************************old*******************************\n");
    HIP_DUMP_MSG(hip);

    /* beware: black magic & dragons ahead */

    memset(&puzzle, 'X', sizeof(puzzle));
    puzzle.opaque[0]='H';
    puzzle.opaque[1]='E';
    puzzle.opaque[2]='L';
    puzzle.opaque[3]='L';
    puzzle.opaque[4]='O';
    puzzle.opaque[5]='!';
    hip_set_param_type(&puzzle, HIP_PARAM_PUZZLE_M);
    hip_set_param_contents_len(&puzzle, sizeof(puzzle) - sizeof(struct hip_tlv_common));

    hip_build_param_contents(hip, nonce, HIP_PARAM_ECHO_REQUEST_M, strlen(nonce));
    hip_build_param(hip, &puzzle);
    p->size = hip_get_msg_total_len(hip);

    /* no more dragons & black magic*/

    HIP_DEBUG("***************************new*******************************\n");
    HIP_DUMP_MSG(hip);

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

    /* just copy it for testing */

    memcpy(p->buffer, m->payload, m->data_len);

    HIP_DEBUG("***************************old*******************************\n");
    HIP_DUMP_MSG(hip);

    p->size = hip_get_msg_total_len(hip);
    HIP_DEBUG("***************************new*************************%i******\n", p->size);
    HIP_DUMP_MSG(hip);

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

    /* FIXME potential buffer overflow, using fixed size buffer in
     * midauth_packet */

    /* just copy it for testing */
    memcpy(p->buffer, m->payload, m->data_len);

    HIP_DEBUG("***************************old*******************************\n");
    HIP_DUMP_MSG(hip);
    p->size = hip_get_msg_total_len(hip);
    HIP_DEBUG("***************************new*******************************\n");
    HIP_DUMP_MSG(hip);

    update_all_headers(p);
    p->size=0;

    return verdict;
}

int filter_midauth(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;

    p->size = 0; /* default: do not change packet */

    switch (p->hip_common->type_hdr) {
	case HIP_I1:
	    HIP_DEBUG("filtering I1\n");
	    break;
	case HIP_R1:
	    HIP_DEBUG("filtering R1\n");
	    verdict = filter_midauth_r1(m, p);
	    break;
	case HIP_I2:
	    HIP_DEBUG("filtering I2\n");
	    verdict = filter_midauth_i2(m, p);
	    break;
	case HIP_R2:
	    HIP_DEBUG("filtering R2\n");
	    verdict = filter_midauth_r2(m, p);
	    break;
	default:
	    HIP_DEBUG("filtering default message type\n");
	    break;
    }

    /* do not change packet when it is dropped */
    if (verdict != NF_ACCEPT)
	p->size = 0;

    if (p->size == 0)
	HIP_DEBUG("*******************NOT CHANGING PACKET\n");
    else
	HIP_DEBUG("*******************CHANGING PACKET\n");

    return verdict;
}

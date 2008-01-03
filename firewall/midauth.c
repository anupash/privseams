/*
 * This code is GNU/GPL.
 */

#include "midauth.h"

/**
 * Changes IPv4 header to match new length and updates the checksum.
 *
 * @param data a pointer to the IPv4 header
 * @param len new payload length
 */
static void update_ipv4_header (void *data, int len) {
    unsigned short *w= (unsigned short *) data;
    struct iphdr *ip = (struct iphdr*) data;
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

int filter_midauth(ipq_packet_msg_t *m, struct midauth_packet *p) {
    int verdict = NF_ACCEPT;

    p->size = 0; /* do not change packet */

    switch (p->hip_common->type_hdr) {
	case HIP_I1:
	    HIP_DEBUG("filtering I1\n");
	    break;
	case HIP_R1:
	    HIP_DEBUG("filtering R1\n");
	    break;
	case HIP_I2:
	    HIP_DEBUG("filtering I2\n");
	    break;
	case HIP_R2:
	    HIP_DEBUG("filtering R2\n");
	    break;
	default:
	    HIP_DEBUG("filtering default message type\n");
	    break;
    }

    return verdict;
}

#ifndef HIP_MIDAUTH_H
#define HIP_MIDAUTH_H

#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include "protodefs.h"
#include "debug.h"

#define MIDAUTH_PACKET_SIZE 10240

struct midauth_packet {
    int size;
    int ip_version;
    int hdr_size;
    unsigned char buffer[MIDAUTH_PACKET_SIZE]; /* space for a modified packet */
    struct hip_common *hip_common; /* in the old packet, don't write there */
};

/* public functions for midauth */

/**
 * Filters accepted packets for middlebox authentication.
 *
 * @param m pointer to the packet that will be filtered
 * @param 
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
int filter_midauth(ipq_packet_msg_t *m, struct midauth_packet *p);

#endif


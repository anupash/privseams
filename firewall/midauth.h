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
	int hdr_length_adapted;
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

/**
 * Take care of adapting all headers in front of the HIP payload to the new
 * content. Call only once per packet, as it modifies the packet size to
 * include header length.
 *
 * @param p the modified midauth packet
 */
void midauth_update_all_headers(struct midauth_packet *p);

/**
 * Check the correctness of a hip_solution_m
 *
 * @param hip the hip_common that contains the solution
 * @param s the solution to be checked
 * @return 0 if correct, nonzero otherwise
 */
int midauth_verify_solution_m(struct hip_common *hip,
                              struct hip_solution_m *s);

/**
 * Insert an ECHO_REQUEST_M parameter into a HIP packet.
 *
 * @param p the modified packet
 * @param nonce the string to add
 * @return 
 */
int midauth_add_echo_request_m(struct hip_common *hip, char *nonce);

/**
 * Insert a PUZZLE_M parameter into a HIP packet.
 *
 * @param p the modified packet
 * @param val_K puzzle parameter val_K
 * @param lifetime puzzle parameter lifetime
 * @param opaque puzzle parameter opaque
 * @param random_i puzzle parameter random_i
 * @return 
 */
int midauth_add_puzzle_m(struct hip_common *hip, uint8_t val_K, uint8_t lifetime,
                         uint8_t *opaque, uint64_t random_i);

#endif


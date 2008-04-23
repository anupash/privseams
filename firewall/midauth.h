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
	struct hip_common *hip; /* refers to old and new packet */
	int hip_copied; /* 0 if unmodified, 1 if modified */
	ipq_packet_msg_t *original_message;
};

typedef int (*midauth_handler)(struct midauth_packet *p);

struct midauth_handlers {
	midauth_handler i1;
	midauth_handler r1;
	midauth_handler i2;
	midauth_handler r2;
	midauth_handler u1;
	midauth_handler u2;
	midauth_handler u3;
};

/* public functions for midauth */

/**
 * Filters accepted packets for middlebox authentication.
 *
 * @param p the packet ready for modification
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
int filter_midauth(struct midauth_packet *p);

/**
 * Accepts a packet. Used in midauth_handlers as a default handler.
 *
 * @param p the packet
 * @return NF_ACCEPT
 */
int midauth_handler_accept(struct midauth_packet *p);

/**
 * Drops a packet. Used in midauth_handlers as a default handler.
 *
 * @param p the packet
 * @return NF_DROP
 */
int midauth_handler_drop(struct midauth_packet *p);

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
 * @param p the packet to be modified
 * @param nonce data to add
 * @param len length of data to add
 * @return 
 */
int midauth_add_echo_request_m(struct midauth_packet *p, void *nonce, int len);

/**
 * Insert a PUZZLE_M parameter into a HIP packet.
 *
 * @param p the packet to be modified
 * @param val_K puzzle parameter val_K
 * @param lifetime puzzle parameter lifetime
 * @param opaque puzzle parameter opaque
 * @param random_i puzzle parameter random_i
 * @return 
 */
int midauth_add_puzzle_m(struct midauth_packet *p, uint8_t val_K, uint8_t lifetime,
                         uint8_t *opaque, uint64_t random_i);

/**
 * Initialize midauth infrastructure.
 */
void midauth_init(void);

#endif


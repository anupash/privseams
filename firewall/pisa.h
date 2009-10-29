/** @file
 * A header file for pisa.c.
 *
 * @author Thomas Jansen
 */
#ifndef HIP_PISA_H
#define HIP_PISA_H

#include "midauth.h"

#define PISA_STATE_DISALLOW	0
#define PISA_STATE_ALLOW	1

/**
 * Register PISA handlers with midauth and initialize data structures.
 *
 * @param h pointer to the handlers
 */
void pisa_init(struct midauth_handlers *h);

#ifdef HIPL_CERTIFICATE_CHANGES
struct pisa_trust_point * get_trust_point_by_hit(const struct in6_addr * hit);
void pisa_remove_trust_point(struct pisa_trust_point * trust_point);
void pisa_free_trust_point(struct pisa_trust_point * trust_point);

typedef struct pisa_trust_point{
	struct in6_addr hit;
	int maximum_parallel_connections;
	int current_connections;
}pisa_trust_point;
#endif /* HIPL_CERTIFICATE_CHANGES */


/**
 * Check if a new random number is necessary.
 */
void pisa_check_for_random_update();

#endif

/** @file
 * A header file for pisa_cert.c.
 *
 * @author Thomas Jansen
 */
#ifndef HIP_PISA_CERT_H
#define HIP_PISA_CERT_H

#include <time.h>
#include <arpa/inet.h>

struct pisa_cert {
	struct in6_addr hit_issuer;
	struct in6_addr hit_subject;
	time_t not_before;
	time_t not_after;
#ifdef HIPL_CERTIFICATE_CHANGES
	int parallel_users;
#endif /* HIPL_CERTIFICATE_CHANGES */
};

/**
 * Split the hip_cert_spki_info.cert part into small chunks
 *
 * @param cert the hip_cert_spki_info.cert part of the certificate
 * @param pc datastructure that will contain the chunks
 */
void pisa_split_cert(char *cert, struct pisa_cert *pc);

#endif

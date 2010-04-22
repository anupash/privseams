/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief The header file for firewall/pisa_cert.c
 * *
 * @author Thomas Jansen
 */

#ifndef HIP_FIREWALL_PISA_CERT_H
#define HIP_FIREWALL_PISA_CERT_H

#include <time.h>
#include <arpa/inet.h>

struct pisa_cert {
    struct in6_addr hit_issuer;
    struct in6_addr hit_subject;
    time_t          not_before;
    time_t          not_after;
};

/**
 * Split the hip_cert_spki_info.cert part into small chunks
 *
 * @param cert the hip_cert_spki_info.cert part of the certificate
 * @param pc datastructure that will contain the chunks
 */
void pisa_split_cert(char *cert, struct pisa_cert *pc);

#endif /* HIP_FIREWALL_PISA_CERT_H */

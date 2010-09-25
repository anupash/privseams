/**
 * @file
 *
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * @brief The header file for firewall/pisa_cert.c
 *
 * @author Thomas Jansen
 */

#ifndef HIP_FIREWALL_PISA_CERT_H
#define HIP_FIREWALL_PISA_CERT_H

#include <time.h>
#include <netinet/in.h>

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
 * @param pc   datastructure that will contain the chunks
 */
void pisa_split_cert(char *cert, struct pisa_cert *pc);

#endif /* HIP_FIREWALL_PISA_CERT_H */

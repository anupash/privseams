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
 */

/** @file
 * A header file for certtools.c
 *
 * Certificate building, parseing and verification functions.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

#ifndef HIP_LIB_CORE_CERTTOOLS_H
#define HIP_LIB_CORE_CERTTOOLS_H

#include <stdint.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/types.h>

#include "hashtable.h"
#include "protodefs.h"


/** Defines */
#define HIP_CERT_CONF_PATH HIPL_SYSCONFDIR "hip_cert.cnf"

/* Needed if the configuration file for certs did not exist  */
#define HIP_CERT_INIT_DAYS 10

#define HIP_CERT_DAY 86400

/** Struct used to deliver the minimal needed information to build SPKI cert */
struct hip_cert_spki_info {
    hip_tlv_type_t  type;
    hip_tlv_len_t   length;
    char            public_key[768];
    char            cert[224];
    char            signature[768];
    struct in6_addr issuer_hit;
    /* 0 if succesfully verified otherwise negative */
    uint32_t        success;
};

/** SPKI cert related functions */
int hip_cert_spki_lib_verify(struct hip_cert_spki_info *);
int hip_cert_spki_create_cert(struct hip_cert_spki_info *,
                              const char *, struct in6_addr *,
                              const char *, struct in6_addr *,
                              time_t *, time_t *);
int hip_cert_spki_construct_keys(HIP_HASHTABLE *, hip_hit_t *, RSA *);
int hip_cert_spki_char2certinfo(char *, struct hip_cert_spki_info *);
int hip_cert_spki_send_to_verification(struct hip_cert_spki_info *);

/* x509v3 cert related functions */
int hip_cert_x509v3_request_certificate(struct in6_addr *, unsigned char *);
int hip_cert_x509v3_request_verification(unsigned char *, int);

/** Utilitary functions */
STACK_OF(CONF_VALUE) * hip_cert_read_conf_section(const char *, CONF *);
CONF *hip_cert_open_conf(void);
void hip_cert_free_conf(CONF *);
int hip_cert_regex(char *, char *, int *, int *);

#endif /* HIP_LIB_CORE_CERTTOOLS_H */

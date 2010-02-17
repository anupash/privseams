#ifndef HIP_CERTTOOLS_H
#define HIP_CERTTOOLS_H

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
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "debug.h"
#include "ife.h"
#include "misc.h"
#include "hashtable.h"

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
                              char *, struct in6_addr *,
                              char *, struct in6_addr *,
                              time_t *, time_t *);
int hip_cert_spki_build_cert(struct hip_cert_spki_info *);
int hip_cert_spki_inject(struct hip_cert_spki_info *, char *, char *);
int hip_cert_spki_construct_keys(HIP_HASHTABLE *, hip_hit_t *, RSA *);
int hip_cert_spki_char2certinfo(char *, struct hip_cert_spki_info *);
int hip_cert_spki_send_to_verification(struct hip_cert_spki_info *);

/** x509v3 cert related functions */
int hip_cert_x509v3_request_certificate(struct in6_addr *, unsigned char *);
int hip_cert_x509v3_request_verification(unsigned char *, int);

/** Utilitary functions */
X509 *hip_cert_der_to_x509(const unsigned char *, int);
X509 *hip_cert_pem_to_x509(char *);
STACK_OF(CONF_VALUE) * hip_cert_read_conf_section(char *, CONF *);
CONF *hip_cert_open_conf(void);
void hip_cert_free_conf(CONF *);
int hip_cert_regex(char *, char *, int *, int *);

#endif /* HIP_CERTTOOLS_H */

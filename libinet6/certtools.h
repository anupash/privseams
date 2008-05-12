#ifndef HIP_CERTTOOLS_H
#define HIP_CERTTOOLS_H

/** @file
 * A header file for certtools.c
 *
 * Certificate building, parseing and verification functions.
 * Syntax as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *  VV is what the function really does like sign etc.
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
#include "debug.h"
#include "ife.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"

/** Struct used to deliver the minimal needed information to build SPKI cert*/
struct hip_cert_spki_info {
        char public_key[256];
	char cert[512];
        char signature[256];
        struct in6_addr issuer_hit;
};

/************************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                      *
 ***********************************************************************************/
int hip_cert_spki_create_cert(struct hip_cert_spki_info *,
                              char *, struct in6_addr *,
                              char *, struct in6_addr *,
                              time_t *, time_t *);

int hip_cert_spki_build_cert(struct hip_cert_spki_info *);
int hip_cert_spki_build_signature(char *, char *);
int hip_cert_spki_inject(struct hip_cert_spki_info *, char *, char *);
int hip_cert_spki_construct_keys(HIP_HASHTABLE *, hip_hit_t *, RSA *);

/************************************************************************************
 * VERIFICATION FUNCTIONS FOR SPKI                                                  *
 ***********************************************************************************/

int hip_cert_spki_verify_signature(char *);

#endif /* HIP_CERTTOOLS_H */

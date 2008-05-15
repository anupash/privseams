#ifndef HIP_CERT_H
#define HIP_CERT_H

/** @file
 * A header file for cert.c
 *
 * Certificate signing and verification functions.
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
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include "debug.h"
#include "ife.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"

int hip_cert_spki_construct_keys(HIP_HASHTABLE *, hip_hit_t *, RSA *);
int hip_cert_spki_sign(struct hip_common *, HIP_HASHTABLE *);

#endif /* HIP_CERT_H */

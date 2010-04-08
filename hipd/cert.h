/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_HIPD_CERT_H
#define HIP_HIPD_CERT_H

/** @file
 * A header file for cert.c
 *
 * Certificate signing and verification functions.
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
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"

#include "hidb.h"
#include "lib/core/hashtable.h"

/** SPKI */
int hip_cert_spki_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_spki_verify(struct hip_common *);

/** x509v3 */
int hip_cert_x509v3_handle_request_to_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_x509v3_handle_request_to_verify(struct hip_common *);

/** utilitary functions */
int hip_cert_hostid2rsa(struct hip_host_id_priv *, RSA *);
int hip_cert_hostid2dsa(struct hip_host_id_priv *, DSA *);

/** ugly hack for supressing warnings in broken environments */
#define BROKEN_SSL_CONST const

#endif /* HIP_HIPD_CERT_H */

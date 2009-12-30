#ifndef HIP_CERT_H
#define HIP_CERT_H

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

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "libhipcore/debug.h"
#include "libhipcore/ife.h"
#include "libhipcore/misc.h"
#include "hidb.h"
#include "libhipcore/hashtable.h"

/** SPKI **/
int hip_cert_spki_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_spki_verify(struct hip_common *);

/** x509v3 **/
int hip_cert_x509v3_handle_request_to_sign(struct hip_common *, HIP_HASHTABLE *);
int hip_cert_x509v3_handle_request_to_verify(struct hip_common *);

/** utilitary functions **/
int hip_cert_hostid2rsa(struct hip_host_id *, RSA *);
int hip_cert_hostid2dsa(struct hip_host_id *, DSA *);

/** ugly hack for supressing warnings in broken environments */
#define BROKEN_SSL_CONST const

#ifdef CONFIG_HIP_MAEMO
/* Fix the maemo environment's broken macros */

#undef BROKEN_SSL_CONST
#define BROKEN_SSL_CONST 

#undef SKM_sk_value
#define SKM_sk_value(type, st,i) \
        ((type *)(void*)sk_value(st, i))

#undef sk_CONF_VALUE_value
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))
#endif

#endif /* HIP_CERT_H */

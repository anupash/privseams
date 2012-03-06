/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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

#ifndef HIP_LIB_CORE_HOSTID_H
#define HIP_LIB_CORE_HOSTID_H

#include <netinet/in.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "protodefs.h"
#include "state.h"

struct hip_ecdsa_keylen {
    int private;
    int public;
};

struct hip_rsa_keylen {
    int e_len;
    int e;
    int n;
};

struct hip_hit_info {
    struct hip_host_id_local lhi;
    hip_lsi_t                lsi;
};


int hip_host_id_to_hit(const struct hip_host_id *const host_id,
                       struct in6_addr *const hit, const int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id_priv *const host_id,
                               struct in6_addr *const hit, const int hit_type);
void hip_get_rsa_keylen(const struct hip_host_id_priv *const host_id,
                        struct hip_rsa_keylen *ret,
                        const int is_priv);
int hip_get_ecdsa_keylen(const struct hip_host_id_priv *const host_id,
                         struct hip_ecdsa_keylen *const ret);
RSA *hip_key_rr_to_rsa(const struct hip_host_id_priv *const host_id, const int is_priv);
DSA *hip_key_rr_to_dsa(const struct hip_host_id_priv *const host_id, const int is_priv);
EC_KEY *hip_key_rr_to_ecdsa(const struct hip_host_id_priv *const host_id, const int is_priv);

int dsa_to_dns_key_rr(const DSA *const dsa, unsigned char **const buf);
int rsa_to_dns_key_rr(const RSA *const rsa, unsigned char **const rsa_key_rr);
int ecdsa_to_key_rr(const EC_KEY *const ecdsa, unsigned char **const ec_key_rr);

EVP_PKEY *hip_key_rr_to_evp_key(const void *const host_id, const int is_priv);

int hip_serialize_host_id_action(struct hip_common *msg,
                                 const int action,
                                 const int anon,
                                 const int use_default,
                                 const int hi_fmt,
                                 const char *hi_file,
                                 const int rsa_key_bits,
                                 const int dsa_key_bits,
                                 const int ecdsa_nid);

#endif /* HIP_LIB_CORE_HOSTID_H */

/*
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

#ifndef HIP_LIB_CORE_HOSTID_H
#define HIP_LIB_CORE_HOSTID_H

#include <netinet/in.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>

#include "protodefs.h"
#include "state.h"

struct hip_ecdsa_keylen {
    int z_len;  // private key length
    int Y_len;  // public key length
};

struct hip_rsa_keylen {
    int e_len;
    int e;
    int n;
};

struct hip_hit_info {
    struct hip_lhi lhi;
    hip_lsi_t      lsi;
};

int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
                           struct in6_addr *hit, int hit_type);

/* Useless abstraction, goes to the same function anyway -- SAMU
 *
 * True that. Let's make this a static inline function and move it to the header
 * file. It still remains as useless abstraction, but at least we eliminate the
 * need for a call and return sequence. -Lauri 06.08.2008
 */
static inline int hip_rsa_host_id_to_hit(const struct hip_host_id *host_id,
                                         struct in6_addr *hit, int hit_type)
{
    return hip_dsa_host_id_to_hit(host_id, hit, hit_type);
}

static inline int hip_ecdsa_host_id_to_hit(const struct hip_host_id *host_id,
                                           struct in6_addr *hit, int hit_type)
{
    return hip_dsa_host_id_to_hit(host_id, hit, hit_type);
}

int hip_host_id_to_hit(const struct hip_host_id *host_id,
                       struct in6_addr *hit, int hit_type);
int hip_private_dsa_host_id_to_hit(const struct hip_host_id_priv *host_id,
                                   struct in6_addr *hit,
                                   int hit_type);
int hip_private_rsa_host_id_to_hit(const struct hip_host_id_priv *host_id,
                                   struct in6_addr *hit,
                                   int hit_type);
int hip_private_ecdsa_host_id_to_hit(const struct hip_host_id_priv *host_id,
                                     struct in6_addr *hit,
                                     int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id_priv *host_id,
                               struct in6_addr *hit, int hit_type);
void hip_get_rsa_keylen(const struct hip_host_id_priv *host_id,
                        struct hip_rsa_keylen *ret,
                        int is_priv);
int hip_get_ecdsa_keylen(const struct hip_host_id_priv *host_id,
                         struct hip_ecdsa_keylen *ret);
RSA *hip_key_rr_to_rsa(const struct hip_host_id_priv *host_id, int is_priv);
DSA *hip_key_rr_to_dsa(const struct hip_host_id_priv *host_id, int is_priv);
EC_KEY *hip_key_rr_to_ecdsa(const struct hip_host_id_priv *host_id, int is_priv);

int dsa_to_dns_key_rr(DSA *dsa, unsigned char **buf);
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr);
int ecdsa_to_key_rr(EC_KEY *ecdsa, unsigned char **ec_key_rr);

int hip_serialize_host_id_action(struct hip_common *msg,
                                 int action,
                                 int anon,
                                 int use_default,
                                 const char *hi_fmt,
                                 const char *hi_file,
                                 int rsa_key_bits,
                                 int dsa_key_bits,
                                 int ecdsa_nid);

#endif /* HIP_LIB_CORE_HOSTID_H */

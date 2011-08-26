/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_MANAGEMENT_H
#define HIP_HIPD_SIGNALING_USER_MANAGEMENT_H

#include <sys/types.h>

#include "lib/core/linkedlist.h"
#include "signaling_prot_common.h"

#define CERTIFICATE_INDEX_HASH_LENGTH   8
#define CERTIFICATE_INDEX_SUFFIX_LENGTH 4

#define CERTIFICATE_INDEX_USER_DIR      HIPL_SYSCONFDIR "/user_certchains/"
#define CERTIFICATE_INDEX_TRUSTED_DIR   HIPL_SYSCONFDIR "/trusted_certs/"
#define CERTIFICATE_INDEX_CERT_SUFFIX   ".0"

enum userdb_flags {
    USER_IS_AUTHED = 1
};

/* Data structures for the user database. */
struct userdb_certificate_context {
    struct in6_addr src_hit;  //  We need one certificate context,
    struct in6_addr dst_hit;  //  per host associtaion and
    uint32_t network_id;     //  network.
    int group;
    int count;
    int next_cert_id;
    STACK_OF(X509) *cert_chain;
};

struct userdb_user_entry {
    long int uid;          // this is only well-defined if this is a local user
    X509_NAME *uname;
    uint8_t flags;
    EVP_PKEY *pub_key;
    hip_ll_t *cert_contexts;
};

/* Init and uninit functions. */
int signaling_user_mgmt_init(void);
int signaling_user_mgmt_uninit(void);

/* Printers */
void userdb_print(void);
int userdb_entry_print(struct userdb_user_entry *e);

/* Get from user database */
struct userdb_user_entry *userdb_get_user(X509_NAME *uname);
struct userdb_certificate_context *userdb_get_certificate_context(struct userdb_user_entry *const user,
                                                                  const struct in6_addr *const src_hit,
                                                                  const struct in6_addr *const dst_hit,
                                                                  const uint32_t network_id);
struct userdb_certificate_context *userdb_get_certificate_context_by_key(const struct userdb_user_entry *const user,
                                                                         const EVP_PKEY *pubkey);
/* Add to user database */
struct userdb_user_entry *userdb_add_user(const struct signaling_user_context *user, int replace);
struct userdb_user_entry *userdb_add_user_from_msg(const struct hip_common *const msg, int replace);
struct userdb_certificate_context *userdb_add_certificate_context(struct userdb_user_entry *const user,
                                                                  const struct in6_addr *const src_hit,
                                                                  const struct in6_addr *const dst_hit,
                                                                  const uint32_t network_id,
                                                                  const struct hip_cert *const first_cert);
int userdb_add_certifiate(struct userdb_certificate_context *cert_ctx,
                          const struct hip_cert *param_cert);
int userdb_add_certificates_from_msg(const struct hip_common *const msg,
                                     struct userdb_user_entry *user);
int userdb_add_key_from_rr(struct userdb_user_entry *user,
                   const struct hip_host_id_key_rdata *const key_rr_header,
                   const unsigned int key_rr_len,
                   const unsigned char *key_rr);

/* Interface to certificate index directory */
int userdb_save_user_certificate_chain(STACK_OF(X509) *cert_chain);

/* Util functions */
int userdb_user_is_authed(const struct userdb_user_entry *const user);
void userdb_apply_func(int(*func)(struct userdb_user_entry *));
int userdb_handle_user_signature(struct hip_common *const msg,
                                    struct signaling_connection *const conn,
                                    enum direction dir);
int userdb_verify_public_key(X509_NAME *subject, const EVP_PKEY *const pub_key);

/* Verify a user signature */
int signaling_verify_user_signature(struct hip_common *msg, EVP_PKEY *pkey);


#endif /* HIP_HIPD_SIGNALING_USER_MANAGEMENT_H */

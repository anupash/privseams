/*
 * signaling_user_api.c
 *
 *  Created on: Nov 26, 2010
 *      Author: ziegeldorf
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/hostid.h"
#include "lib/core/prefix.h"
#include "lib/core/hashtable.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_common_builder.h"
#include "signaling_user_management.h"
#include "signaling_user_api.h"
#include "signaling_x509_api.h"

HIP_HASHTABLE *user_db = NULL;

static unsigned long userdb_user_entry_hash(const struct userdb_user_entry *e)
{
    return X509_NAME_hash(e->uname);
}

static int userdb_user_entries_cmp(const struct userdb_user_entry *e1,
                                   const struct userdb_user_entry *e2)
{
    if (!e1 || !e2) {
        return -1;
    }
    return X509_name_cmp(e1->uname, e2->uname);
}

static IMPLEMENT_LHASH_HASH_FN(userdb_user_entry, struct userdb_user_entry)
static IMPLEMENT_LHASH_COMP_FN(userdb_user_entries, struct userdb_user_entry)

static void userdb_apply_func_doall_arg(struct userdb_user_entry *entry, void *ptr)
{
    int err = 0;
    int(**func) (struct userdb_user_entry *) = ptr;

    if ((err = (**func)(entry))) {
        HIP_DEBUG("Error evaluating following entry: \n");
        userdb_entry_print(entry);
    }
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(userdb_apply_func, struct userdb_user_entry, void *)

void userdb_apply_func(int(*func)(struct userdb_user_entry *))
{
    hip_ht_doall_arg(user_db, (LHASH_DOALL_ARG_FN_TYPE) LHASH_DOALL_ARG_FN(userdb_apply_func), &func);
}

static void userdb_certificate_chain_print(STACK_OF(X509) *chain, UNUSED const char *const prefix)
{
    char buf[SIGNALING_USER_ID_MAX_LEN];
    int  i;

    HIP_DEBUG("%sCertificate chain subjects:\n", prefix);
    if (chain == NULL) {
        HIP_DEBUG("%s\t -> no certificates in chain\n", prefix);
        return;
    }
    for (i = sk_X509_num(chain) - 1; i >= 0; i--) {
        X509_NAME_oneline(X509_get_subject_name(sk_X509_value(chain, i)), buf, SIGNALING_USER_ID_MAX_LEN);
        buf[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
        HIP_DEBUG("%s\t -> Subject #%02d: %s\n", prefix, i + 1, buf);
    }
}

static void userdb_certificate_context_print(struct userdb_certificate_context *ctx, const char *const prefix)
{
    HIP_DEBUG_HIT("\t\t HIT1:", &ctx->src_hit);
    HIP_DEBUG_HIT("\t\t HIT2:", &ctx->dst_hit);
    HIP_DEBUG("%sGroup %d,\t count %d,\t network id %d:\n", prefix, ctx->group, ctx->count, ctx->network_id);
    userdb_certificate_chain_print(ctx->cert_chain, prefix);
}

int userdb_entry_print(struct userdb_user_entry *e)
{
    const struct hip_ll_node          *listentry = NULL;
    struct userdb_certificate_context *cert_ctx  = NULL;
    char                               subj_name[SIGNALING_USER_ID_MAX_LEN];

    if (e == NULL) {
        HIP_DEBUG("\t\t < NULL ENTRY > \n ");
        return 0;
    }

    HIP_DEBUG("\t----- USERDB ELEMENT START ------\n");
    X509_NAME_oneline(e->uname, subj_name, SIGNALING_USER_ID_MAX_LEN);
    subj_name[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
    HIP_DEBUG("\tUser name:\t %s\n", subj_name);
    HIP_DEBUG("\tUid:\t\t %ld \n", e->uid);
    if (e->pub_key) {
        switch (EVP_PKEY_type(e->pub_key->type)) {
        case EVP_PKEY_RSA:
            HIP_DEBUG("\tKey:\t\t RSA\n");
            break;
        case EVP_PKEY_DSA:
            HIP_DEBUG("\tKey:\t\t DSA\n");
            break;
        case EVP_PKEY_EC:
            HIP_DEBUG("\tKey:\t\t ECDSA\n");
            break;
        default:
            HIP_DEBUG("\tKey:\t\t n/a\n");
        }
    } else {
        HIP_DEBUG("\tKey:\t\t n/a\n");
    }
    HIP_DEBUG("\tCertificate contexts:\n");
    while ((listentry = hip_ll_iterate(e->cert_contexts, listentry))) {
        if ((cert_ctx = listentry->ptr)) {
            userdb_certificate_context_print(cert_ctx, "\t\t");
        }
    }
    HIP_DEBUG("\t----- USERDB ELEMENT END   ------\n");
    return 0;
}

/* Print the contents of the database */
void userdb_print(void)
{
    HIP_DEBUG("------------------ USERDB START ------------------\n");
    userdb_apply_func(&userdb_entry_print);
    HIP_DEBUG("------------------ USERDB END   ------------------\n");
}

int signaling_user_mgmt_init(void)
{
    if (!(user_db = hip_ht_init(LHASH_HASH_FN(userdb_user_entry), LHASH_COMP_FN(userdb_user_entries)))) {
        HIP_ERROR("failed to initialize user db\n");
        return -1;
    }
    return 0;
}

int signaling_user_mgmt_uninit(void)
{
    hip_ht_uninit(user_db);
    return 0;
}

struct userdb_user_entry *userdb_get_user(X509_NAME *uname)
{
    struct userdb_user_entry search_entry;

    search_entry.uname = uname;
    return hip_ht_find(user_db, &search_entry);
}

struct userdb_certificate_context *userdb_get_certificate_context(struct userdb_user_entry *const user,
                                                                  const struct in6_addr *const src_hit,
                                                                  const struct in6_addr *const dst_hit,
                                                                  const uint32_t network_id)
{
    const struct hip_ll_node          *listentry = NULL;
    struct userdb_certificate_context *cert_ctx  = NULL;

    if (!user) {
        return NULL;
    }

    while ((listentry = hip_ll_iterate(user->cert_contexts, listentry))) {
        if ((cert_ctx = listentry->ptr) &&
            IN6_ARE_ADDR_EQUAL(src_hit, &cert_ctx->src_hit) &&
            IN6_ARE_ADDR_EQUAL(dst_hit, &cert_ctx->dst_hit) &&
            network_id == cert_ctx->network_id) {
            return cert_ctx;
        }
    }

    return NULL;
}

/**
 * @param replace   0 if an existing user is not replaces, != 0 if an existing user is replaced with
 *                  the user from the given context
 *
 * @return          the user entry (either the new one, or existing user depending on the replace flag)
 *                  or NULL on error
 */
struct userdb_user_entry *userdb_add_user(const struct signaling_user_context *user, int replace)
{
    X509_NAME                *uname = NULL;
    struct userdb_user_entry *new = NULL;

    /* Check if we already have that user */
    if (signaling_DER_to_X509_NAME(user->subject_name, user->subject_name_len, &uname)) {
        HIP_ERROR("Could not get X509 Name from DER encoding\n");
        return NULL;
    }
    new = userdb_get_user(uname);
    if (new && !replace) {
        return new;
    } else if (new) {
        /* free the old user */
        EVP_PKEY_free(new->pub_key);
        free(new);
        new = NULL;
    }

    /* Now build and add */
    if (!(new = malloc(sizeof(struct userdb_user_entry)))) {
        HIP_ERROR("Could not allocate memory for new userdb entry \n");
        return NULL;
    }
    if (!(new->cert_contexts = malloc(sizeof(struct hip_ll)))) {
        HIP_ERROR("Could not allocate empty new list\n");
        free(new);
        return NULL;
    }
    hip_ll_init(new->cert_contexts);
    new->uname = uname;
    new->flags = 0;
    new->uid   = user->uid;
    if (user->key_rr_len > 0) {
        userdb_add_key_from_rr(new, &user->rdata, user->key_rr_len, user->pkey);
    } else {
        new->pub_key = NULL;
    }

    hip_ht_add(user_db, new);
    userdb_print();
    return new;
}

/**
 * Search for some kind of user context in the message
 * (user context parameter, or connection context parameter)
 * and add this user, if he does not already exist.
 *
 * @return      the new entry on success,
 *              NULL on error if no user information is present or user already exists
 */
struct userdb_user_entry *userdb_add_user_from_msg(const struct hip_common *const msg, int replace)
{
    //const struct signaling_connection   *conn     = NULL;
    const struct hip_tlv_common         *param    = NULL;
    const struct signaling_user_context *user_ctx = NULL;
    struct signaling_user_context        user;

    /* sanity checks */
    if (!msg) {
        HIP_ERROR("Cannot add user from  NULL-message\n");
        return NULL;
    }

    /* First check if there is a connection context,
     * This is the case if the message was sent by the firewall. */
/*    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)) &&
 *       hip_get_param_type(param) == HIP_PARAM_SIGNALING_CONNECTION) {
 *        //conn = (const struct signaling_connection *) (param + 1);
 *        //user_ctx = &conn->ctx_out.user;
 *    }
 */
    /* This is no message from a firewall, so just init a connection
     * from the information in the message. */
    /* get connection and update flags */
    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_ID)) &&
        hip_get_param_type(param) == HIP_PARAM_SIGNALING_USER_INFO_ID) {
        signaling_init_user_context(&user);
        signaling_build_user_context((const struct signaling_param_user_context *) param, &user);
        user_ctx = &user;
    }
    /* By now we should have a user context. */
    if (!user_ctx) {
        HIP_ERROR("There is no user context information inside the message\n");
        return NULL;
    }

    /* User does not exist, so add his context. */
    return userdb_add_user(user_ctx, replace);
}

struct userdb_certificate_context *userdb_add_certificate_context(struct userdb_user_entry *const user,
                                                                  const struct in6_addr *const src_hit,
                                                                  const struct in6_addr *const dst_hit,
                                                                  const uint32_t network_id,
                                                                  const struct hip_cert *const first_cert)
{
    struct userdb_certificate_context *new_ctx = NULL;

    /* sanity checks */
    HIP_ASSERT(first_cert);
    HIP_ASSERT(user);
    HIP_ASSERT(src_hit && dst_hit);

    if (!(new_ctx = malloc(sizeof(struct userdb_certificate_context)))) {
        HIP_ERROR("Could not allocate new certificate context \n");
        return NULL;
    }

    new_ctx->count        = first_cert->cert_count;
    new_ctx->group        = first_cert->cert_group;
    new_ctx->next_cert_id = 1;
    new_ctx->network_id   = network_id;
    memcpy(&new_ctx->src_hit, src_hit, sizeof(struct in6_addr));
    memcpy(&new_ctx->dst_hit, dst_hit, sizeof(struct in6_addr));
    if (!(new_ctx->cert_chain = sk_X509_new_null())) {
        HIP_ERROR("memory allocation failure\n");
        free(new_ctx);
        return NULL;
    }
    if (hip_ll_add_first(user->cert_contexts, new_ctx)) {
        HIP_ERROR("Error adding to list\n");
        free(new_ctx);
        return NULL;
    }

    return new_ctx;
}

struct userdb_certificate_context *userdb_get_certificate_context_by_key(const struct userdb_user_entry *const user,
                                                                         const EVP_PKEY *pubkey)
{
    const struct hip_ll_node          *listentry = NULL;
    struct userdb_certificate_context *cert_ctx  = NULL;
    X509                              *leafcert  = NULL;

    if (!user) {
        return NULL;
    }

    while ((listentry = hip_ll_iterate(user->cert_contexts, listentry))) {
        if ((cert_ctx = listentry->ptr) && sk_X509_num(cert_ctx->cert_chain) > 0) {
            leafcert = sk_X509_value(cert_ctx->cert_chain, sk_X509_num(cert_ctx->cert_chain) - 1);
            if (match_public_key(leafcert, pubkey)) {
                return cert_ctx;
            }
        }
    }

    return NULL;
}

/**
 *
 * @param key_rr_header the header of the resource record
 * @param key_rr        the resource record for the public key
 * @param key_rr_len    the length of the key resource record (without the length of the key_rr_header)
 */
int userdb_add_key_from_rr(struct userdb_user_entry *user,
                           const struct hip_host_id_key_rdata *const key_rr_header,
                           const unsigned int key_rr_len,
                           const unsigned char *key_rr)
{
    int                err = 0;
    struct hip_host_id pseudo_ui;

    HIP_IFEL(!user, -1, "User db entry is NULL \n");
    HIP_IFEL(!key_rr, -1, "Key rr is NULL.\n");
    HIP_IFEL(user->pub_key, -1, "Key is already set, no support for multiple keys. \n");

    pseudo_ui.hi_length       = htons(key_rr_len);
    pseudo_ui.rdata.algorithm = key_rr_header->algorithm;
    memcpy(pseudo_ui.key, key_rr, key_rr_len);
    HIP_IFEL(!(user->pub_key = hip_key_rr_to_evp_key(&pseudo_ui, 0)), -1, "Could not deserialize users public key\n");
    return 0;

out_err:
    return err;
}

/**
 * @return the id of the next expected certificate, 0 if chain is complete
 */
int userdb_add_certifiate(struct userdb_certificate_context *cert_ctx,
                          const struct hip_cert *param_cert)
{
    int   err  = 0;
    X509 *cert = NULL;

    /* sanity checks */
    HIP_IFEL(!cert_ctx,   -1, "Cannot add certificate to NULL-certificate context.\n");
    HIP_IFEL(!param_cert, -1, "Cannot add certificate from NULL-parameter.\n");
    HIP_IFEL(!cert_ctx->next_cert_id, 0, "Chain is already complete \n");

    /* check that certificate context matches */
    HIP_IFEL(param_cert->cert_group != cert_ctx->group,
             cert_ctx->next_cert_id, "Certificate groups do not match \n");
    HIP_IFEL(param_cert->cert_id != cert_ctx->next_cert_id,
             cert_ctx->next_cert_id, "Expected cert id %d differs from received cert id %d. \n", cert_ctx->next_cert_id, param_cert->cert_id);

    /* decode and add certificate */
    HIP_IFEL(signaling_DER_to_X509((const unsigned char *) (param_cert + 1),
                                   ntohs(param_cert->length) - sizeof(struct hip_cert) + sizeof(struct hip_tlv_common),
                                   &cert),
             cert_ctx->next_cert_id, "Could not decode certificate, dropping...");
    sk_X509_push(cert_ctx->cert_chain, cert);
    cert_ctx->next_cert_id++;
    if (cert_ctx->next_cert_id > cert_ctx->count) {
        cert_ctx->next_cert_id = 0;
    }

    return cert_ctx->next_cert_id;
out_err:
    return err;
}

/**
 * @return the id of the next expected certificate, 0 if chain is complete, -1 on internal error
 */
int userdb_add_certificates_from_msg(const struct hip_common *const msg,
                                     struct userdb_user_entry *user)
{
    int                                         err                 = 0;
    int                                         next_cert_id        = -1;
    const struct signaling_param_cert_chain_id *param_cert_chain_id = NULL;
    const struct hip_cert                      *param_cert          = NULL;
    struct userdb_certificate_context          *cert_ctx            = NULL;

    /* sanity checks */
    HIP_IFEL(!msg,      -1, "Message is NULL. \n");
    HIP_IFEL(!(param_cert_chain_id = hip_get_param(msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             -1, "Message contains no certificate chain identifier \n");

    /* Get certificate context or add new */
    HIP_IFEL(!(param_cert = hip_get_param(msg, HIP_PARAM_CERT)),
             -1, "Message contains no certificate. \n");
    if (!(cert_ctx = userdb_get_certificate_context(user, &msg->hits, &msg->hitr, ntohl(param_cert_chain_id->network_id)))) {
        if (!(cert_ctx = userdb_add_certificate_context(user,
                                                        &msg->hits,
                                                        &msg->hitr,
                                                        ntohl(param_cert_chain_id->network_id),
                                                        param_cert))) {
            HIP_ERROR("Error adding new certificate context.\n");
            err = -1;
            goto out_err;
        }
    }

    /* process certificates from the message */
    while (param_cert != NULL && hip_get_param_type((const struct hip_tlv_common *) param_cert) == HIP_PARAM_CERT) {
        HIP_DEBUG("Got certificate %d from a group of %d certificates \n", param_cert->cert_id, param_cert->cert_count);
        next_cert_id = userdb_add_certifiate(cert_ctx, param_cert);
        if (next_cert_id == 0) {
            return 0;
        } else if (next_cert_id != param_cert->cert_id + 1) {
            HIP_DEBUG("received out of order ceritifcate, dropping... \n");
        }
        param_cert = (const struct hip_cert *) hip_get_next_param(msg, (const struct hip_tlv_common *) param_cert);
    }

    return next_cert_id;
out_err:
    return err;
}

/**
 * @return 1 if user is authenticated, 0 if not, or on error
 */
int userdb_user_is_authed(const struct userdb_user_entry *const user)
{
    return user && user->flags & USER_IS_AUTHED;
}

/**
 * Get the short hash of a X509 name.
 * This equals the output of 'openssl x509 -in some-cert.pem -hash'
 *
 * @param subject   the X509 name of the subject
 * @param out_buf   the output buffer, where the subject hash strint is written
 * @return          the number of characters written to out_buf, or negative on error
 *
 * @note            see sprintf() for return values
 */
static int subject_hash(X509_NAME *subject, char *const out_buf)
{
    return sprintf(out_buf, "%08lx", X509_NAME_hash(subject));
}

static void get_user_certchain_hash_path(X509_NAME *subject, char *const buf)
{
    strcat(buf, CERTIFICATE_INDEX_USER_DIR);
    subject_hash(subject, buf + sizeof(CERTIFICATE_INDEX_USER_DIR) - 1);
    /* We need the -1 because sizeof, unlike strlen, counts the 0-terminator. However, we prefer sizeof for performance reasons */
    strcat(buf, ".0");
}

static void get_free_user_certchain_hash_path(X509_NAME *subject, char *const buf)
{
    struct stat buf_stat;
    int         i = 0;
    get_user_certchain_hash_path(subject, buf);
    while (!stat(buf, &buf_stat) && i < 10) {
        i++;
        sprintf(buf + sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH - 1, ".%d", i);
    }
}

/*
 * TODO: beautify this
 */
static void get_free_user_certchain_name_path(X509_NAME *subject, char *const buf)
{
    char        name_buf[128];
    int         name_len;
    int         i = 0;
    struct stat stat_buf;

    strcat(buf, CERTIFICATE_INDEX_USER_DIR);
    memset(name_buf, 0, 128);
    X509_NAME_get_text_by_NID(subject, NID_commonName, name_buf, 127);
    name_buf[127] = '\0';
    name_len      = strlen(name_buf);
    if (name_len == 0) {
        X509_NAME_get_text_by_NID(subject, NID_organizationName, name_buf, 127);
        name_buf[127] = '\0';
        name_len      = strlen(name_buf);
    }
    strcat(buf, name_buf);
    strcat(buf, ".cert.0");

    HIP_DEBUG("Path: %s \n", buf);
    while (!stat(buf, &stat_buf) && i < 10) {
        i++;
        sprintf(buf + sizeof(CERTIFICATE_INDEX_USER_DIR) + name_len - 1, ".cert.%d", i);
    }
}

/**
 * Compare if two certificate chains are equal.
 * We consider two chains as equal if all certificates from the shorter chain,
 * match with the certificates from the other chain.
 *
 * @note    The given certificate chain should have the leaf certificate at the bottom
 *          of the stack.
 *
 * TODO: update if we got a matching longer certificate chain
 * @return 1 if we have a matching certificate chain, 0 if not
 */
static int signaling_have_user_cert_chain(STACK_OF(X509) *cert_chain)
{
    int        i = 0;
    char       path_buf[PATH_MAX];
    X509      *cert           = NULL;
    X509_NAME *x509_subj_name = NULL;
    STACK_OF(X509) * local_chain = NULL;

    if (sk_X509_num(cert_chain) <= 0) {
        return 1;
    }

    cert           = sk_X509_value(cert_chain, sk_X509_num(cert_chain) - 1);
    x509_subj_name = X509_get_subject_name(cert);
    memset(path_buf, 0, PATH_MAX);
    get_user_certchain_hash_path(x509_subj_name, path_buf);

    while ((local_chain = signaling_load_certificate_chain(path_buf)) != NULL) {
        if (!certificate_chain_cmp(local_chain, cert_chain)) {
            return 1;
        }
        free(local_chain);
        i++;
        path_buf[sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH] = (char) i;
    }
    return 0;
}

/**
 * @return 0 if the certificate chain has been added or if we have it already
 *         negative if an error occurs
 */
int userdb_save_user_certificate_chain(STACK_OF(X509) *cert_chain)
{
    int        err            = 0;
    X509      *cert           = NULL;
    X509_NAME *x509_subj_name = NULL;
    char       subj_name[128];
    char       dst_path[PATH_MAX];
    char       dst_hash_path[PATH_MAX];

    if (sk_X509_num(cert_chain) <= 0) {
        return 0;
    }

    /* write the certificates to a file */
    cert           = sk_X509_value(cert_chain, sk_X509_num(cert_chain) - 1);
    x509_subj_name = X509_get_subject_name(cert);
    X509_NAME_oneline(x509_subj_name, subj_name, 128);
    HIP_DEBUG("Got certificate chain for user: %s\n", subj_name);

    if (signaling_have_user_cert_chain(cert_chain)) {
        HIP_DEBUG("Already have user's certificate chain \n");
        return 0;
    }

    /* construct the destination path */
    memset(dst_path, 0, PATH_MAX);
    get_free_user_certchain_name_path(x509_subj_name, dst_path);
    HIP_DEBUG("User's certificate chain is new, saving to file: %s.\n", dst_path);
    HIP_IFEL(signaling_save_certificate_chain(cert_chain, dst_path),
             -1, "Could not save certificate chain to file \n");
    memset(dst_hash_path, 0, PATH_MAX);
    get_free_user_certchain_hash_path(x509_subj_name, dst_hash_path);
    if (symlink(dst_path, dst_hash_path)) {
        HIP_DEBUG("Failed creating symlink: %s -> %s \n", dst_hash_path, dst_path);
    } else {
        HIP_DEBUG("Successfully created symlink: %s -> %s \n", dst_hash_path, dst_path);
    }

out_err:
    return err;
}

/**
 * Try to verify the public key of given user.
 *
 * @return 0 if a certificate chain could be build and verified, a non-zero error code otherwise
 */
int userdb_verify_public_key(X509_NAME *subject, const EVP_PKEY *const pub_key)
{
    int  err = 0;
    int  i   = 0;
    char name[SIGNALING_USER_ID_MAX_LEN];
    //char hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH + CERTIFICATE_INDEX_SUFFIX_LENGTH];
    char hash_filename[PATH_MAX];
    STACK_OF(X509) * cert_chain = NULL;
    X509                              *leaf_cert = NULL;
    struct userdb_user_entry          *db_entry  = NULL;
    struct userdb_certificate_context *cert_ctx  = NULL;

    /* sanity checks */
    HIP_IFEL(!pub_key,      -1, "Cannot verify NULL-pubkey.\n");
    HIP_IFEL(!subject,      -1, "Need X509 subject name for certificate lookup\n");

    X509_NAME_oneline(subject, name, SIGNALING_USER_ID_MAX_LEN);
    HIP_DEBUG("Verifying public key of subject: %s \n", name);
    memset(hash_filename, 0, PATH_MAX);

    /* Check if we have the user in our database */
    if ((db_entry = userdb_get_user(subject))) {
        if ((cert_ctx = userdb_get_certificate_context_by_key(db_entry, pub_key))) {
            HIP_DEBUG("Using certificate chain from user database.\n");
            cert_chain = cert_ctx->cert_chain;
            leaf_cert  = sk_X509_pop(cert_chain);
        }
    }

    /* If there was no entry in the database, check the certificate directories. */
    if (!cert_chain) {
        get_user_certchain_hash_path(subject, hash_filename);
        HIP_DEBUG("Looking up certificates index beginning at: %s\n", hash_filename);
        while ((cert_chain = signaling_load_certificate_chain(hash_filename)) != NULL) {
            leaf_cert = sk_X509_value(cert_chain, sk_X509_num(cert_chain) - 1);
            if (match_public_key(leaf_cert, pub_key)) {
                break;
            }
            HIP_DEBUG("Rejecting certificate %s, because public keys did not match\n", hash_filename);
            leaf_cert = NULL;
            free(cert_chain);
            cert_chain = NULL;

            /* move to next possible certificate */
            i++;
            sprintf(hash_filename + sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH - 1, ".%i", i);
        }
    }

    if (!cert_chain) {
        return SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED;
    }

    // We need only check that there is a matching chain, verification has been done earlier
    return 0;

    //return verify_certificate_chain(leaf_cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_chain);

out_err:
    return err;
}

/* Verify RSA Signature
 * return zero on success
 */
int signaling_verify_user_signature_rsa(struct signaling_user_context *user_ctx, struct hip_sig *param_user_signature, unsigned char *sha1_digest)
{
    int                   err    = 0;
    RSA                  *rsa    = NULL;
    int                   offset = 0;
    struct hip_rsa_keylen keylen;
    int                   bytes;

    /*Generating RSA key from the user context*/
    /* Have a look at hip_key_rr_to_rsa if u want to know more*/
    const uint8_t *tmp   = (const uint8_t *) &user_ctx->pkey;
    int            e_len = tmp[offset++];

    /* Check for public exponent longer than 255 bytes (see RFC 3110) */
    if (e_len == 0) {
        e_len   = ntohs((uint16_t) tmp[offset]);
        offset += 2;
    }
    bytes = user_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata) -
            offset - e_len;

    keylen.e_len = offset;
    keylen.e     = e_len;
    keylen.n     = bytes;

    rsa = RSA_new();
    if (!rsa) {
        HIP_ERROR("Failed to allocate RSA\n");
        return -1;
    }

    offset  = keylen.e_len;
    rsa->e  = BN_bin2bn(&user_ctx->pkey[offset], keylen.e, 0);
    offset += keylen.e;
    rsa->n  = BN_bin2bn(&user_ctx->pkey[offset], keylen.n, 0);

    /*Signature verification*/
    HIP_IFEL(RSA_size(rsa) != ntohs(param_user_signature->length) - 1,
             -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n", RSA_size(rsa), ntohs(param_user_signature->length));
    HIP_IFEL(!RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, param_user_signature->signature, RSA_size(rsa), rsa),
             -1, "RSA user signature did not verify correctly\n");
    RSA_free(rsa);
    return 0;
out_err:
    RSA_free(rsa);
    return err;
}

/* Verify ECDSA Signature
 * return zero on success
 */
int signaling_verify_user_signature_ecdsa(struct signaling_user_context *user_ctx, struct hip_sig *param_user_signature, unsigned char *sha1_digest)
{
    int                     err     = 0;
    int                     nid     = 0;
    EC_POINT               *pub_key = NULL;
    EC_GROUP               *group   = NULL;
    struct hip_ecdsa_keylen key_lens;
    EC_KEY                 *ecdsa;
    enum hip_cuve_id        curve_id;
    int                     curve_size;


    if (!user_ctx) {
        HIP_ERROR("NULL host id\n");
        return -1;
    }

    /*Generating ECDSA key from the user context*/
    /* Have a look at hip_key_rr_to_ecdsa if u want to know more*/
    curve_id = ntohs(*(const uint16_t *) user_ctx->pkey);
    HIP_DEBUG("Got curve id %d \n", curve_id);
    switch (curve_id) {
    case NIST_ECDSA_160:
        HIP_DEBUG("Using curve secp160r1\n");
        nid = NID_secp160r1;
        break;
    case NIST_ECDSA_256:
        HIP_DEBUG("Using curve secp256r1/prime256v1 \n");
        nid = NID_X9_62_prime256v1;
        break;
    case NIST_ECDSA_384:
        HIP_DEBUG("Using curve secp384r1 \n");
        nid = NID_secp384r1;
        break;
    default:
        HIP_DEBUG("Curve not supported.\n");
        return -1;
    }

    switch (nid) {
    case NID_secp160r1:
        curve_size = 160;
        break;
    case NID_X9_62_prime256v1:
        curve_size = 256;
        break;
    case NID_secp384r1:
        curve_size = 384;
        break;
    default:
        HIP_DEBUG("Curve not supported.\n");
        return -1;
    }

    key_lens.private = (curve_size + 7) >> 3;
    key_lens.public  = key_lens.private * 2 + 1;


    /* Build public key structure from key rr */
    if (!(ecdsa = EC_KEY_new())) {
        HIP_ERROR("Failed to init new key. \n");
        return -1;
    }
    if (!(group = EC_GROUP_new_by_curve_name(nid))) {
        HIP_ERROR("Failed building the group.\n");
        return -1;
    }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    if (!(pub_key = EC_POINT_new(group))) {
        HIP_ERROR("Failed to init public key (point).\n");
        return -1;
    }
    if (!EC_KEY_set_group(ecdsa, group)) {
        HIP_ERROR("Failed setting the group for key.\n");
        return -1;
    }
    if (!EC_POINT_oct2point(group, pub_key, user_ctx->pkey + HIP_CURVE_ID_LENGTH, key_lens.public, NULL)) {
        HIP_ERROR("Failed deserializing public key.\n");
        return -1;
    }
    if (!EC_KEY_set_public_key(ecdsa, pub_key)) {
        HIP_ERROR("Failed setting public key.\n");
        return -1;
    }


    /*Signature verification*/
    HIP_IFEL(ECDSA_size(ecdsa) != ntohs(param_user_signature->length) - 1,
             -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n", ECDSA_size(ecdsa), ntohs(param_user_signature->length));
    HIP_IFEL(impl_ecdsa_verify(sha1_digest, ecdsa, param_user_signature->signature),
             -1, "ECDSA user signature did not verify correctly\n");

    EC_KEY_free(ecdsa);
    return 0;
out_err:
    EC_KEY_free(ecdsa);
    return err;
}

/**
 * @return 0 if signature verified correctly, < 0 otherwise
 */
int signaling_verify_user_signature_from_msg(struct hip_common *msg, struct signaling_user_context *user_ctx,
                                             uint8_t flag_selective_sign)
{
    int             err = 0;
    int             hash_range_len;
    struct hip_sig *param_user_signature = NULL;
    unsigned char   sha1_digest[HIP_AH_SHA_LEN];
    const int       orig_len = hip_get_msg_total_len(msg);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I2_VERIFY_USER_SIG, PERF_R2_VERIFY_USER_SIG, "
              "PERF_CONN_U1_VERIFY_USER_SIG, PERF_CONN_U2_VERIFY_USER_SIG\n");
    hip_perf_start_benchmark(perf_set, PERF_I2_VERIFY_USER_SIG);
    hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_USER_SIG);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U1_VERIFY_USER_SIG);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U2_VERIFY_USER_SIG);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U3_VERIFY_USER_SIG);
#endif

    /* sanity checks */
    HIP_IFEL(!(param_user_signature = hip_get_param_readwrite(msg, HIP_PARAM_SIGNALING_USER_SIGNATURE)),
             -1, "Packet contains no user signature\n");
    /* Modify the packet to verify signature */
    hash_range_len = ((const uint8_t *) param_user_signature) - ((const uint8_t *) msg);
    hip_zero_msg_checksum(msg);
    HIP_IFEL(hash_range_len < 0, -ENOENT, "Invalid signature len\n");
    hip_set_msg_total_len(msg, hash_range_len);

    if (flag_selective_sign) {
        HIP_IFEL(signaling_build_hash_tree_and_get_root((struct hip_common *) msg, (unsigned char *) sha1_digest), -1,
                 "Building of the sha1 digest from hash-tree failed");
    } else {
        HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, hash_range_len, sha1_digest),
                 -1, "Could not build message digest \n");
    }

    switch (user_ctx->rdata.algorithm) {
    case HIP_HI_RSA:
        HIP_DEBUG("Verifying RSA signature...\n");
        err = signaling_verify_user_signature_rsa(user_ctx, param_user_signature, sha1_digest);
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("Verifying ECDSA \n");
        err = signaling_verify_user_signature_ecdsa(user_ctx, param_user_signature, sha1_digest);
        break;
    default:
        HIP_DEBUG("Algorithm used is : %u but not supported here for user verification\n", user_ctx->rdata.algorithm);
        break;
    }


#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I2_VERIFY_USER_SIG, PERF_R2_VERIFY_USER_SIG, "
              "PERF_CONN_U1_VERIFY_USER_SIG, PERF_CONN_U2_VERIFY_USER_SIG\n");
    hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_USER_SIG);
    hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_USER_SIG);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_VERIFY_USER_SIG);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_VERIFY_USER_SIG);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_VERIFY_USER_SIG);
#endif

out_err:
    hip_set_msg_total_len(msg, orig_len);
    return err;
}

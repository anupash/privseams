/*
 * signaling_netstat_wrapper.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/common.h"

#include "signaling_oslayer.h"

/* MAX = sizeof(netstat -tpn | grep :{port} | grep :{port}) < 60 */
#define CALLBUF_SIZE            60
/* MAX = sizeof(/proc/{port}/exe) <= 16 */
#define SYMLINKBUF_SIZE         16

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "firewall/common_types.h"
#include "firewall/hslist.h"


#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"
#include "signaling_user_management.h"
#include "signaling_x509_api.h"

struct slist *verified_apps = NULL;

/*
 * Get the attribute certificate corresponding to the given application binary.
 *
 * @note app_file is supposed to be 0-terminated
 */
static X509AC *get_application_attribute_certificate_chain(const char *app_file, STACK_OF(X509) **chain)
{
    FILE *fp = NULL;
    char app_cert_file[PATH_MAX];
    X509AC *app_cert = NULL;
    int err = 0;

    HIP_IFEL(app_file == NULL, -1, "Got no path to application (NULL).\n");

    /* Get the application attribute certificate */
    sprintf(app_cert_file, "%s.cert", app_file);
    HIP_IFEL(!(fp = fopen(app_cert_file, "r")),
            -1,"Application certificate could not be found at %s.\n", app_cert_file);
    HIP_IFEL(!(app_cert = PEM_read_X509AC(fp, NULL, NULL, NULL)),
            -1, "Could not decode application certificate.\n");
    fclose(fp);

    /* Look if there is a chain for this certificate */
    if (!chain) {
        return app_cert;
    }
    sprintf(app_cert_file, "%s.chain", app_file);
    *chain = signaling_load_certificate_chain(app_cert_file);

    return app_cert;

out_err:
    return NULL;
}

/**
 * This hashes a file 'in_file' and returns the digest in 'digest_buffer'.
 */
static int hash_file(const char *in_file, unsigned char *digest_buffer)
{
    SHA_CTX context;
    int fd;
    int i;
    unsigned char read_buffer[1024];
    FILE *f;
    int err = 0;

    HIP_IFEL(!in_file, -1, "No path to application given (NULL).\n");
    HIP_IFEL(!digest_buffer, -1, "Output buffer is NULL.\n");

    HIP_DEBUG("Hashing file: %s. \n", in_file);

    f = fopen(in_file,"r");
    fd=fileno(f);
    SHA1_Init(&context);
    for (;;) {
        i = read(fd,read_buffer,1024);
        if(i <= 0)
            break;
        SHA1_Update(&context,read_buffer,(unsigned long)i);
    }
    SHA1_Final(digest_buffer,&context);
    fclose(f);

out_err:
    return err;
}

static int verify_application_hash(const char *file, X509AC *ac)
{
    int err = 0;
    int res = 0;
    unsigned char md[SHA_DIGEST_LENGTH];
    ASN1_BIT_STRING *hash;

    HIP_IFEL(!file, -1, "No path to application given.");
    HIP_IFEL(!ac, -1, "No attribute certificate given.");

    // Check if hash is present in certificate
    HIP_IFEL(ac->info->holder->objectDigestInfo == NULL,
            -1, "Hash could not be found in attribute certificate.");

    // Get the hash of file into a ASN1 Bitstring
    // TODO: We need to choose the hash algorithm equal to the one in the certificate?
    HIP_IFEL(0 > hash_file(file, md),
            -1, "Could not compute hash of binary.\n");
    hash = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(hash,md,SHA_DIGEST_LENGTH);

    // Compare the hashes
    // TODO: ASN1_BIT_STRING_cmp compares string types too, is this ok here?
    res = ASN1_STRING_cmp(hash, ac->info->holder->objectDigestInfo->digest);
    if(res != 0) {
        HIP_DEBUG("Hashes differ:\n");
        HIP_HEXDUMP("\thash in cert:\t", ac->info->holder->objectDigestInfo->digest->data, ac->info->holder->objectDigestInfo->digest->length);
        HIP_HEXDUMP("\thash of app:\t", hash->data, hash->length);
        err = -1;
    } else {
        HIP_DEBUG("Hash of file %s matches the one in the certificate.\n", file);
    }

out_err:
    return err;
}

/*
 * Determine the pid, and path of an application and fill it into the struct.
 *
 * TODO:
 *  - add more checks for right connection (check src and destination addresses)
 *  - add parsing of udp connections
 *
 *  @return NULL on error, the path to the application binary on success
 */
int signaling_netstat_get_application_system_info_by_ports(const uint16_t src_port,
                                                           const uint16_t dst_port,
                                                           struct system_app_context *const sys_ctx)
{
    FILE *fp;
    int err = 0, UNUSED scanerr;
    char *res;
    char callbuf[CALLBUF_SIZE];
    char symlinkbuf[SYMLINKBUF_SIZE];
    char readbuf[NETSTAT_SIZE_OUTPUT];

    memset(sys_ctx->proto,       0, NETSTAT_SIZE_PROTO);
    memset(sys_ctx->recv_q,      0, NETSTAT_SIZE_RECV_SEND);
    memset(sys_ctx->send_q,      0, NETSTAT_SIZE_RECV_SEND);
    memset(sys_ctx->remote_addr, 0, NETSTAT_SIZE_ADDR_v6);
    memset(sys_ctx->local_addr,  0, NETSTAT_SIZE_ADDR_v6);
    memset(sys_ctx->state,       0, NETSTAT_SIZE_STATE);
    memset(sys_ctx->progname,    0, NETSTAT_SIZE_PROGNAME);

    /**
     * Prepare and make call to netstat.
     * Distinguish between client and server process.
     */
    if (dst_port != 0) {
        sprintf(callbuf, "netstat -tpneW | grep :%d | grep :%d", src_port, dst_port);
        memset(readbuf, 0, NETSTAT_SIZE_OUTPUT);
        HIP_IFEL(!(fp = popen(callbuf, "r")),
                 -1, "Failed to make call to nestat.\n");
        res = fgets(readbuf, NETSTAT_SIZE_OUTPUT, fp);
        pclose(fp);
    } else {
        sprintf(callbuf, "netstat -tpneWl | grep :%d", src_port);
        memset(readbuf, 0, NETSTAT_SIZE_OUTPUT);
        HIP_IFEL(!(fp = popen(callbuf, "r")),
                 -1, "Failed to make call to nestat.\n");
        res = fgets(readbuf, NETSTAT_SIZE_OUTPUT, fp);
        pclose(fp);
    }

    if(!res) {
        HIP_DEBUG("No output from netstat call: %s\n", callbuf);
    }
    HIP_IFEL(!res, -1, "Got no output from netstat.\n");

    /*
     * Parse the output.
     * Format is the same for connections and listening sockets.
     */
    scanerr = sscanf(readbuf, "%s %s %s %s %s %s %d %d %d/%s",
                     sys_ctx->proto,
                     sys_ctx->recv_q,
                     sys_ctx->send_q,
                     sys_ctx->local_addr,
                     sys_ctx->remote_addr,
                     sys_ctx->state,
                     &sys_ctx->uid,
                     &sys_ctx->inode,
                     &sys_ctx->pid,
                     sys_ctx->progname);
    HIP_DEBUG("Found program %s (%d) owned by uid %d on a %s connection from: \n", sys_ctx->progname, sys_ctx->pid, sys_ctx->uid, sys_ctx->proto);
    HIP_DEBUG("\t from:\t %s\n", sys_ctx->local_addr);
    HIP_DEBUG("\t to:\t %s\n",   sys_ctx->remote_addr);

    // determine path to application binary from /proc/{pid}/exe
    memset(sys_ctx->path, 0, SIGNALING_PATH_MAX_LEN);
    sprintf(symlinkbuf, "/proc/%i/exe", sys_ctx->pid);
    HIP_IFEL(0 > readlink(symlinkbuf, sys_ctx->path, SIGNALING_PATH_MAX_LEN),
             -1, "Failed to read symlink to application binary\n");

    HIP_DEBUG("Found application binary at: %s \n", sys_ctx->path);

out_err:
    return err;
}

/*
 * Fill in the context information of an application.
 *
 * Also sets application path.
 */
int signaling_get_application_context_from_certificate(X509AC *ac,
                                                       struct signaling_application_context *app_ctx)
{
    int err = 0;
    X509_NAME *name;

    HIP_IFEL(!ac,       -1, "Cannot fill application context from NULL-certificate.\n");
    HIP_IFEL(!app_ctx,  -1, "Cannot write to NULL-application context.\n");

    /* Fill in context */
    if ((ac->info->issuer->type == 0)||
        ((ac->info->issuer->type == 1)&&(ac->info->issuer->d.v2Form->issuer != NULL))) {
        name = X509AC_get_issuer_name(ac);
        if (!name)
            HIP_DEBUG("Error getting AC issuer name, possibly not a X500 name");
        else
        {
            X509_NAME_oneline(name, app_ctx->issuer_dn, SIGNALING_ISS_DN_MAX_LEN);
        }

    }

    if (ac->info->holder->entity != NULL) {
        name = X509AC_get_holder_entity_name(ac);
        if (!name) {
            HIP_DEBUG("Error getting AC holder name, possibly not a X500 name");
        } else {
            X509_NAME_oneline(name, app_ctx->application_dn, SIGNALING_APP_DN_MAX_LEN);
        }
    }

out_err:
    return err;
}

/*
 * Argument is a null-terminated string.
 */
int signaling_verify_application(const char *app_path)
{
    int err = 0;
    unsigned char md[SHA_DIGEST_LENGTH];
    struct slist *verified_app = verified_apps;
    char *hash = NULL;

    X509AC *app_cert = NULL;
    STACK_OF(X509) *untrusted_chain = NULL;

    /* Look if it has been verified before. */
    HIP_IFEL(0 > hash_file(app_path, md),
             -1, "Could not compute hash of binary.\n");
    while (verified_app) {
        if (!memcmp(md, verified_app->data, SHA_DIGEST_LENGTH)) {
            HIP_DEBUG("Application has recently been verified and is unchanged, skipping certificate chain verification. \n");
            return 0;
        }
        verified_app = verified_app->next;
    }

    /* Get application certificate chain */
    HIP_IFEL(!(app_cert = get_application_attribute_certificate_chain(app_path, &untrusted_chain)),
             -1, "No application certificate found for application: %s.\n", app_path);

    HIP_DEBUG("Found chain of size %d \n", sk_X509_num(untrusted_chain));
    //HIP_DEBUG("Application certificate: \n");
    //X509AC_print(app_cert);

    /* Before we do any verifying, check that hashes match */
    HIP_IFEL(0 > verify_application_hash(app_path, app_cert),
             -1, "Hash of application doesn't match hash in certificate.\n");

    /* Now verify the chain */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_X509AC_VERIFY_CERT_CHAIN\n");   // test 1.1.2
    hip_perf_start_benchmark(perf_set, PERF_X509AC_VERIFY_CERT_CHAIN);
#endif
    HIP_IFEL(verify_ac_certificate_chain(app_cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, untrusted_chain),
             -1, "Attribute certificate for application %s did not verify correctly.\n", app_path);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_X509AC_VERIFY_CERT_CHAIN\n");
    hip_perf_stop_benchmark(perf_set, PERF_X509AC_VERIFY_CERT_CHAIN);
#endif

    /* Add to verified applications */
    hash = malloc(SHA_DIGEST_LENGTH);
    memcpy(hash, md, SHA_DIGEST_LENGTH);
    verified_apps = append_to_slist(verified_apps, hash);
    HIP_DEBUG("Added hash of application to verified apps. \n", hash);

out_err:
    sk_X509_free(untrusted_chain);
    if (app_cert) {
        X509AC_free(app_cert);
    }
    return err;
}

/*
 * Just a wrapper.
 */
int signaling_get_verified_application_context_by_ports(uint16_t src_port,
                                                        uint16_t dst_port,
                                                        struct signaling_connection_context *const ctx)
{
    int err = 0;
    X509AC *ac = NULL;
    struct system_app_context sys_ctx;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_CTX_LOOKUP\n");   // test 1.1
    hip_perf_start_benchmark(perf_set, PERF_CTX_LOOKUP);

    HIP_DEBUG("Start PERF_NETSTAT_LOOKUP\n");  // test 1.1.1
    hip_perf_start_benchmark(perf_set, PERF_NETSTAT_LOOKUP);
#endif

    HIP_IFEL(signaling_netstat_get_application_system_info_by_ports(src_port, dst_port, &sys_ctx),
             -1, "Netstat failed to get system context for application corresponding to ports %d -> %d.\n", src_port, dst_port);
    ctx->user.uid = sys_ctx.uid;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_NETSTAT_LOOKUP\n");
    hip_perf_stop_benchmark(perf_set, PERF_NETSTAT_LOOKUP);

    HIP_DEBUG("Start PERF_VERIFY_APPLICATION\n");   // test 1.1.2
    hip_perf_start_benchmark(perf_set, PERF_VERIFY_APPLICATION);
#endif

    HIP_IFEL(signaling_verify_application(sys_ctx.path),
             -1, "Could not verify certificate of application: %s.\n", sys_ctx.path);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_VERIFY_APPLICATION\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY_APPLICATION);
#endif

    HIP_IFEL(!(ac = get_application_attribute_certificate_chain(sys_ctx.path, NULL)),
            -1, "Could not open application certificate.");
    HIP_IFEL(signaling_get_application_context_from_certificate(ac, &ctx->app),
             -1, "Could not build application context for application: %s.\n", sys_ctx.path);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_CTX_LOOKUP\n");
    hip_perf_stop_benchmark(perf_set, PERF_CTX_LOOKUP);
#endif
out_err:
    return err;
}


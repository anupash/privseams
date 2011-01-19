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

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"

/*
 * Get the attribute certificate corresponding to the given application binary.
 *
 * @note app_file is supposed to be 0-terminated
 */
static X509AC *get_application_attribute_certificate(const char *app_file)
{
    FILE *fp = NULL;
    char *app_cert_file = NULL;
    X509AC *app_cert = NULL;
    int err = 0;

    HIP_IFEL(app_file == NULL, -1, "Got no path to application (NULL).\n");

    /* Build path to application certificate */
    HIP_IFEL(!(app_cert_file = malloc(strlen(app_file) + 6)),
             -1, "Could not allocate memory for filename \n");
    memset(app_cert_file, 0, strlen(app_file) + 6);
    strcat(app_cert_file, app_file);
    strcat(app_cert_file, ".cert");

    /* Now get the application certificate */
    HIP_IFEL(!(fp = fopen(app_cert_file, "r")),
            -1,"Application certificate could not be found at %s.\n", app_cert_file);
    HIP_IFEL(!(app_cert = PEM_read_X509AC(fp, NULL, NULL, NULL)),
            -1, "Could not decode application certificate.\n");
    fclose(fp);

out_err:
    free(app_cert_file);
    return app_cert;
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

    // prepare and make call to netstat
    sprintf(callbuf, "netstat -tpneW | grep :%d | grep :%d", src_port, dst_port);
    memset(readbuf, 0, NETSTAT_SIZE_OUTPUT);
    HIP_IFEL(!(fp = popen(callbuf, "r")),
             -1, "Failed to make call to nestat.\n");
    res = fgets(readbuf, NETSTAT_SIZE_OUTPUT, fp);
    pclose(fp);

    /*
     * If we have no connection, then we might be the server process.
     * We have to look for a listening socket on the destination port.
     */
    if(!res) {
        // prepare make second call to netstat
        HIP_DEBUG("No output from netstat call: %s\n", callbuf);
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
    HIP_IFEL(!res, -1, "Got no output from netstat (neither connection nor listening socket).\n");

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
    const char *issuer_cert_file;
    FILE *fp = NULL;
    /* X509 Stuff */
    X509AC *app_cert = NULL;
    X509 *issuercert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;

    /* Get application certificate */
    HIP_IFEL(!(app_cert = get_application_attribute_certificate(app_path)),
             -1, "No application certificate found for application: %s.\n", app_path);

    /* Look for and get issuer certificate */
    issuer_cert_file = "cert.pem";
    HIP_IFEL(!(fp = fopen(issuer_cert_file, "r")),
             -1, "No issuer cert file given.\n");
    HIP_IFEL(!(issuercert = PEM_read_X509(fp, NULL, NULL, NULL)),
             -1, "Could not decode root cert file.\n");
    HIP_DEBUG("Using issuer certificate at: %s.\n", issuer_cert_file);
    fclose(fp);

    /* Before we do any verifying, check that hashes match */
    HIP_IFEL(0 > verify_application_hash(app_path, app_cert),
             -1, "Hash of application doesn't match hash in certificate.\n");

    /* Setup the certificate store, which is passed used in the verification context store */
    HIP_IFEL(!(store = X509_STORE_new()),
             -1, "Error setting up the store. Exiting... \n");

    /* Add the issuer certificate into the certificate lookup store. */
    if(issuercert != NULL) {
        X509_STORE_add_cert(store, issuercert);
    }

    /* Setup the store context that is passed to the verify function. */
    HIP_IFEL(!(verify_ctx = X509_STORE_CTX_new()),
             -1, "Error setting up the verify context.\n");

    /* Init the store context */
    HIP_IFEL(!(X509_STORE_CTX_init(verify_ctx, store, NULL, NULL)),
             -1, "Error initializing the verify context.\n");

    /* Now do the verifying */
    HIP_IFEL(!X509AC_verify_cert(verify_ctx, app_cert),
             -1, "Certificate %s did not verify correctly!\n", "attr_cert.pem");

out_err:
    if (verify_ctx) {
        X509_STORE_CTX_free(verify_ctx);
    }
    // function is null tolerant
    X509_STORE_free(store);
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

    ctx->src_port = src_port;
    ctx->dest_port = dst_port;
    HIP_IFEL(signaling_netstat_get_application_system_info_by_ports(src_port, dst_port, &sys_ctx),
             -1, "Netstat failed to get system context for application corresponding to ports %d -> %d.\n", src_port, dst_port);
    ctx->user_ctx.uid = sys_ctx.uid;
    HIP_IFEL(signaling_verify_application(sys_ctx.path),
             -1, "Could not verify certificate of application: %s.\n", sys_ctx.path);
    HIP_IFEL(!(ac = get_application_attribute_certificate(sys_ctx.path)),
            -1, "Could not open application certificate.");
    HIP_IFEL(signaling_get_application_context_from_certificate(ac, &ctx->app_ctx),
             -1, "Could not build application context for application: %s.\n", sys_ctx.path);

out_err:
    return err;
}




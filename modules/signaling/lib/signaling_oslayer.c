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

// Netstat format widths (derived from netstat source code)
#define NETSTAT_SIZE_PROTO      7
#define NETSTAT_SIZE_RECV_SEND  7
#define NETSTAT_SIZE_OUTPUT     160
#define NETSTAT_SIZE_STATE      12
#define NETSTAT_SIZE_PROGNAME   20
#define NETSTAT_SIZE_ADDR_v6    50


#include <x509ac.h>
#include <x509attr.h>
#include <x509ac-supp.h>
#include <x509attr-supp.h>
#include <x509ac_utils.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"

/*
 * Get the attribute certificate corresponding to the given application binary.
 */
static X509AC *get_application_attribute_certificate(const char *app_file) {
    FILE *fp = NULL;
    char *app_cert_file = NULL;
    X509AC *app_cert = NULL;
    int err = 0;

    HIP_IFEL(app_file == NULL, -1, "Got no path to application (NULL).\n");

    /* Build path to application certificate */
    app_cert_file = malloc(strlen(app_file) + 6);
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
    return app_cert;
}

/**
 * This hashes a file 'in_file' and returns the digest in 'digest_buffer'.
 */
static int hash_file(const char *in_file, unsigned char *digest_buffer) {
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
    SHA1_Final(&(digest_buffer[0]),&context);
    fclose(f);

out_err:
    return err;
}


static void hex_print(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int verify_application_hash(const char *file, X509AC *ac) {
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
        HIP_DEBUG("\thash in cert:\t");
        hex_print(ac->info->holder->objectDigestInfo->digest->data,
                ac->info->holder->objectDigestInfo->digest->length);
        HIP_DEBUG("\thash of app:\t");
        hex_print(hash->data, hash->length);
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
int signaling_netstat_get_application_by_ports(const uint16_t src_port, const uint16_t dst_port, struct signaling_application_context *app_ctx) {
    FILE *fp;
    int err = 0, UNUSED scanerr;
    char *res;
    char callbuf[CALLBUF_SIZE];
    char symlinkbuf[SYMLINKBUF_SIZE];
    char readbuf[NETSTAT_SIZE_OUTPUT];

    // variables for parsing
    char proto[NETSTAT_SIZE_PROTO];
    char unused[NETSTAT_SIZE_RECV_SEND];
    char remote_addr[NETSTAT_SIZE_ADDR_v6];
    char local_addr[NETSTAT_SIZE_ADDR_v6];
    char state[NETSTAT_SIZE_STATE];
    char progname[NETSTAT_SIZE_PROGNAME];
    UNUSED int inode;

    memset(proto, 0, NETSTAT_SIZE_PROTO);
    memset(unused, 0, NETSTAT_SIZE_RECV_SEND);
    memset(remote_addr, 0, NETSTAT_SIZE_ADDR_v6);
    memset(local_addr, 0, NETSTAT_SIZE_ADDR_v6);
    memset(state, 0, NETSTAT_SIZE_STATE);
    memset(progname, 0, NETSTAT_SIZE_PROGNAME);

    // prepare and make call to netstat
    memset(callbuf, 0, CALLBUF_SIZE);
    sprintf(callbuf, "netstat -tpneW | grep :%d | grep :%d", src_port, dst_port);
    memset(&readbuf[0], 0, NETSTAT_SIZE_OUTPUT);
    HIP_IFEL(!(fp = popen(callbuf, "r")), -1, "Failed to make call to nestat.\n");
    res = fgets(&readbuf[0], NETSTAT_SIZE_OUTPUT, fp);
    pclose(fp);

    /*
     * If we have no connection, then we might be the server process.
     * We have to look for a listening socket on the destination port.
     */
    if(!res) {
        // prepare make second call to netstat
        HIP_DEBUG("No output from netstat call: %s\n", callbuf);
        memset(callbuf, 0, CALLBUF_SIZE);
        sprintf(callbuf, "netstat -tpneWl | grep :%d", src_port);
        memset(&readbuf[0], 0, NETSTAT_SIZE_OUTPUT);
        HIP_IFEL(!(fp = popen(callbuf, "r")), -1, "Failed to make call to nestat.\n");
        res = fgets(&readbuf[0], NETSTAT_SIZE_OUTPUT, fp);
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
            proto, unused, unused, local_addr, remote_addr, state, &app_ctx->euid, &inode, &app_ctx->pid, progname);
    HIP_DEBUG("Found program %s (%d) owned by uid %d on a %s connection from: \n", progname, app_ctx->pid, app_ctx->euid, proto);
    HIP_DEBUG("\t from:\t %s\n", local_addr);
    HIP_DEBUG("\t to:\t %s\n", remote_addr);

    // determine path to application binary from /proc/{pid}/exe
    memset(symlinkbuf, 0, SYMLINKBUF_SIZE);
    app_ctx->path = (char *) malloc(PATHBUF_SIZE);
    memset(app_ctx->path, 0, PATHBUF_SIZE);
    sprintf(symlinkbuf, "/proc/%i/exe", app_ctx->pid);
    HIP_IFEL(0 > readlink(symlinkbuf, app_ctx->path, PATHBUF_SIZE),
            -1, "Failed to read symlink to application binary\n");

    HIP_DEBUG("Found application binary at: %s \n", app_ctx->path);

out_err:
    return err;
}

/*
 * Fill in the context information of an application.
 *
 * Also sets application path.
 */
int signaling_get_application_context_from_certificate(char *app_path, struct signaling_application_context *app_ctx) {
    int err = 0;
    X509AC *ac = NULL;
    X509_NAME *name;

    HIP_IFEL(!(ac = get_application_attribute_certificate(app_path)),
            -1, "Could not open application certificate.");

    /* Dump certificate */
    //X509AC_print(app_cert);

    /* Fill in context */
    app_ctx->path = app_path;

    if( (ac->info->issuer->type == 0)||
        ((ac->info->issuer->type == 1)&&(ac->info->issuer->d.v2Form->issuer != NULL)))
    {
        name = X509AC_get_issuer_name(ac);
        if (!name)
            HIP_DEBUG("Error getting AC issuer name, possibly not a X500 name");
        else
        {
            app_ctx->issuer_dn = (char *) malloc(ONELINELEN);
            X509_NAME_oneline(name,app_ctx->issuer_dn,ONELINELEN);
        }

    }

    if( ac->info->holder->entity != NULL) {
        name = X509AC_get_holder_entity_name(ac);
        if (!name) {
            HIP_DEBUG("Error getting AC holder name, possibly not a X500 name");
        } else {
            app_ctx->application_dn = (char *) malloc(ONELINELEN);
            X509_NAME_oneline(name,app_ctx->application_dn,ONELINELEN);
        }
    }

out_err:
    return err;
}

/*
 * Argument is a null-terminated string.
 */
int signaling_verify_application(const char *app_path) {
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

    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509AC_free(app_cert);

out_err:

    return err;
}

/*
 * Just a wrapper.
 */
int signaling_get_verified_application_context_by_ports(uint16_t src_port, uint16_t dst_port, struct signaling_application_context *app_ctx) {
    int err = 0;
    HIP_IFEL(signaling_netstat_get_application_by_ports(src_port, dst_port, app_ctx),
            -1, "Netstat failed to get path to application for given port pair.\n");
    HIP_IFEL(signaling_verify_application(app_ctx->path),
            -1, "Could not verify certificate of application: %s.\n", app_ctx->path);
    HIP_IFEL(signaling_get_application_context_from_certificate(app_ctx->path, app_ctx),
            -1, "Could not build application context for application: %s.\n", app_ctx->path);

    /* Needs to be done for completeness, since get_application_certificate_context does not fill in ports */
    app_ctx->src_port = src_port;
    app_ctx->dest_port = dst_port;

out_err:
    return err;
}




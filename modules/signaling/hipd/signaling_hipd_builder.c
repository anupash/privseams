/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

#include <string.h>
#include <unistd.h>

#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"

#include "hipd/hadb.h"

#include <x509ac.h>
#include <x509attr.h>
#include <x509ac-supp.h>
#include <x509attr-supp.h>
#include <x509ac_utils.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_hipd_builder.h"
#include "signaling_netstat_api.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/hipd/signaling_state.h"

/*
 * Returns the name of an application information parameter field.
 */
const char *signaling_get_param_field_type_name(const hip_tlv_type_t param_type)
{
    switch (param_type) {
    case SIGNALING_APPINFO_APP_DN: 		return "Application Distinguished Name";
    case SIGNALING_APPINFO_ISSUER_DN:	return "Issuer Distinguished NAme";
    case SIGNALING_APPINFO_REQS:		return "Application Requirements";
    case SIGNALING_APPINFO_GROUPS:		return "Application Groups";
    }
    return "UNDEFINED Application information";
}

/*
 * Get the attribute certificate corresponding to the given application binary.
 */
static X509AC *signaling_get_application_cert(const char *app_file) {
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
static void signaling_hash_file(const char *in_file, unsigned char *digest_buffer) {
    SHA_CTX context;
    int fd;
    int i;
    unsigned char read_buffer[1024];
    FILE *f;

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
}


UNUSED static void hex_print(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int signaling_verify_application_hash(const char *file, X509AC *ac) {
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
    signaling_hash_file(file, md);
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
 * Argument is a null-terminated string.
 */
static int signaling_verify_application(struct signaling_state *ctx) {
    int err = 0;
    const char *issuer_cert_file;
    FILE *fp = NULL;
    /* X509 Stuff */
    X509AC *app_cert = NULL;
    X509 *issuercert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;

    /* Get application certificate */
    HIP_IFEL(!(app_cert = signaling_get_application_cert(ctx->application.path)),
            -1, "No application certificate found for application: %s.\n", ctx->application.path);

    /* Look for and get issuer certificate */
    issuer_cert_file = "cert.pem";
    HIP_IFEL(!(fp = fopen(issuer_cert_file, "r")),
            -1, "No issuer cert file given.\n");
    HIP_IFEL(!(issuercert = PEM_read_X509(fp, NULL, NULL, NULL)),
            -1, "Could not decode root cert file.\n");
    HIP_DEBUG("Using issuer certificate at: %s.\n", issuer_cert_file);
    fclose(fp);

    /* Before we do any verifying, check that hashes match */
    HIP_IFEL(0 > signaling_verify_application_hash(ctx->application.path, app_cert),
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

    /* Free memory */
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509AC_free(app_cert);

out_err:

    return err;
}


/*
 * Fill in the context information of an application.
 */
static int signaling_get_application_context(struct signaling_state *ctx) {
    int err = 0;
    X509AC *ac = NULL;
    X509_NAME *name;

    HIP_IFEL(!(ac = signaling_get_application_cert(ctx->application.path)),
            -1, "Could not open application certificate.");

    /* Dump certificate */
    //X509AC_print(app_cert);

    /* Read whatever we want to know. */
    /* Issuer name */
    if( (ac->info->issuer->type == 0)||
        ((ac->info->issuer->type == 1)&&(ac->info->issuer->d.v2Form->issuer != NULL)))
    {
        name = X509AC_get_issuer_name(ac);
        if (!name)
            HIP_DEBUG("Error getting AC issuer name, possibly not a X500 name");
        else
        {
            ctx->application.issuer_dn = (char *) malloc(ONELINELEN);
            X509_NAME_oneline(name,ctx->application.issuer_dn,ONELINELEN);
        }

    }

    /* Application INFORMATION */
    if( ac->info->holder->entity != NULL) {
        name = X509AC_get_holder_entity_name(ac);
        if (!name) {
            HIP_DEBUG("Error getting AC holder name, possibly not a X500 name");
        } else {
            ctx->application.application_dn = (char *) malloc(ONELINELEN);
            X509_NAME_oneline(name,ctx->application.application_dn,ONELINELEN);
        }
    }

    HIP_DEBUG("Found following context for application: %s \n", ctx->application.path);
    HIP_DEBUG("\tIssuer name: %s\n", ctx->application.application_dn);
    HIP_DEBUG("\tHolder name: %s\n", ctx->application.issuer_dn);

out_err:
    return err;
}

/*
 * Appends a tlv struct at the location given by 'start'.
 */
static void *signaling_build_param_append_tlv(void *start, hip_tlv_type_t type, const void *contents, hip_tlv_len_t length) {
	const void *src = NULL;
	uint8_t *dst = NULL;
	struct hip_tlv_common *tlv = start;

	if(length > 0) {
		hip_set_param_type(tlv, type);
		hip_set_param_contents_len(tlv, length);

		src = contents;
		dst = hip_get_param_contents_direct_readwrite(tlv);
		memcpy(dst, src, length);

		start = (uint8_t *)start + sizeof(struct hip_tlv_common) + length;
	} else {
		HIP_DEBUG("Passed zero-length argument of type %d... ignoring!", type);
	}

	return start;
}

/**
 * Build a SIGNALING APP INFO (= Name, Developer, Serial) parameter
 *
 * @param msg the message
 * @param type the info type
 * @param info the info (app name, devloper or serial)
 * @param length the length of the info
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_appinfo(struct hip_common *msg)
{
    struct hip_tlv_common appinfo;
    int err = 0;
    int length_contents = 0;
    void *contents_start, *p_tmp;
    struct signaling_state *sig_state = NULL;
    hip_ha_t *entry = NULL;

    HIP_IFEL(!(entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr)),
                 -1, "failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_DEBUG("Got state from HADB: ports src: %d dest %d \n", sig_state->connection.src_port, sig_state->connection.dest_port);

    /* Dynamically lookup application from port information */
    HIP_IFEL(0 > signaling_netstat_get_application_path(sig_state),
            -1, "Got no path to application. \n");

    /* Verify the application */
    HIP_IFEL(0 > signaling_verify_application(sig_state),
            -1, "Could not verify certificate of application: %s.\n", sig_state->application.path);

    /* Get the application context. */
    HIP_IFEL(0 > signaling_get_application_context(sig_state),
            -1, "Could not build application context for application: %s.\n", sig_state->application.path);

    HIP_ASSERT(msg != NULL);

    /* Set type */
    hip_set_param_type(&appinfo, HIP_PARAM_SIGNALING_APPINFO);

    /* Calculate the length */
    if(sig_state->application.application_dn != NULL)
        length_contents = strlen(sig_state->application.application_dn);
    if(strlen(sig_state->application.application_dn) > 0)
    	length_contents += 4;

    /* Set length */
    hip_set_param_contents_len(&appinfo, length_contents);

	/* Build the contents (a list of tlv structs) */
    contents_start = p_tmp = malloc(length_contents);
    p_tmp = signaling_build_param_append_tlv(p_tmp, SIGNALING_APPINFO_APP_DN, sig_state->application.application_dn, strlen(sig_state->application.application_dn));
    err = hip_build_generic_param(msg, &appinfo, sizeof(struct hip_tlv_common), contents_start);

out_err:
    return err;
}

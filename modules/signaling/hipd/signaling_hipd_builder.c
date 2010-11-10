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
 * @brief adds parameters according to the defined parameter structure to a
 *        packet
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#include <string.h>

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

/*
 * Argument is a null-terminated string.
 */
static int signaling_verify_application(const char *app_file) {
    int err = 0;
    const char *issuer_cert_file;
    FILE *fp = NULL;
    /* X509 Stuff */
    X509AC *app_cert = NULL;
    X509 *issuercert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;

    /* Get application certificate */
    HIP_IFEL(!(app_cert = signaling_get_application_cert(app_file)),
            -1, "No application certificate found for application: %s.\n", app_file);

    /* Look for and get issuer certificate */
    issuer_cert_file = "cert.pem";
    HIP_IFEL(!(fp = fopen(issuer_cert_file, "r")),
            -1, "No issuer cert file given.\n");
    HIP_IFEL(!(issuercert = PEM_read_X509(fp, NULL, NULL, NULL)),
            -1, "Could not decode root cert file.\n");
    HIP_DEBUG("Using issuer certificate at: %s.\n", issuer_cert_file);
    fclose(fp);

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
    /* Free memory */
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509AC_free(app_cert);

    return err;
}


/*
 * Fill in the context information of an application.
 */
static int signaling_get_application_context(const char *app_file) {
    int err = 0;
    X509AC *ac = NULL;
    X509_NAME *name;
    char issuername[ONELINELEN];
    char holdername[ONELINELEN];

    HIP_IFEL(!(ac = signaling_get_application_cert(app_file)),
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
            X509_NAME_oneline(name,issuername,ONELINELEN);
        }

    }

    /* Application INFORMATION */
    if( ac->info->holder->entity != NULL) {
        name = X509AC_get_holder_entity_name(ac);
        if (!name) {
            HIP_DEBUG("Error getting AC holder name, possibly not a X500 name");
        } else {
            X509_NAME_oneline(name,holdername,ONELINELEN);
        }
    }

    HIP_DEBUG("Found following context for application: %s \n", app_file);
    HIP_DEBUG("\tIssuer name: %s\n", issuername);
    HIP_DEBUG("\tHolder name: %s\n", holdername);

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
    char app_path_buf[PATHBUF_SIZE];

    HIP_IFEL(!(entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr)),
                 -1, "failed to retrieve hadb entry");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling ports\n");
    HIP_DEBUG("Got ports from HADB: src: %d dest %d \n", sig_state->connection.src_port, sig_state->connection.dest_port);

    /* Dynamically lookup application from port information */
    HIP_IFEL(0 > signaling_netstat_get_application_path(sig_state->connection.src_port, sig_state->connection.dest_port, app_path_buf),
            -1, "Got not path to application. \n");

    /* Verify the application */
    HIP_IFEL(0 > signaling_verify_application(app_path_buf),
            -1, "Could not verify certificate of application: %s.\n", app_path_buf);

    /* Get the application context. */
    HIP_IFEL(0 > signaling_get_application_context(app_path_buf),
            -1, "Could not build application context for application: %s.\n", app_path_buf);

    /* Contents hardcoded for test
     * TODO: Get this dynamically
     */
    const char *app_dn      = "Mozilla Firefox 3.2.1";
    const char *app_groups  = "browser, client";

    HIP_ASSERT(msg != NULL);

    /* Set type */
    hip_set_param_type(&appinfo, HIP_PARAM_SIGNALING_APPINFO);

    /* Calculate the length */
    length_contents = strlen(app_dn) + strlen(app_groups);
    if(strlen(app_dn) > 0)
    	length_contents += 4;
    if(strlen(app_groups) > 0)
    	length_contents += 4;

    /* Set length */
    hip_set_param_contents_len(&appinfo, length_contents);

	/* Build the contents (a list of tlv structs) */
    contents_start = p_tmp = malloc(length_contents);
    p_tmp = signaling_build_param_append_tlv(p_tmp, SIGNALING_APPINFO_APP_DN, app_dn, strlen(app_dn));
    p_tmp = signaling_build_param_append_tlv(p_tmp, SIGNALING_APPINFO_GROUPS, app_groups, strlen(app_groups));
    err = hip_build_generic_param(msg, &appinfo, sizeof(struct hip_tlv_common), contents_start);

out_err:
    return err;
}

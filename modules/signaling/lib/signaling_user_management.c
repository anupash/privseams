/*
 * signaling_user_api.c
 *
 *  Created on: Nov 26, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_management.h"


/**
 * Try to verify the public key of given user.
 *
 * @param user_ctx  the user context containing the user name
 *
 * @return 0 on success, negative on error
 */
int signaling_user_api_verify_pubkey(X509_NAME *subject, UNUSED const EVP_PKEY *const pub_key, UNUSED X509 **user_cert)
{
    char *name;

    name = X509_NAME_oneline(subject, NULL, SIGNALING_USER_ID_MAX_LEN);
    HIP_DEBUG("Verifying public key of subject: %s \n", name);


    free(name);
    return SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED;
}

/**
 * @file
 *
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
/** @file
 * A teststub for certtools.c/h
 *
 * File for testing the main operations of certtools.
 * First this test takes the default HIT and the corresponding key.
 * Secondly it creates a certificate where itself is the issuer and the subject.
 * Then it tries to verify it. If it succeeds everything should be OK :)
 *
 * @author Samu Varjonen
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>
#include <openssl/safestack.h>

#include "lib/core/certtools.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/protodefs.h"


int main(int argc, char *argv[])
{
    int err                                    = 0, i = 0, len;
    struct hip_cert_spki_info *cert            = NULL;
    struct hip_cert_spki_info *to_verification = NULL;
    time_t not_before                          = 0, not_after = 0;
    struct hip_common *msg;
    struct in6_addr *defhit;
    char certificate[1024];
    unsigned char der_cert[1024];
    CONF *conf;
    CONF_VALUE *item;
    STACK_OF(CONF_VALUE) * sec      = NULL;
    STACK_OF(CONF_VALUE) * sec_name = NULL;

    if (argc != 2) {
        printf("Usage: %s spki|x509\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    HIP_DEBUG("- This test tool has to be run as root otherwise this will fail!\n");
    HIP_DEBUG("- Hipd has to run otherwise this will hang!\n");

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
             "Malloc for msg failed\n");
    defhit = malloc(sizeof(struct in6_addr));
    if (!defhit) {
        goto out_err;
    }

    if (strcmp(argv[1], "spki")) {
        goto skip_spki;
    }

    HIP_DEBUG("Starting to test SPKI certficate tools\n");

    cert            = malloc(sizeof(struct hip_cert_spki_info));
    if (!cert) {
        goto out_err;
    }

    to_verification = malloc(sizeof(struct hip_cert_spki_info));
    if (!to_verification) {
        goto out_err;
    }

    time(&not_before);
    time(&not_after);
    HIP_DEBUG("Reading configuration file (%s)\n", HIP_CERT_CONF_PATH);
    conf = hip_cert_open_conf();
    sec  = hip_cert_read_conf_section("hip_spki", conf);

    for (i = 0; i < sk_CONF_VALUE_num(sec); i++) {
        item = sk_CONF_VALUE_value(sec, i);
        if (!strcmp(item->name, "issuerhit")) {
            err = inet_pton(AF_INET6, item->value, defhit);
            if (err < 1) {
                err = -1;
                goto out_err;
            }
        }
        if (!strcmp(item->name, "days")) {
            not_after += HIP_CERT_DAY * atoi(item->value);
        }
    }
    hip_cert_free_conf(conf);

    hip_cert_spki_create_cert(cert,
                              "hit", defhit,
                              "hit", defhit,
                              &not_before,
                              &not_after);

    /*
     * Concatenate everything together as if we would have gotten
     * it from someone else and we would be starting to verify.
     *
     * So the process would be take the cert blob and take out
     * public-key sequence, cert sequence and signature sequence
     * and create a hip_cert_spki_info and send it to the daemon
     * for verification.
     */
    memset(&certificate, '\0', sizeof(certificate));
    sprintf((char *) &certificate, "(sequence %s%s%s)",
            cert->public_key,
            cert->cert,
            cert->signature);
    HIP_DEBUG("\n\nCertificate gotten back from daemon:\n\n"
              "%s\n\nCertificate len %d\n\n",
              certificate,
              strlen(certificate));

    HIP_IFEL(hip_cert_spki_char2certinfo(certificate, to_verification), -1,
             "Failed to construct the hip_cert_spki_info from certificate\n");

    /*
     * below, commented out, is the daemons version of the verification
     * and below that is the lib version of the verification
     */
    /*
     * HIP_DEBUG("Sending the certificate to daemon for verification\n");
     *
     * HIP_IFEL(hip_cert_spki_send_to_verification(to_verification), -1,
     *       "Failed in sending to verification\n");
     * HIP_IFEL(to_verification->success, -1,
     *       "Verification was not successfull\n");
     * HIP_DEBUG("Verification was successfull (return value %d)\n",
     *        to_verification->success);
     */
    /* Lets do the verification in library */
    HIP_IFEL(hip_cert_spki_lib_verify(to_verification), -1,
             "Verification was not succesfull\n");
    HIP_DEBUG("Verification was successfull (return value %d)\n",
              to_verification->success);

    goto out_err;

skip_spki:
    HIP_DEBUG("Starting to test x509v3 support\n");

    conf     = hip_cert_open_conf();
    sec_name = hip_cert_read_conf_section("hip_x509v3_name", conf);

    for (i = 0; i < sk_CONF_VALUE_num(sec_name); i++) {
        item = sk_CONF_VALUE_value(sec_name, i);
        if (!strcmp(item->name, "issuerhit")) {
            err = inet_pton(AF_INET6, item->value, defhit);
            if (err < 1) {
                err = -1;
                goto out_err;
            }
        }
    }
    hip_cert_free_conf(conf);
    len = hip_cert_x509v3_request_certificate(defhit, der_cert);

    /** Now send it back for the verification */
    HIP_IFEL(((err = hip_cert_x509v3_request_verification(der_cert, len)) < 0),
             -1, "Failed to verify a certificate\n");

out_err:
    HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");

    if (cert) {
        free(cert);
    }
    if (to_verification) {
        free(to_verification);
    }
    exit(err);
}

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
 * This file contains functions that are specific to PISA. They deal with the
 * certificate loading.
 *
 * @brief Functions for certificate loading
 *
 * @author Thomas Jansen
 */

#include "hipd.h"
#include "pisa.h"

#define CERT_MAX_SIZE 1024

static char *midauth_cert = NULL;

/**
 * Load a certificate from the file /etc/hip/cert and store it in memory
 *
 * @return 0 on success
 */
static int hip_pisa_load_certificate(void)
{
    FILE *f = NULL;

    if (midauth_cert) {
        free(midauth_cert);
    }
    midauth_cert = malloc(CERT_MAX_SIZE);
    memset(midauth_cert, 0, CERT_MAX_SIZE);

    if (!(f = fopen("/etc/hip/cert", "r"))) {
        HIP_ERROR("Could not open certificate file.\n");
        return -1;
    }

    if (fread(midauth_cert, CERT_MAX_SIZE - 1, 1, f) == 0) {
        perror("fread returned 0");
    }
    fclose(f);
    return 0;
}

/**
 * Load a certificate from disk and return a pointer to the global
 * variable containing it.
 *
 * @see hip_pisa_load_certificate*
 *
 * @param void
 * @return pointer to midauth_cert
 */
char *hip_pisa_get_certificate(void)
{
    hip_pisa_load_certificate();
    return midauth_cert;
}

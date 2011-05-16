/*
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

/**
 * @file
 * Generate a SPKI certificate for use with PISA.
 *
 * @author Thomas Jansen <mithi@mithi.net>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "lib/core/builder.h"
#include "lib/core/certtools.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/protodefs.h"


/**
 * Get the default hit of the local HIPD.
 *
 * @param result location to store the result in
 * @return 0 on success
 */
static int get_default_hit(struct in6_addr *result)
{
    int                          err   = 0;
    struct       hip_common     *msg   = NULL;
    const struct hip_tlv_common *param = NULL;
    const struct in6_addr       *hit   = NULL;

    if (!(msg = hip_msg_alloc())) {
        return -1;
    }

    HIP_IFE(hip_build_user_hdr(msg, HIP_MSG_GET_DEFAULT_HIT, 0), -1);
    HIP_IFE(hip_send_recv_daemon_info(msg, 0, 0), -ECOMM);

    param = hip_get_param(msg, HIP_PARAM_HIT);
    hit   = hip_get_param_contents_direct(param);
    memcpy(result, hit, sizeof(struct in6_addr));

out_err:
    free(msg);
    return err;
}

/**
 * Create the certificate with the given parameters.
 *
 * @param not_before start of certificate lifetime
 * @param not_after end of certificate lifetime
 * @param hit HIT of issuer and subject
 * @param certificate buffer to store the resulting certificate in
 * @param size size of the certificate buffer
 * @return 0 on success
 */
static int create_certificate(time_t *not_before, time_t *not_after,
                              struct in6_addr *hit, char *certificate,
                              size_t size)
{
    int                       err = 0;
    struct hip_cert_spki_info cert;

    HIP_IFEL(!not_before || !not_after || !hit || !certificate, -1,
             "NULL parameter found.\n");

    hip_cert_spki_create_cert(&cert, "hit", hit, "hit", hit, not_before,
                              not_after);

    snprintf(certificate, size, "(sequence %s%s%s)", cert.public_key,
             cert.cert, cert.signature);
out_err:
    if (err != 0 && certificate) {
        certificate[0] = '\0';
    }
    return err;
}

int main(int argc, char *argv[])
{
    time_t          not_before = 0, not_after = 0;
    struct in6_addr hit;
    int             err               = 0, days = 0;
    FILE           *f                 = NULL;
    char            certificate[1024] = "";

    HIP_IFEL(argc != 3, -1, "Wrong number of arguments.\n");

    HIP_IFEL(getuid() != 0, -1, "You're not superuser.\n");

    days = atoi(argv[1]);
    HIP_IFEL(days <= 0, -1, "Specify a positive number of days.\n");

    f = fopen(argv[2], "w");
    HIP_IFEL(f == NULL, -1, "Could not write to file.\n");

    time(&not_before);
    time(&not_after);
    not_after += days * 24 * 60 * 60;

    HIP_IFEL(get_default_hit(&hit), -1, "Could not get HIT from hipd.\n");
    HIP_IFEL(create_certificate(&not_before, &not_after, &hit,
                                certificate, sizeof(certificate)) != 0,
             -1, "Could not create the certificate.\n");

    fwrite(certificate, strlen(certificate), 1, f);

out_err:
    if (err == -1) {
        fprintf(stderr, "usage: pisacert days filename\n");
        fprintf(stderr, "must be run as superuser, e.g. with sudo\n");
    }

    if (f) {
        fclose(f);
    }

    return err;
}

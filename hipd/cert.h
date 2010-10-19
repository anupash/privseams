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
 *
 * Certificate signing and verification functions.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 */

#ifndef HIP_HIPD_CERT_H
#define HIP_HIPD_CERT_H

#include <openssl/rsa.h>

#include "lib/core/hashtable.h"
#include "lib/core/protodefs.h"

/** SPKI */
int hip_cert_spki_sign(struct hip_common *);
int hip_cert_spki_verify(struct hip_common *);

/** x509v3 */
int hip_cert_x509v3_handle_request_to_sign(struct hip_common *);
int hip_cert_x509v3_handle_request_to_verify(struct hip_common *);

/** utilitary functions */
int hip_cert_hostid2rsa(struct hip_host_id_priv *, RSA *);
int hip_cert_hostid2dsa(struct hip_host_id_priv *, DSA *);

#endif /* HIP_HIPD_CERT_H */
